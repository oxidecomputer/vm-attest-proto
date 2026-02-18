// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::{debug, warn};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Read, Write},
    ops::DerefMut,
};
use vsock::{VsockListener, VsockStream};

use crate::{
    QualifyingData, VmInstanceAttestResponse, VmInstanceAttestation,
    VmInstanceRot,
    mock::{VmInstanceRotMock, VmInstanceRotMockError},
};

/// the maximum length of a message that we'll accept from clients
const MAX_LINE_LENGTH: usize = 1024;

/// This type is an implementation of a `VmInstanceRot` that listens for
/// connections on a vsock. It receives JSON messages that encode the sole
/// parameter to the `VmInstanceRot::attest` function.
pub struct VmInstanceRotVsockServer {
    mock: VmInstanceRotMock,
    listener: VsockListener,
}

#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotVsockError {
    #[error("error from underlying VmInstanceRoT mock")]
    MockRotError(#[from] VmInstanceRotMockError),

    #[error("error deserializing Command from JSON")]
    Request(serde_json::Error),

    #[error("error serializing response to JSON")]
    Response(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),
}

impl VmInstanceRotVsockServer {
    pub fn new(mock: VmInstanceRotMock, listener: VsockListener) -> Self {
        Self { mock, listener }
    }

    // message handling loop
    pub fn run(&self) -> Result<(), VmInstanceRotVsockError> {
        debug!("listening for clients");

        let mut msg = String::new();
        for client in self.listener.incoming() {
            debug!("new client");

            // `incoming` yeilds iterator over a Result
            let reader = BufReader::with_capacity(MAX_LINE_LENGTH, client?);
            let mut reader = reader.take(MAX_LINE_LENGTH as u64);
            loop {
                // would like to do this before `loop` but we need to write to
                // the client as well
                let count = reader.read_line(&mut msg)?;
                if count == 0 {
                    debug!("read 0 bytes: EOF");
                    break;
                }

                // detect receipt of a message longer than the max
                if count == MAX_LINE_LENGTH && !msg.ends_with('\n') {
                    warn!(
                        "Error: Line length exceeded the limit of {} bytes.",
                        MAX_LINE_LENGTH
                    );
                    let response = VmInstanceAttestResponse::Error(
                        "Request too long".to_string(),
                    );
                    let mut response = serde_json::to_string(&response)?;
                    response.push('\n');
                    debug!("sending error response: {response}");
                    reader
                        .get_mut()
                        .get_mut()
                        .write_all(response.as_bytes())?;
                    break;
                }

                debug!("string received: {msg}");
                let result: Result<QualifyingData, serde_json::Error> =
                    serde_json::from_str(&msg);
                let qualifying_data = match result {
                    Ok(q) => q,
                    Err(e) => {
                        // send error message to client, then map to error type
                        let response =
                            VmInstanceAttestResponse::Error(e.to_string());
                        let mut response = serde_json::to_string(&response)?;
                        response.push('\n');
                        debug!("sending error response: {response}");
                        reader
                            .get_mut()
                            .get_mut()
                            .write_all(response.as_bytes())?;
                        return Err(VmInstanceRotVsockError::Request(e));
                    }
                };

                debug!("qualifying data received: {qualifying_data:?}");
                let response = match self.mock.attest(&qualifying_data) {
                    Ok(a) => VmInstanceAttestResponse::Attestation(a),
                    Err(e) => VmInstanceAttestResponse::Error(e.to_string()),
                };

                let mut response = serde_json::to_string(&response)?;
                response.push('\n');

                debug!("sending response: {response}");
                reader.get_mut().get_mut().write_all(response.as_bytes())?;
                msg.clear();
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct VmInstanceRotVsockClient {
    socket: RefCell<VsockStream>,
}

impl VmInstanceRotVsockClient {
    pub fn new(socket: VsockStream) -> Self {
        Self {
            socket: RefCell::new(socket),
        }
    }
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotVsockClientError {
    #[error("error deserializing a PlatformAttestation from JSON")]
    Deserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error from the VmInstanceRoT")]
    VmInstanceRotError(String),
}

impl VmInstanceRot for VmInstanceRotVsockClient {
    type Error = VmInstanceRotVsockClientError;

    fn attest(
        &self,
        qualifying_data: &QualifyingData,
    ) -> Result<VmInstanceAttestation, Self::Error> {
        let mut command = serde_json::to_string(&qualifying_data)?;
        command.push('\n');
        let command = command;

        debug!("writing command");
        self.socket.borrow_mut().write_all(command.as_bytes())?;

        let mut socket_mut = self.socket.borrow_mut();
        let mut reader = BufReader::new(socket_mut.deref_mut());

        let mut response = String::new();
        reader.read_line(&mut response)?;

        debug!("got response: {response}");
        // map response message to Result
        let response: VmInstanceAttestResponse =
            serde_json::from_str(&response)?;
        match response {
            VmInstanceAttestResponse::Attestation(a) => Ok(a),
            VmInstanceAttestResponse::Error(e) => {
                Err(Self::Error::VmInstanceRotError(e))
            }
        }
    }
}
