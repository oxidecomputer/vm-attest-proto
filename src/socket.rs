// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::debug;
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Write},
    ops::DerefMut,
    os::unix::net::{UnixListener, UnixStream},
};

use crate::{
    PlatformAttestation, QualifyingData, VmInstanceRot,
    mock::{VmInstanceRotMock, VmInstanceRotMockError},
};

// This type is used by software within the VM instance to send commands and
// get responses from an implementation of the VmInstanceRot over a socket
pub struct VmInstanceRotSocket {
    socket: RefCell<UnixStream>,
}

impl VmInstanceRotSocket {
    pub fn new(socket: UnixStream) -> Self {
        Self {
            socket: RefCell::new(socket),
        }
    }
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceAttestSocketError {
    #[error("error deserializing a Command from JSON")]
    CommandDeserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),
}

impl VmInstanceRot for VmInstanceRotSocket {
    type Error = VmInstanceAttestSocketError;

    // serialize parames into message structure representing the
    // VmInstanceAttester::attest function
    fn attest(
        &self,
        qualifying_data: &QualifyingData,
    ) -> Result<PlatformAttestation, Self::Error> {
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
        let attestation: PlatformAttestation = serde_json::from_str(&response)?;

        Ok(attestation)
    }
}

/// This type acts as a socket server accepting encoded messages that
/// correspond to functions from the VmInstanceAttester.
pub struct VmInstanceRotSocketServer {
    mock: VmInstanceRotMock,
    listener: UnixListener,
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotSocketRunError {
    #[error("error from underlying VmInstanceRoT mock")]
    MockRotError(#[from] VmInstanceRotMockError),

    #[error("error deserializing Command from JSON")]
    CommandDeserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error deserializing data")]
    Serialize,
}

impl VmInstanceRotSocketServer {
    pub fn new(mock: VmInstanceRotMock, listener: UnixListener) -> Self {
        Self { mock, listener }
    }

    // message handling loop
    pub fn run(&self) -> Result<(), VmInstanceRotSocketRunError> {
        debug!("listening for clients");

        let mut msg = String::new();
        for client in self.listener.incoming() {
            debug!("new client");

            // `incoming` yeilds iterator over a Result
            let mut client = client?;
            loop {
                // would like to do this before `loop` but we need to write to
                // the client as well
                let mut reader = BufReader::new(&mut client);
                let count = reader.read_line(&mut msg)?;
                if count == 0 {
                    debug!("read 0 bytes: EOF");
                    break;
                }

                debug!("string received: {msg}");
                let qualifying_data: QualifyingData =
                    serde_json::from_str(&msg)?;
                debug!("qualifying data received: {qualifying_data:?}");

                let platform_attestation =
                    self.mock.attest(&qualifying_data)?;
                let mut response =
                    serde_json::to_string(&platform_attestation)?;
                response.push('\n');

                debug!("sending response: {response}");
                client.write_all(response.as_bytes())?;
                msg.clear();
            }
        }

        Ok(())
    }
}
