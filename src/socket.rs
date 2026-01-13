// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::debug;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Write},
    ops::DerefMut,
    os::unix::net::{UnixListener, UnixStream},
};

use crate::{
    Attestation, CertChain, MeasurementLog, Nonce, VmInstanceAttester,
    mock::{VmInstanceAttestMock, VmInstanceAttestMockError},
};

#[derive(Debug, Deserialize, Serialize)]
struct AttestData {
    nonce: Nonce,
    user_data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
enum Command {
    Attest(AttestData),
    GetCertChains,
    GetMeasurementLogs,
}

// This type is used by clients to send commands and get responses from
// an implementation of the VmInstanceAttest API over a socket
pub struct VmInstanceAttestSocket {
    socket: RefCell<UnixStream>,
}

impl VmInstanceAttestSocket {
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

impl VmInstanceAttester for VmInstanceAttestSocket {
    type Error = VmInstanceAttestSocketError;

    // serialize parames into message structure representing the
    // VmInstanceAttester::attest function
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Vec<Attestation>, Self::Error> {
        let attest_data = AttestData {
            nonce: nonce.clone(),
            user_data: user_data.to_vec(),
        };

        let mut command = serde_json::to_string(&Command::Attest(attest_data))?;
        command.push('\n');
        let command = command;

        debug!("writing command");
        self.socket.borrow_mut().write_all(command.as_bytes())?;

        let mut socket_mut = self.socket.borrow_mut();
        let mut reader = BufReader::new(socket_mut.deref_mut());

        let mut response = String::new();
        reader.read_line(&mut response)?;

        debug!("got response: {response}");
        let attestations: Vec<Attestation> = serde_json::from_str(&response)?;

        Ok(attestations)
    }

    // serialize parames into message structure representing the
    // VmInstanceAttester::get_cert_chains
    fn get_cert_chains(&self) -> Result<Vec<CertChain>, Self::Error> {
        let mut command = serde_json::to_string(&Command::GetCertChains)?;
        command.push('\n');
        let command = command;

        debug!("writing command: {command}");
        self.socket.borrow_mut().write_all(command.as_bytes())?;

        let mut socket_mut = self.socket.borrow_mut();
        let mut reader = BufReader::new(socket_mut.deref_mut());

        let mut response = String::new();
        reader.read_line(&mut response)?;

        debug!("got response: {response}");
        let cert_chains: Vec<CertChain> = serde_json::from_str(&response)?;

        Ok(cert_chains)
    }

    // serialize parames into message structure representing the
    // VmInstanceAttester::get_measurement_logs
    fn get_measurement_logs(&self) -> Result<Vec<MeasurementLog>, Self::Error> {
        let mut command = serde_json::to_string(&Command::GetMeasurementLogs)?;
        command.push('\n');
        let command = command;

        debug!("writing command: {command}");
        self.socket.borrow_mut().write_all(command.as_bytes())?;

        let mut socket_mut = self.socket.borrow_mut();
        let mut reader = BufReader::new(socket_mut.deref_mut());

        let mut response = String::new();
        reader.read_line(&mut response)?;

        debug!("got response: {response}");
        let logs: Vec<MeasurementLog> = serde_json::from_str(&response)?;

        Ok(logs)
    }
}

/// This type acts as a socket server accepting encoded messages that
/// correspond to functions from the VmInstanceAttester.
pub struct VmInstanceAttestSocketServer {
    mock: VmInstanceAttestMock,
    listener: UnixListener,
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceAttestSocketRunError {
    #[error("error from underlying VmInstanceRoT mock")]
    MockRotError(#[from] VmInstanceAttestMockError),

    #[error("error deserializing Command from JSON")]
    CommandDeserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error deserializing data")]
    Serialize,
}

impl VmInstanceAttestSocketServer {
    pub fn new(mock: VmInstanceAttestMock, listener: UnixListener) -> Self {
        Self { mock, listener }
    }

    // message handling loop
    pub fn run(&self) -> Result<(), VmInstanceAttestSocketRunError> {
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
                let command: Command = serde_json::from_str(&msg)?;
                debug!("command received: {command:?}");

                let mut response = match command {
                    Command::Attest(data) => {
                        debug!("getting attestation");
                        let attestations =
                            self.mock.attest(&data.nonce, &data.user_data)?;
                        serde_json::to_string(&attestations)?
                    }
                    Command::GetCertChains => {
                        debug!("getting cert chains");
                        let cert_chains = self.mock.get_cert_chains()?;
                        serde_json::to_string(&cert_chains)?
                    }
                    Command::GetMeasurementLogs => {
                        debug!("get measurement logs");
                        let logs = self.mock.get_measurement_logs()?;
                        serde_json::to_string(&logs)?
                    }
                };
                response.push('\n');

                debug!("sending response: {response}");
                client.write_all(response.as_bytes())?;
                msg.clear();
            }
        }

        Ok(())
    }
}
