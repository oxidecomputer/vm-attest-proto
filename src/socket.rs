// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dice_verifier::Nonce;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    ops::DerefMut,
    os::unix::net::{UnixListener, UnixStream},
};

use crate::{
    PlatformAttestation, QualifyingData, Response, VmInstanceRot,
    mock::{VmInstanceRotMock, VmInstanceRotMockError},
};

/// the maximum length of a message that we'll accept from clients
const MAX_LINE_LENGTH: usize = 1024;

/// This type wraps the client side of a `UnixStream` socket.
/// The service side should be an instance of the `VmInstanceRotSocketServer`
/// type.
#[derive(Debug)]
pub struct VmInstanceRotSocketClient {
    socket: RefCell<UnixStream>,
}

impl VmInstanceRotSocketClient {
    pub fn new(socket: UnixStream) -> Self {
        Self {
            socket: RefCell::new(socket),
        }
    }
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotSocketClientError {
    #[error("error deserializing a Command from JSON")]
    CommandDeserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error from the VmInstanceRot")]
    VmInstanceRot(String),
}

impl VmInstanceRot for VmInstanceRotSocketClient {
    type Error = VmInstanceRotSocketClientError;

    /// Turn the `QualifyingData` provided into a JSON message that we send
    /// over the socket. We get back a `PlatformAttestation` that we
    /// deserialize from JSON.
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
        // map `Response` to `Result<PlatformAttestation, Self::Error>`
        let response: Response = serde_json::from_str(&response)?;
        match response {
            Response::Success(p) => Ok(p),
            Response::Error(e) => Err(Self::Error::VmInstanceRot(e)),
        }
    }
}

/// This type raps a UnixListener accepting JSON encoded messages /
/// `QualifyingData` from the `VmInstanceRotSocketClient`. The `QualifyingData`
/// is passed to an instance of the `VmInstanceRotMock`.
pub struct VmInstanceRotSocketServer {
    mock: VmInstanceRotMock,
    listener: UnixListener,
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotSocketRunError {
    #[error("error from underlying VmInstanceRoT mock")]
    MockRotError(#[from] VmInstanceRotMockError),

    #[error("failed to deserialize QualifyingData request from JSON")]
    Request(serde_json::Error),

    #[error("failed to serialize Response to JSON")]
    Response(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),
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
            // we should only receive `QualifyingData` over this interface so
            // we can limit the line length to something reasonable
            let reader = BufReader::with_capacity(MAX_LINE_LENGTH, client?);
            let mut reader = reader.take(MAX_LINE_LENGTH as u64);
            loop {
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
                    let response =
                        Response::Error("Request too long".to_string());
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
                        let response = Response::Error(e.to_string());
                        let mut response = serde_json::to_string(&response)?;
                        response.push('\n');
                        debug!("sending error response: {response}");
                        reader
                            .get_mut()
                            .get_mut()
                            .write_all(response.as_bytes())?;
                        return Err(VmInstanceRotSocketRunError::Request(e));
                    }
                };

                debug!("qualifying data received: {qualifying_data:?}");

                let response = match self.mock.attest(&qualifying_data) {
                    Ok(a) => Response::Success(a),
                    Err(e) => Response::Error(e.to_string()),
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

/// This enumeration represents the response message sent from one of the
/// `VmInstanceTcpServer`
#[derive(Debug, Deserialize, Serialize)]
pub enum VmResponse {
    Success(AttestedKey),
    Error(String),
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceTcpServerError<T: VmInstanceRot> {
    #[error("failed to deserialize Nonce request from JSON")]
    Request(serde_json::Error),

    #[error("failed to serialize Response to JSON")]
    Response(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error from the underlying VmInstanceRot")]
    VmInstanceRotError(<T as VmInstanceRot>::Error),
}

/// This type wraps a TcpListener accepting JSON encoded `Nonce`s from a
/// challenger / `VmInstanceTcpClient`. It is intended to be run within a
/// (mock) vm instance. For each challenge / `Nonce` received this type will
/// generate some data (local to the VM) and hash the two together. This
/// `QualifyingData` is then sent down to the `VmInstanceRot` by way of the
/// `vm_instance_rot` member.
pub struct VmInstanceTcpServer<T: VmInstanceRot> {
    challenge_listener: TcpListener,
    vm_instance_rot: T,
}

impl<T: VmInstanceRot> VmInstanceTcpServer<T> {
    pub fn new(challenge_listener: TcpListener, vm_instance_rot: T) -> Self {
        Self {
            challenge_listener,
            vm_instance_rot,
        }
    }

    pub fn run(&self) -> Result<(), VmInstanceTcpServerError<T>> {
        let mut msg = String::new();
        for client in self.challenge_listener.incoming() {
            debug!("new client");

            let reader = BufReader::with_capacity(MAX_LINE_LENGTH, client?);
            let mut reader = reader.take(MAX_LINE_LENGTH as u64);
            loop {
                // read Nonce from stream (JSON)
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
                    let response =
                        Response::Error("Request too long".to_string());
                    let mut response = serde_json::to_string(&response)?;
                    response.push('\n');
                    debug!("sending error response: {response}");
                    reader
                        .get_mut()
                        .get_mut()
                        .write_all(response.as_bytes())?;
                    break;
                }

                debug!("nonce received: {msg}");
                let result: Result<Nonce, serde_json::Error> =
                    serde_json::from_str(&msg);
                let nonce = match result {
                    Ok(q) => q,
                    Err(e) => {
                        let response = VmResponse::Error(e.to_string());
                        let mut response = serde_json::to_string(&response)?;
                        response.push('\n');
                        debug!("sending error response: {response}");
                        reader
                            .get_mut()
                            .get_mut()
                            .write_all(response.as_bytes())?;
                        return Err(VmInstanceTcpServerError::Request(e));
                    }
                };
                debug!("nonce decoded: {nonce:?}");

                //   - generate `public_key`
                let user_data = vec![1, 2, 3, 4];

                //   - generate `qualifying_data`
                let mut qualifying_data = Sha256::new();
                qualifying_data.update(nonce);
                qualifying_data.update(&user_data);
                let qualifying_data = QualifyingData::from(
                    Into::<[u8; 32]>::into(qualifying_data.finalize()),
                );

                //   - get `attestation` from `VmInstanceRot` by passing
                //     `qualifying_data` to VmInstanceRot through
                let platform_attestation =
                    match self.vm_instance_rot.attest(&qualifying_data) {
                        Ok(a) => a,
                        Err(e) => {
                            let response = VmResponse::Error(e.to_string());
                            let mut response =
                                serde_json::to_string(&response)?;
                            response.push('\n');
                            debug!("sending error response: {response}");
                            reader
                                .get_mut()
                                .get_mut()
                                .write_all(response.as_bytes())?;
                            return Err(
                                VmInstanceTcpServerError::VmInstanceRotError(e),
                            );
                        }
                    };

                let attested_key = AttestedKey {
                    attestation: platform_attestation,
                    public_key: user_data,
                };

                let response = VmResponse::Success(attested_key);

                //   - return `attestation` + `public_key`
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

#[derive(Debug, Deserialize, Serialize)]
pub struct AttestedKey {
    pub attestation: PlatformAttestation,
    pub public_key: Vec<u8>,
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceTcpError {
    #[error("error converting type with serde")]
    Serialization(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error propagated from the VmInstance")]
    VmInstance(String),
}

/// This type wraps the client side of a TCP connection / stream.
/// The server side should be an instance of the `VmInstanceTcpServer`.
pub struct VmInstanceTcp {
    stream: TcpStream,
}

impl VmInstanceTcp {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Send a nonce to the `VmInstanceTcpServer`, get back an `AttestedKey`
    /// that we deserialize from JSON.
    pub fn attest_key(
        &mut self,
        nonce: &Nonce,
    ) -> Result<AttestedKey, VmInstanceTcpError> {
        debug!("generated nonce: {nonce:?}");
        let mut nonce = match nonce {
            Nonce::N32(a) => serde_json::to_string(&a)?,
        };
        nonce.push('\n');
        self.stream.write_all(nonce.as_bytes())?;
        debug!("nonce sent to vm instance");

        // get back struct w/ attestation + public key
        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        debug!("got attesetd key: {response}");

        let response: VmResponse = serde_json::from_str(&response)?;
        match response {
            VmResponse::Success(a) => Ok(a),
            VmResponse::Error(e) => Err(VmInstanceTcpError::VmInstance(e)),
        }
    }
}
