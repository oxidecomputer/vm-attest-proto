// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dice_verifier::Nonce;
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    ops::DerefMut,
    os::unix::net::{UnixListener, UnixStream},
};

use crate::{
    PlatformAttestation, QualifyingData, VmInstanceRot,
    mock::{VmInstanceRotMock, VmInstanceRotMockError},
};

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
        let attestation: PlatformAttestation = serde_json::from_str(&response)?;

        Ok(attestation)
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

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceTcpServerError<T: VmInstanceRot> {
    #[error("error converting type with serde")]
    Serialization(#[from] serde_json::Error),

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

            let mut client = client?;
            loop {
                let mut reader = BufReader::new(&mut client);

                //   - read nonce from stream (JSON)
                let count = reader.read_line(&mut msg)?;
                if count == 0 {
                    debug!("read 0 bytes: EOF");
                    break;
                }

                debug!("nonce received: {msg}");
                let nonce: Nonce = serde_json::from_str(&msg)?;
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
                //     `VmInstanceRotSocket::attest`
                let platform_attestation =
                    self.vm_instance_rot.attest(&qualifying_data).map_err(
                        VmInstanceTcpServerError::<T>::VmInstanceRotError,
                    )?;

                let attested_key = AttestedKey {
                    attestation: platform_attestation,
                    public_key: user_data,
                };

                //   - return `attestation` + `public_key`
                let mut response = serde_json::to_string(&attested_key)?;
                response.push('\n');

                debug!("sending response: {response}");
                client.write_all(response.as_bytes())?;
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
        let mut nonce = serde_json::to_string(&nonce)?;
        nonce.push('\n');
        self.stream.write_all(nonce.as_bytes())?;
        debug!("nonce sent to vm instance");

        // get back struct w/ attestation + public key
        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        debug!("got attesetd key: {response}");

        Ok(serde_json::from_str(&response)?)
    }
}
