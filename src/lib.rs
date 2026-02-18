// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use std::{error, fmt};

pub mod mock;
pub mod socket;
#[cfg(feature = "vsock")]
pub mod vsock;

/// User chosen value. Probably random data. Must not be reused.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QualifyingData([u8; 32]);

impl QualifyingData {
    /// When challenging a platform for an attestation the challenger will
    /// typically want to include random qualifying data (a nonce) in their
    /// challenge. This function uses the RNG from `getrandom` to generate
    /// such qualifying data.
    pub fn from_platform_rng() -> Result<Self, getrandom::Error> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce[..])?;
        let nonce = nonce;

        Ok(Self(nonce))
    }

    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for QualifyingData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for QualifyingData {
    fn from(data: [u8; 32]) -> Self {
        Self(data)
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum RotType {
    OxidePlatform,
    OxideInstance,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct MeasurementLog {
    pub rot: RotType,
    pub data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VmInstanceAttestation {
    // the attestation from the Oxide Platform RoT
    // the message signed by RoT is:
    //   attestation = sign(hubpack(log) | qualifying_data)
    // where:
    //   `vm_data` is the 32 bytres passed from the VM down to the VmInstanceRot
    //   `qualifying_data` = sha(vm_cfg | vm_data)
    // this is a hubpack serialization of the `attest_data::Attestation`
    // structure
    // NOTE: JSON would be better
    pub attestation: Vec<u8>,

    // the platform RoT cert chain
    // these are DER encoded, ordered from leaf to first intermediate
    // TODO: encoding these as PEM strings may be preferable, the JSON encoded
    // `Vec<u8>` may end up being less efficient
    pub cert_chain: Vec<Vec<u8>>,

    // measurement logs from the:
    // - Oxide Platform RoT: a hubpack serialized attest_data::Log
    // - VM Instance RoT: a JSON serialized mock::Measurement structure
    pub measurement_logs: Vec<MeasurementLog>,
}

/// This enumeration represents the response message returned by the
/// `VmInstanceRot` in response to the `attest` function / message.
#[derive(Debug, Deserialize, Serialize)]
pub enum VmInstanceAttestResponse {
    Attestation(VmInstanceAttestation),
    Error(String),
}

/// An interface for obtaining attestations and supporting data from the VM
/// Instance RoT
pub trait VmInstanceRot {
    type Error: error::Error + fmt::Debug;

    /// Get an attestation from each of the RoTs resident on the host platform
    /// qualified by the provided `QualifyingData`.
    fn attest(
        &self,
        qualifying_data: &QualifyingData,
    ) -> Result<VmInstanceAttestation, Self::Error>;
}
