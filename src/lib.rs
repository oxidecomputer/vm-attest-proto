// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod mock;

/// User chosen value. Probably random data. Must not be reused.
#[derive(Debug)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn from_array(nonce: [u8; 32]) -> Self {
        Self(nonce)
    }

    pub fn from_platform_rng() -> Result<Self, getrandom::Error> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce[..])?;
        let nonce = nonce;

        Ok(Self(nonce))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum RotType {
    OxidePlatform,
    OxideInstance,
}

#[allow(dead_code)]
pub struct Attestation {
    rot: RotType,
    data: Vec<u8>,
}

#[allow(dead_code)]
pub struct MeasurementLog {
    rot: RotType,
    data: Vec<u8>,
}

#[allow(dead_code)]
pub struct CertChain {
    rot: RotType,
    certs: Vec<Vec<u8>>,
}

/// An interface for obtaining attestations and supporting data from the VM
/// Instance RoT
pub trait VmInstanceAttester {
    type Error;

    /// Get an attestation from each of the RoTs resident on the host platform.
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Vec<Attestation>, Self::Error>;

    /// Return all relevant measurement logs, in order of concatenation.
    fn get_measurement_logs(&self) -> Result<Vec<MeasurementLog>, Self::Error>;

    /// Return the cert chain for the given RotType.
    fn get_cert_chains(&self) -> Result<Vec<CertChain>, Self::Error>;
}
