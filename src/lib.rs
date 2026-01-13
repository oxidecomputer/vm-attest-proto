// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};

pub mod mock;
pub mod socket;

/// User chosen value. Probably random data. Must not be reused.
#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum RotType {
    OxidePlatform,
    OxideInstance,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct Attestation {
    pub rot: RotType,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct MeasurementLog {
    pub rot: RotType,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct CertChain {
    pub rot: RotType,
    pub certs: Vec<Vec<u8>>,
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

#[cfg(test)]
mod test {
    use crate::*;

    const NONCE: [u8; 32] = [
        129, 37, 8, 100, 45, 226, 22, 204, 43, 211, 159, 134, 112, 205, 125,
        172, 227, 69, 213, 38, 85, 213, 255, 132, 157, 226, 213, 93, 204, 133,
        188, 63,
    ];

    #[test]
    fn nonce_to_json() {
        let nonce = Nonce::from_array(NONCE);
        let json = serde_json::to_string(&nonce).expect("Nonce to JSON");
        assert_eq!(
            json,
            "[129,37,8,100,45,226,22,204,43,211,159,134,112,205,125,172,227,69,213,38,85,213,255,132,157,226,213,93,204,133,188,63]"
        );
    }

    #[test]
    fn rottype_to_json() {
        let json = serde_json::to_string(&RotType::OxidePlatform)
            .expect("RotType to JSON");
        assert_eq!(json, "\"OxidePlatform\"");
    }

    #[test]
    fn attestation_to_json() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let attestation = Attestation {
            rot: RotType::OxidePlatform,
            data,
        };
        let json =
            serde_json::to_string(&attestation).expect("RotType to JSON");
        assert_eq!(
            json,
            "{\"rot\":\"OxidePlatform\",\"data\":[222,173,190,239]}"
        );
    }
}
