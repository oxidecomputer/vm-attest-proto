// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::AttestDataError as OxAttestDataError;
use dice_verifier::{
    Attest as OxAttest, AttestError as OxAttestError,
    AttestMock as OxAttestMock, Attestation as OxAttestation, Log,
};
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_cert::PkiPath;

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
    OxideHardware,
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

/// A representation of the measurement log produced by the VM instance RoT.
/// This is the log of measurements that propolis mixes into the data provided
/// to the attestation produced by the `RotType::OxideHardware`.
#[derive(Serialize, Deserialize)]
pub struct VmInstanceConf {
    pub uuid: Uuid,
    #[serde(rename = "image-digest")]
    pub image_digest: Measurement,
}

#[derive(Serialize, Deserialize)]
pub struct Measurement {
    pub algorithm: String,
    pub digest: String,
}

/// An interface for obtaining an attestation from the Oxide RoT
///
/// An attestation from the Oxide RoT is an ed25519::Signature.
/// In the future, we may change algorithms and that will result in a new trait,
/// because the signature and hash lengths may change. The alternative is to
/// instead return a serialized signature and specify the algorithms used per
/// version.
pub trait AttestationSigner {
    type Error;

    /// Get an attestation from the Oxide RoT entangled with the provided nonce & data.
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Vec<Attestation>, Self::Error>;

    /// Return all relevant measurement logs, in order of concatenation.
    fn get_measurement_logs(&self) -> Result<Vec<MeasurementLog>, Self::Error>;

    /// Return the cert chain for the given RotType.
    fn get_cert_chain(&self, rot: RotType) -> Result<PkiPath, Self::Error>;
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum AttestMockError {
    #[error("error deserializing data")]
    Serialize,
    #[error("error from Oxide attestation interface")]
    OxideAttestError(#[from] OxAttestError),
    #[error("error from Oxide attestation data")]
    OxideAttestDataError(#[from] OxAttestDataError),
    #[error("Rot has no cert chain")]
    NoCertChain,
}

/// This type mocks the `propolis` process that backs a VM.
pub struct AttestMock {
    oxattest_mock: OxAttestMock,
    log: VmInstanceConf,
}

impl AttestMock {
    pub fn new(oxattest_mock: OxAttestMock, log: VmInstanceConf) -> Self {
        Self { oxattest_mock, log }
    }
}

impl AttestationSigner for AttestMock {
    type Error = AttestMockError;

    /// `propolis` receives the nonce & user data from the caller.
    /// It then combines this data w/ attributes describing the VM (rootfs,
    /// instance UUID etc) and attestations from other RoTs on the platform.
    /// The format of each attestation is dependent on the associated `RotType`.
    /// NOTE: the order of the attestations returned is significant
    fn attest(
        &self,
        nonce: &Nonce,
        user_data: &[u8],
    ) -> Result<Vec<Attestation>, Self::Error> {
        let mut msg = Sha256::new();
        // msg.update w/
        // - attestations from platform RoTs
        msg.update(self.log.uuid);
        msg.update(&self.log.image_digest.digest);
        msg.update(nonce);
        msg.update(user_data);
        let msg = msg.finalize();

        let nonce = attest_data::Array::<32>(msg.into());
        let attest = self.oxattest_mock.attest(&nonce)?;

        let mut data = vec![0u8; OxAttestation::MAX_SIZE];
        let len = hubpack::serialize(&mut data, &attest)
            .map_err(|_| AttestMockError::Serialize)?;
        data.truncate(len);
        let data = data;

        let mut attestations = Vec::new();
        let rot = RotType::OxideHardware;
        attestations.push(Attestation { rot, data });

        Ok(attestations)
    }

    /// Get all measurement logs from the various RoTs on the platform.
    fn get_measurement_logs(&self) -> Result<Vec<MeasurementLog>, Self::Error> {
        let oxide_log = self.oxattest_mock.get_measurement_log()?;

        let mut data = vec![0u8; Log::MAX_SIZE];
        let len = hubpack::serialize(&mut data, &oxide_log)
            .map_err(|_| AttestMockError::Serialize)?;
        data.truncate(len);

        let mut logs = Vec::new();
        let rot = RotType::OxideHardware;
        logs.push(MeasurementLog { rot, data });

        Ok(logs)
    }

    fn get_cert_chain(&self, rot: RotType) -> Result<PkiPath, Self::Error> {
        match rot {
            RotType::OxideHardware => {
                Ok(self.oxattest_mock.get_certificates()?)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::fs;
    use x509_cert::{Certificate, der::asn1::Utf8StringRef};

    /// This module holds `const &str`s with paths to test data generated by
    /// build.rs
    mod config {
        include!(concat!(env!("OUT_DIR"), "/config.rs"));
    }

    // make this more interesting
    const NONCE: [u8; 32] = [0u8; 32];
    const USER_DATA: [u8; 32] = [0u8; 32];

    /// Pull in test data generated by build.rs & create mock RoT-Rs
    fn setup() -> AttestMock {
        let oxattest_mock = OxAttestMock::load(
            config::SIGNER_PKIPATH,
            config::LOG,
            config::ATTESTATION_SIGNER,
        )
        .expect("failed to create OxAttestMock from inputs");

        let instance_cfg = fs::read_to_string(config::VM_INSTANCE_CFG)
            .expect("read ATTEST_INSTANCE_LOG to string");

        let instance_cfg: VmInstanceConf = serde_json::from_str(&instance_cfg)
            .expect("parse JSON from mock cfg for instance RoT");

        AttestMock::new(oxattest_mock, instance_cfg)
    }

    #[test]
    fn get_measurement_logs() {
        let attest = setup();

        let logs = attest.get_measurement_logs().expect("get_measurement_logs");
        for log in logs {
            match log.rot {
                RotType::OxideHardware => assert!(!log.data.is_empty()),
            }
        }
    }

    // utility function to get common name from cert subject
    fn get_cert_cn(cert: &Certificate) -> Option<Utf8StringRef<'_>> {
        use const_oid::db::rfc4519::COMMON_NAME;

        for elm in cert.tbs_certificate.subject.0.iter() {
            for atav in elm.0.iter() {
                if atav.oid == COMMON_NAME {
                    return Some(
                        Utf8StringRef::try_from(&atav.value).expect(
                            "Decode name attribute value to UTF8 string",
                        ),
                    );
                }
            }
        }

        None
    }

    #[test]
    fn get_cert_chain() {
        let attest = setup();

        let cert_chain = attest
            .get_cert_chain(RotType::OxideHardware)
            .expect("get_cert_chain");
        let leaf_cn = get_cert_cn(&cert_chain[0]);

        // the leaf cert CN is defined in test-data/config.kdl
        assert_eq!(leaf_cn, Some(Utf8StringRef::new("alias").unwrap()));
    }

    #[test]
    fn attest() {
        let attest = setup();

        let nonce =
            Nonce::from_platform_rng().expect("Nonce from platform RNG");
        // TODO: should be a crypto key
        let user_data = vec![0u8, 1];

        let _ = attest
            .attest(&nonce, &user_data)
            .expect("AttestMock attest");
    }

    #[test]
    fn verify_cert_chain() {
        use std::fs;

        let attest = setup();
        let cert_chain = attest
            .get_cert_chain(RotType::OxideHardware)
            .expect("get cert chain");

        let root_cert = fs::read(config::PKI_ROOT).unwrap_or_else(|e| {
            panic!(
                "Read root cert for test PKI from file: {}, {e:?}",
                config::PKI_ROOT
            )
        });
        let root_cert = Certificate::load_pem_chain(&root_cert)
            .expect("Parse test root certificate");
        let verified_root = dice_verifier::verify_cert_chain(
            &cert_chain,
            Some(root_cert.as_ref()),
        )
        .expect("verify cert chain");
        assert_eq!(&root_cert[0], verified_root);
    }

    #[test]
    fn verify_attestation() {
        let attest = setup();

        // Find the log from the OxideHardware RoT.
        // This log gets special handling since it's included in attestations
        // from OxideHardware RoT directly.
        // TODO: Logs provided to VMs will always include one from this RoT.
        // We may be better off making it easier to find.
        let logs = attest.get_measurement_logs().expect("get_measurement_logs");
        let oxlog = logs.iter().find_map(|log| {
            if log.rot == RotType::OxideHardware {
                Some(log)
            } else {
                None
            }
        });

        let (log, _): (Log, _) = if let Some(oxlog) = oxlog {
            hubpack::deserialize(&oxlog.data)
                .expect("deserialize hubpacked log")
        } else {
            panic!("No measurement log for RotType::OxideHardware");
        };

        // Data passed from VM through API to propolis.
        // propolis, acting as the (sorta) RoT for VM mixes this into the 32
        // bytes that it passes to the oxide RoT for signing.
        // We'll need this later (along with the logs) to verify the attestation.
        let nonce = Nonce::from_array(NONCE);

        let cert_chain = attest
            .get_cert_chain(RotType::OxideHardware)
            .expect("AttestMock get_cert_chain");
        // signer cert is the leaf
        let signer_pub = &cert_chain[0];

        let attestation = attest
            .attest(&nonce, &USER_DATA)
            .expect("AttestMock attest");

        // Find the attestation from the OxideHardware RoT.
        // This gets special handling since we're using it to bind all other
        // attestations from the platform together
        // TODO: Attestations provided to VMs will always include one from this
        // RoT. We may be better off making it easier to find.
        let attestation = attestation.iter().find_map(|attest| {
            if attest.rot == RotType::OxideHardware {
                Some(attest)
            } else {
                None
            }
        });

        let (attestation, _): (OxAttestation, _) =
            if let Some(attestation) = attestation {
                hubpack::deserialize(&attestation.data)
                    .expect("deserialize attestation")
            } else {
                panic!("No attestation from RotType::OxideHubris");
            };

        // Reconstruct the 32 bytes passed from `AttestMock` down to the
        // RotType::OxideHardware:
        //
        // We pass `AttestMock` a 32 byte nonce and a &[u8] that we call `data`.
        // It then combines them as: `sha256(UUID | sha256(rootfs) | nonce | data)`
        let mut data_digest = Sha256::new();

        // Use the mock instance log as reference integrity measurements for
        // reconstructing the message signed by the RotType::OxideHardware.
        //
        // NOTE: Reference measurements for these things elements of the
        // attestation aren't something that we can provide in the typical
        // "signed manifest" sense. References for the following elements of
        // the attestation will come from:
        // - uuid: the oxide API call used to start the VM instance
        // - rootfs: some external authority responsible for producing the VM
        // image
        let instance_cfg = fs::read_to_string(config::VM_INSTANCE_CFG)
            .expect("read ATTEST_INSTANCE_LOG to string");
        let instance_cfg: VmInstanceConf = serde_json::from_str(&instance_cfg)
            .expect("parse JSON from mock cfg for instance RoT");
        data_digest.update(&instance_cfg.uuid);
        data_digest.update(&instance_cfg.image_digest.digest);

        // update digest w/ data provided by the VM
        data_digest.update(&nonce);
        data_digest.update(&USER_DATA);

        // smuggle this data into the `verify_attestation` function in the
        // `attest_data::Nonce` type
        let data_digest = data_digest.finalize();
        let data_digest = attest_data::Nonce {
            0: data_digest.into(),
        };

        let result = dice_verifier::verify_attestation(
            &signer_pub,
            &attestation,
            &log,
            &data_digest,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn appraise_log() {
        use dice_verifier::{MeasurementSet, ReferenceMeasurements};
        use rats_corim::Corim;
        let attest = setup();

        let corim = Corim::from_file(config::CORIM).expect("Corim from file");
        let rims =
            ReferenceMeasurements::try_from(std::slice::from_ref(&corim))
                .expect("Reference integrity measurements from file");

        let logs = attest.get_measurement_logs().expect("get_measurement_logs");
        let oxlog = logs.iter().find_map(|log| {
            if log.rot == RotType::OxideHardware {
                Some(log)
            } else {
                None
            }
        });

        let (log, _): (Log, _) = if let Some(oxlog) = oxlog {
            hubpack::deserialize(&oxlog.data)
                .expect("deserialize hubpacked log")
        } else {
            panic!("No measurement log for RotType::OxideHardware");
        };

        let cert_chain = attest
            .get_cert_chain(RotType::OxideHardware)
            .expect("AttestMock get_cert_chain");

        let measurements = MeasurementSet::from_artifacts(&cert_chain, &log)
            .expect("MeasurementSet from PkiPath and Log");

        let result = dice_verifier::verify_measurements(&measurements, &rims);
        assert!(result.is_ok());
    }
}
