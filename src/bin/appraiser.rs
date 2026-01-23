// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use dice_verifier::{
    Attestation, Corim, Log, MeasurementSet, Nonce, ReferenceMeasurements,
};
use log::{debug, info};
use sha2::{Digest, Sha256, digest::FixedOutputReset};
use std::{fs, net::TcpStream, path::PathBuf};
use vm_attest_trait::{RotType, mock::VmInstanceConf, socket::VmInstanceTcp};
use x509_cert::{
    Certificate,
    der::{Decode, asn1::Utf8StringRef},
};

// utility function to get common name from cert subject
fn get_cert_cn(cert: &Certificate) -> Option<Utf8StringRef<'_>> {
    use const_oid::db::rfc4519::COMMON_NAME;

    for elm in cert.tbs_certificate.subject.0.iter() {
        for atav in elm.0.iter() {
            if atav.oid == COMMON_NAME {
                return Some(
                    Utf8StringRef::try_from(&atav.value)
                        .expect("Decode name attribute value to UTF8 string"),
                );
            }
        }
    }

    None
}

/// the appraiser challenges the VM instance by sending it a Nonce. It gets
/// back an attestation from the platform. It then uses the artifacts provided
/// to appraise the attestation.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    /// The root certificate(s) used for verifying cert chains from the RoT
    #[clap(long)]
    root_cert: Option<PathBuf>,

    #[clap(long, default_value_t = false)]
    self_signed: bool,

    /// Reference integrity measurements in CoRIM documents that identify the
    /// various software components that we trust
    #[clap(long)]
    reference_measurements: Vec<PathBuf>,

    /// Reference integrity measurements in a JSON structure that identify the
    /// expected UUID & boot disk digest
    #[clap(long)]
    vm_instance_cfg: PathBuf,

    /// The IP address of the VM that we're challenging for an attestation
    address: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    // load reference integrity measurements from CORIMs
    let mut corims = Vec::new();
    for corim in &args.reference_measurements {
        let corim = Corim::from_file(corim).with_context(|| {
            format!("loading CORIM from: {}", corim.display())
        })?;
        corims.push(corim);
    }
    let platform_rim = ReferenceMeasurements::try_from(corims.as_slice())
        .context("Reference measurements from CORIMs")?;
    debug!("loaded reference integrity measurements");

    // load the provided root certs
    let root_certs = match args.root_cert {
        Some(path) => {
            let root_cert = fs::read(&path)
                .with_context(|| format!("read file: {}", path.display()))?;
            Some(
                Certificate::load_pem_chain(&root_cert)
                    .context("failed to load certs from the provided file")?,
            )
        }
        None => {
            if !args.self_signed {
                return Err(anyhow!(
                    "No root cert, `--self-signed` must be explicit"
                ));
            } else {
                None
            }
        }
    };
    debug!("loaded root certs: {:?}", root_certs);

    // construct a `VmInstanceConf` from test data
    // this is our reference for appraising the log produced by the
    // `RotType::OxideInstance`
    let instance_rim = fs::read_to_string(&args.vm_instance_cfg)
        .context("read ATTEST_INSTANCE_LOG to string")?;
    let instance_rim: VmInstanceConf = serde_json::from_str(&instance_rim)
        .context("parse JSON from rim for instance RoT log")?;

    let stream = TcpStream::connect(&args.address)
        .with_context(|| format!("tcp stream connect: {}", &args.address))?;
    debug!("connected to server: {}", &args.address);

    let mut vm_instance = VmInstanceTcp::new(stream);
    // send Nonce to server
    let nonce = Nonce::from_platform_rng()?;
    let attested_key =
        vm_instance.attest_key(&nonce).context("get attested key")?;
    info!("attested_key: {attested_key:?}");

    let mut cert_chain_pem = Vec::new();
    for cert in &attested_key.attestation.cert_chain {
        cert_chain_pem
            .push(Certificate::from_der(cert).context("certificate from DER")?);
    }
    let cert_chain_pem = cert_chain_pem;
    let verified_root = dice_verifier::verify_cert_chain(
        &cert_chain_pem,
        root_certs.as_deref(),
    )
    .context("verify cert chain")?;
    let cn = get_cert_cn(verified_root);
    let cn = cn.ok_or(anyhow!("No CN in cert chain root"))?;
    info!("cert chain verified against root with CN: {cn}");

    // verify attestation
    let mut qualifying_data = Sha256::new();
    qualifying_data.update(nonce);
    qualifying_data.update(&attested_key.public_key);
    let vm_qualifying_data = qualifying_data.finalize_fixed_reset();

    // Reconstruct the 32 bytes passed from `VmInstanceAttestMock` down to
    // the RotType::OxidePlatform:
    //
    // The challenger passes OxideInstance RoT 32 byte nonce and a &[u8]
    // that we call `data`. It then combines them as:
    // `sha256(instance_log | nonce | data)`
    //
    // include the log from the OxideInstance RoT in the digest
    for log in &attested_key.attestation.measurement_logs {
        match log.rot {
            RotType::OxideInstance => qualifying_data.update(&log.data),
            _ => continue,
        }
    }
    qualifying_data.update(vm_qualifying_data);

    // smuggle this data into the `verify_attestation` function in the
    // `attest_data::Nonce` type
    let qualifying_data = qualifying_data.finalize();
    let qualifying_data = Nonce {
        0: qualifying_data.into(),
    };

    // get the log from the Oxide platform RoT
    let oxlog = attested_key
        .attestation
        .measurement_logs
        .iter()
        .find(|&log| log.rot == RotType::OxidePlatform);

    // put log in the form expected by the `verify_attestation` function
    let (log, _): (Log, _) = if let Some(oxlog) = oxlog {
        hubpack::deserialize(&oxlog.data)
            .context("hubpack deserialize platform RoT log")?
    } else {
        return Err(anyhow!("no measurement log for Oxide Platform RoT"));
    };

    let (ox_attest, _): (Attestation, _) =
        hubpack::deserialize(&attested_key.attestation.attestation)?;

    dice_verifier::verify_attestation(
        &cert_chain_pem[0],
        &ox_attest,
        &log,
        &qualifying_data,
    )
    .context("verify attestation")?;

    info!("attestation verified");

    // appraise logs
    for log in &attested_key.attestation.measurement_logs {
        match log.rot {
            RotType::OxidePlatform => {
                // use dice-verifier crate to use the RIMs to appraise the
                // log from the OxidePlatform RoT
                let (log, _): (Log, _) = hubpack::deserialize(&log.data)?;
                let measurements =
                    MeasurementSet::from_artifacts(&cert_chain_pem, &log)
                        .context("measurement set from artifacts")?;

                dice_verifier::verify_measurements(
                    &measurements,
                    &platform_rim,
                )?;
                info!("measurement log from Oxide Platform RoT appraised");
            }
            RotType::OxideInstance => {
                // compare log / config description from the OxideInstance
                // RoT to the reference from the config reference
                let instance_cfg =
                    str::from_utf8(&log.data).context("string from UTF8")?;
                let instance_cfg: VmInstanceConf =
                    serde_json::from_str(instance_cfg)
                        .context("VmInstanceConf from JSON")?;

                if instance_rim != instance_cfg {
                    return Err(anyhow!(
                        "Vm Instance Conf verification failed"
                    ));
                }
                info!("metadata from Oxide VM Instance RoT appraised");
            }
        }
    }

    // do something with the public key

    Ok(())
}
