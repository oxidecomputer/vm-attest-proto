// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use dice_verifier::{
    Attestation as OxAttestation, Corim, Log, MeasurementSet,
    ReferenceMeasurements,
};

use log::{debug, info};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::net::UnixStream, path::PathBuf};
use x509_cert::{Certificate, der::Decode};

use vm_attest_trait::{
    Nonce, RotType, VmInstanceAttester, mock::VmInstanceConf,
    socket::VmInstanceAttestSocket,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    #[clap(long)]
    root_cert: Option<PathBuf>,

    #[clap(long, default_value_t = false)]
    self_signed: bool,

    #[clap(long)]
    reference_measurements: Vec<PathBuf>,

    #[clap(long)]
    vm_instance_cfg: PathBuf,

    // Path to socket file. If file already exists an error is returned
    file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    // fail early if the socket file doesn't exist
    if !args.file.exists() {
        return Err(anyhow!("socket file missing"));
    }

    // load reference integrity measurements from CORIMs
    let mut corims = Vec::new();
    for corim in &args.reference_measurements {
        let corim = Corim::from_file(corim).with_context(|| {
            format!("loading CORIM from: {}", corim.display())
        })?;
        corims.push(corim);
    }
    let rims = ReferenceMeasurements::try_from(corims.as_slice())
        .context("Reference measurements from CORIMs")?;
    debug!("loaded reference integrity measurements");

    // load the provided root certs
    let root_cert = match args.root_cert {
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
    debug!("loaded root certs: {:?}", root_cert);

    // construct a `VmInstanceConf` from test data
    // this is our reference for appraising the log produced by the
    // `RotType::OxideInstance`
    let instance_rim = fs::read_to_string(&args.vm_instance_cfg)
        .context("read ATTEST_INSTANCE_LOG to string")?;
    let instance_rim: VmInstanceConf = serde_json::from_str(&instance_rim)
        .context("parse JSON from rim for instance RoT log")?;

    let stream = UnixStream::connect(&args.file).context("connec to socket")?;
    debug!("connected to socket");
    let attest = VmInstanceAttestSocket::new(stream);

    let nonce =
        Nonce::from_platform_rng().context("Nonce from paltform RNG")?;
    debug!("generating nonce: {nonce:?}");
    let data = vec![66, 77, 88, 99];
    debug!("user_data: {data:?}");

    let cert_chains = attest.get_cert_chains().context("get cert chains")?;
    debug!("got cert chains");

    for cert_chain in &cert_chains {
        match cert_chain.rot {
            RotType::OxidePlatform => {
                // TODO: having access to each cert chain as a Vec<Certificate>
                // for future use would be nice ... maybe a HashMap keyed on
                // the RotType.
                let mut cert_chain_pem = Vec::new();
                for cert in &cert_chain.certs {
                    cert_chain_pem.push(
                        Certificate::from_der(cert)
                            .context("Certificate from DER")?,
                    );
                }
                let _verified_root = dice_verifier::verify_cert_chain(
                    &cert_chain_pem,
                    root_cert.as_deref(),
                )
                .context("verify cert chain")?;
                match root_cert {
                    Some(_) => {
                        // TODO: pull subject string from the cert
                        info!("cert chain verified against provided root");
                    }
                    None => info!("cert chain verified to self-signed root"),
                }
            }
            // this RoT doesn't have a cert chain
            RotType::OxideInstance => {
                return Err(anyhow!(
                    "unexpected cert chain from OxideInstance RoT"
                ));
            }
        }
    }

    let logs = attest
        .get_measurement_logs()
        .context("get measurement logs")?;
    debug!("got measurement logs");

    let attestations =
        attest.attest(&nonce, &data).context("get attestations")?;
    debug!("got attestations");

    if attestations.len() != 1 {
        return Err(anyhow!("unexpected number of attestations returned"));
    }

    let attestation = &attestations[0];
    if attestation.rot != RotType::OxidePlatform {
        return Err(anyhow!(format!(
            "unexpected RotType in attestation: {:?}",
            attestation.rot
        )));
    }

    let (attestation, _): (OxAttestation, _) =
        hubpack::deserialize(&attestation.data)
            .context("deserialize attestation from Oxide platform RoT")?;

    // Reconstruct the 32 bytes passed from `VmInstanceAttestMock` down to
    // the RotType::OxidePlatform:
    //
    // The challenger passes OxideInstance RoT 32 byte nonce and a &[u8]
    // that we call `data`. It then combines them as:
    // `sha256(instance_log | nonce | data)`
    let mut data_digest = Sha256::new();

    // include the log from the OxideInstance RoT in the digest
    for log in &logs {
        match log.rot {
            RotType::OxideInstance => data_digest.update(&log.data),
            _ => continue,
        }
    }

    // update digest w/ data provided by the VM
    data_digest.update(&nonce);
    data_digest.update(&data);

    // smuggle this data into the `verify_attestation` function in the
    // `attest_data::Nonce` type
    let data_digest = data_digest.finalize();
    let data_digest = attest_data::Nonce {
        0: data_digest.into(),
    };

    // get the log from the Oxide platform RoT

    // let _ = (0..3).find_map(|x| if x > 2 { Some(x) } else { None });
    // As there is no transformation of the argument this could be written as:
    // let _ = (0..3).find(|&x| x > 2);

    let oxlog = logs.iter().find(|&log| log.rot == RotType::OxidePlatform);

    // put log in the form expected by the `verify_attestation` function
    let (log, _): (Log, _) = if let Some(oxlog) = oxlog {
        hubpack::deserialize(&oxlog.data).expect("deserialize hubpacked log")
    } else {
        return Err(anyhow!("No measurement log for RotType::OxidePlatform"));
    };

    // signer cert is the leaf
    let cert = Certificate::from_der(&cert_chains[0].certs[0])
        .expect("Certificate from DER");

    let result = dice_verifier::verify_attestation(
        &cert,
        &attestation,
        &log,
        &data_digest,
    );

    if result.is_err() {
        return Err(anyhow!("attestation verification failed"));
    } else {
        info!("attestation verified");
    }

    // get cert chain required to reconstruct the collection of measurements
    // from the Oxide Platform RoT
    let oxplatform_rot_cert_chain = cert_chains
        .iter()
        .find(|&cert_chain| cert_chain.rot == RotType::OxidePlatform);
    let oxplatform_rot_cert_chain =
        if let Some(cert_chain) = oxplatform_rot_cert_chain {
            cert_chain
        } else {
            return Err(anyhow!("No cert chain for RotType::OxidePlatform"));
        };

    for log in &logs {
        match log.rot {
            RotType::OxidePlatform => {
                // use dice-verifier crate to use the RIMs to appraise the
                // log from the OxidePlatform RoT
                let (log, _): (Log, _) = hubpack::deserialize(&log.data)
                    .context(
                        "deserialize hubpacked log from Oxide Platform RoT",
                    )?;
                let mut cert_chain_pem = Vec::new();
                for cert in &oxplatform_rot_cert_chain.certs {
                    cert_chain_pem.push(
                        Certificate::from_der(cert)
                            .context("Certificate from DER")?,
                    );
                }

                let measurements =
                    MeasurementSet::from_artifacts(&cert_chain_pem, &log)
                        .expect("MeasurementSet from PkiPath and Log");

                dice_verifier::verify_measurements(&measurements, &rims)
                    .context("appraising measurements")?;
                info!("measurement log from Oxide Platform RoT appraised");
            }
            RotType::OxideInstance => {
                // compare log / config description from the OxideInstance
                // RoT to the reference from the config reference
                let instance_cfg =
                    std::str::from_utf8(&log.data).expect("utf8 from log data");
                let instance_cfg: VmInstanceConf =
                    serde_json::from_str(instance_cfg)
                        .expect("parse JSON from log data");

                if instance_rim != instance_cfg {
                    return Err(anyhow!(
                        "appraisal of measurements from VmInstanceRot failed"
                    ));
                }
                info!("metadata from Oxide VM Instance RoT appraised");
            }
        }
    }

    Ok(())
}
