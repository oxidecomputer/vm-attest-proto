// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use clap_verbosity::{InfoLevel, Verbosity};
use dice_verifier::{
    Attestation, Corim, Log, MeasurementSet, Nonce, ReferenceMeasurements,
};
use log::{debug, info};
use sha2::{Digest, Sha256};
use std::{fs, net::TcpStream, os::unix::net::UnixStream, path::PathBuf};
use vm_attest_trait::{
    PlatformAttestation, QualifyingData, RotType, VmInstanceRot,
    mock::VmInstanceConf,
    socket::{VmInstanceRotSocketClient, VmInstanceTcp},
    vsock::VmInstanceRotVsockClient,
};
use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};
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

#[derive(Debug, Subcommand)]
pub enum SocketType {
    /// Connect to `vm-instance-rot` as a client on a unix domain socket
    Unix {
        // path to unix socket file
        sock: PathBuf,
    },
    /// Connect to `vm-instance-rot` as a client on a vsock
    Vsock {
        // port to listen on
        #[clap(default_value_t = 1024)]
        port: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum Backend {
    /// Connect to the `vm-instance-rot` as a client
    VmInstanceRot {
        #[command(subcommand)]
        socket_type: SocketType,
    },
    /// Connect to the `vm-instnace` over TCP
    VmInstance { address: String },
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

    #[command(subcommand)]
    backend: Backend,
}

fn appraise_platform_attestation(
    attestation: &PlatformAttestation,
    qualifying_data: &QualifyingData,
    root_certs: Option<&[Certificate]>,
    rims: &ReferenceMeasurements,
    instance_rim: &VmInstanceConf,
) -> Result<()> {
    let mut cert_chain_pem = Vec::new();
    for cert in &attestation.cert_chain {
        cert_chain_pem
            .push(Certificate::from_der(cert).context("certificate from DER")?);
    }
    let cert_chain_pem = cert_chain_pem;
    let verified_root =
        dice_verifier::verify_cert_chain(&cert_chain_pem, root_certs)
            .context("verify cert chain")?;
    let cn = get_cert_cn(verified_root);
    let cn = cn.ok_or(anyhow!("No CN in cert chain root"))?;
    info!("cert chain verified against root with CN: {cn}");

    // Reconstruct the 32 bytes passed from `VmInstanceAttestMock` down to
    // the RotType::OxidePlatform:
    //
    // The challenger passes OxideInstance RoT 32 byte nonce and a &[u8]
    // that we call `data`. It then combines them as:
    // `sha256(instance_log | nonce | data)`
    //
    // include the log from the OxideInstance RoT in the digest
    let mut qdata = Sha256::new();
    for log in &attestation.measurement_logs {
        match log.rot {
            RotType::OxideInstance => qdata.update(&log.data),
            _ => continue,
        }
    }
    qdata.update(qualifying_data);

    // smuggle this data into the `verify_attestation` function in the
    // `attest_data::Nonce` type
    let qualifying_data = qdata.finalize();
    let qualifying_data = Nonce {
        0: qualifying_data.into(),
    };

    // get the log from the Oxide platform RoT
    let oxlog = attestation
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
        hubpack::deserialize(&attestation.attestation)?;

    dice_verifier::verify_attestation(
        &cert_chain_pem[0],
        &ox_attest,
        &log,
        &qualifying_data,
    )
    .context("verify attestation")?;

    info!("attestation verified");

    // appraise logs
    for log in &attestation.measurement_logs {
        match log.rot {
            RotType::OxidePlatform => {
                // use dice-verifier crate to use the RIMs to appraise the
                // log from the OxidePlatform RoT
                let (log, _): (Log, _) = hubpack::deserialize(&log.data)?;
                let measurements =
                    MeasurementSet::from_artifacts(&cert_chain_pem, &log)
                        .context("measurement set from artifacts")?;

                dice_verifier::verify_measurements(&measurements, rims)?;
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

                if *instance_rim != instance_cfg {
                    return Err(anyhow!(
                        "Vm Instance Conf verification failed"
                    ));
                }
                info!("metadata from Oxide VM Instance RoT appraised");
            }
        }
    }

    Ok(())
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

    match args.backend {
        // Using these backends we're talking directly to the `VmInstanceRot`
        // so there's no `VmInstance` to complicate the qualifying data. In this
        // case the qualifying data is just a random `Nonce`. Similarly, when
        // verifying attestations from this backend there's no log from the
        // `VmInstance` to appraise.
        Backend::VmInstanceRot { socket_type } => {
            let qualifying_data = QualifyingData::from_platform_rng()
                .context("qualifying data from platform RNG")?;
            match socket_type {
                SocketType::Unix { sock } => {
                    let stream = UnixStream::connect(&sock)
                        .context("connect to domain socket")?;
                    debug!("connected to VmInstanceRotServer socket");
                    let vm_instance_rot =
                        VmInstanceRotSocketClient::new(stream);
                    let attestation =
                        vm_instance_rot.attest(&qualifying_data)?;
                    appraise_platform_attestation(
                        &attestation,
                        &qualifying_data,
                        root_certs.as_deref(),
                        &platform_rim,
                        &instance_rim,
                    )
                    .context("appraise platform attestation")?;
                    info!(
                        "appraised attestation from VmInstanceRot over socket"
                    );
                }
                SocketType::Vsock { port } => {
                    let addr = VsockAddr::new(VMADDR_CID_HOST, port);
                    let stream = VsockStream::connect(&addr)
                        .context("vsock stream connect")?;
                    let vm_instance_rot = VmInstanceRotVsockClient::new(stream);
                    let attestation =
                        vm_instance_rot.attest(&qualifying_data)?;
                    appraise_platform_attestation(
                        &attestation,
                        &qualifying_data,
                        root_certs.as_deref(),
                        &platform_rim,
                        &instance_rim,
                    )
                    .context("appraise platform attestation")?;
                    info!(
                        "appraised attestation from VmInstanceRot over vsock"
                    );
                }
            };
        }
        // Using this backend will cause us to talk to the `VmInstance` over
        // Tcp. The `VmInstance` will include the public_key returned in the
        // `AttestedKey` structure in the qualifying data that it passes down
        // to the `VmInstanceRot`. We must recreate this qualifying data and
        // pass it to the appraisal function.
        Backend::VmInstance { address } => {
            let stream = TcpStream::connect(&address)
                .with_context(|| format!("tcp stream connect: {}", &address))?;
            debug!("connected to server: {}", &address);

            let mut vm_instance = VmInstanceTcp::new(stream);
            // send Nonce to server
            let nonce = Nonce::from_platform_rng()?;
            let attested_key =
                vm_instance.attest_key(&nonce).context("get attested key")?;

            // reconstruct the qualifying data constructed by the vm instance
            let mut qualifying_data = Sha256::new();
            qualifying_data.update(nonce);
            qualifying_data.update(&attested_key.public_key);
            let vm_qualifying_data = QualifyingData::from(
                Into::<[u8; 32]>::into(qualifying_data.finalize()),
            );

            // appraise the platform attestation & qualifying data
            appraise_platform_attestation(
                &attested_key.attestation,
                &vm_qualifying_data,
                root_certs.as_deref(),
                &platform_rim,
                &instance_rim,
            )
            .context("appraise platform attestation")?;
            info!("attested public key: {:?}", attested_key.public_key);

            // do something with the public key
        }
    }

    Ok(())
}
