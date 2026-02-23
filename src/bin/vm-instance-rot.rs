// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use clap_verbosity::{InfoLevel, Verbosity};
use dice_verifier::AttestMock as OxAttestMock;
use log::debug;
use std::{fs, os::unix::net::UnixListener, path::PathBuf};
use vsock::{VsockAddr, VsockListener};

use vm_attest_trait::{
    VmInstanceConf, mock::VmInstanceRotMock, socket::VmInstanceRotSocketServer,
    vsock::VmInstanceRotVsockServer,
};

#[derive(Debug, Subcommand)]
enum SocketType {
    /// Listen for messages on a unix domain socket
    Unix { sock: PathBuf },
    /// Listen for messages on the host side of a vsock
    Vsock {
        /// Accept connections from this specific context ID
        #[clap(long, default_value_t = libc::VMADDR_CID_ANY)]
        cid: u32,

        /// Port to listen on
        #[clap(default_value_t = 1024)]
        port: u32,
    },
}

/// This is a mock implementation of the root of trust exposed to a virtual
/// machine (VM). It runs locally in a process accepting requests on either
/// a unix domain socket or on the host side of a vsock.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    /// The root certificate(s) used for verifying cert chains from the RoT
    #[clap(long)]
    cert_chain: PathBuf,

    /// The log returned by the mock platform RoT
    #[clap(long)]
    log: PathBuf,

    /// Key used by the mock platform RoT to sign attestations
    #[clap(long)]
    signing_key: PathBuf,

    /// Measurement log for VmInstanceRot,
    #[clap(long)]
    vm_instance_cfg: PathBuf,

    /// The type of the socket to listen on
    #[command(subcommand)]
    socket_type: SocketType,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let oxide_platform_rot = Box::new(
        OxAttestMock::load(&args.cert_chain, &args.log, &args.signing_key)
            .context("create OxAttestMock from artifacts")?,
    );

    debug!("reading VmInstanceRotMock config from file");
    let instance_cfg = fs::read_to_string(&args.vm_instance_cfg)
        .context("read ATTEST_INSTANCE_CFG to string")?;
    let instance_cfg: VmInstanceConf = serde_json::from_str(&instance_cfg)
        .context("parse JSON from mock cfg for instance RoT")?;

    debug!("creating instance of VmInstanceAttestMock");
    // instantiate an `AttestMock` w/ the Oxide platform RoT instance requested
    // by the caller & the config
    let attest = VmInstanceRotMock::new(oxide_platform_rot, instance_cfg);

    match args.socket_type {
        SocketType::Unix { sock } => {
            if sock.exists() {
                return Err(anyhow!("socket file exists"));
            }
            debug!("binding to sock file: {}", sock.display());

            let listener = UnixListener::bind(&sock)
                .context("failed to bind to socket")?;
            debug!("listening on socket file: {}", sock.display());

            Ok(VmInstanceRotSocketServer::new(attest, listener).run()?)
        }
        SocketType::Vsock { cid, port } => {
            debug!("binding to vsock cid:port: ({cid}, {port})");
            let listener = VsockListener::bind(&VsockAddr::new(cid, port))
                .with_context(|| format!("bind to cid,pid: ({cid},{port})"))?;
            debug!("listening on cid,port: ({cid},{port})");

            Ok(VmInstanceRotVsockServer::new(attest, listener).run()?)
        }
    }
}
