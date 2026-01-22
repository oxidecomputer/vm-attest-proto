// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use clap_verbosity::{InfoLevel, Verbosity};

use log::debug;
use std::{net::TcpListener, os::unix::net::UnixStream, path::PathBuf};
use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

use vm_attest_trait::{
    socket::{VmInstanceRotSocket, VmInstanceTcpServer},
    vsock::VmInstanceRotVsockClient,
};

#[derive(Debug, Subcommand)]
enum SocketType {
    Unix {
        // path to unix socket file
        sock: PathBuf,
    },
    Vsock {
        // port to listen on
        #[clap(default_value_t = 1024)]
        port: u32,
    },
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    // Address used for server that listens for challenges
    #[clap(long, default_value_t = String::from("localhost:6666"))]
    address: String,

    #[command(subcommand)]
    socket_type: SocketType,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    match args.socket_type {
        SocketType::Unix { sock } => {
            // fail early if the socket file doesn't exist
            if !sock.exists() {
                return Err(anyhow!("socket file missing"));
            }

            let stream = UnixStream::connect(&sock)
                .context("connect to domain socket")?;
            debug!("connected to VmInstanceRotServer socket");
            let vm_instance_rot = VmInstanceRotSocket::new(stream);

            let challenge_listener = TcpListener::bind(&args.address)
                .context("bind to TCP socket")?;
            debug!("Listening on TCP address{:?}", &args.address);

            let server =
                VmInstanceTcpServer::new(challenge_listener, vm_instance_rot);
            Ok(server.run()?)
        }
        SocketType::Vsock { port } => {
            debug!("connecting to host vsock on port: {port}");
            let addr = VsockAddr::new(VMADDR_CID_HOST, port);
            let stream =
                VsockStream::connect(&addr).context("vsock stream connect")?;

            debug!("creating VmInstanceRotVsockClient from VsockStream");
            let vm_instance_rot = VmInstanceRotVsockClient::new(stream);

            debug!("binding to address: {}", &args.address);
            let challenge_listener = TcpListener::bind(&args.address)
                .context("bind to TCP socket")?;
            debug!("Listening on TCP address{:?}", &args.address);

            let server =
                VmInstanceTcpServer::new(challenge_listener, vm_instance_rot);
            Ok(server.run()?)
        }
    }
}
