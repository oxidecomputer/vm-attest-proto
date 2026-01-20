// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};

use log::debug;
use std::{net::TcpListener, os::unix::net::UnixStream, path::PathBuf};

use vm_attest_trait::{
    socket::VmInstanceRotSocket, socket::VmInstanceTcpServer,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    // Path to socket file. If file already exists an error is returned
    socket: PathBuf,

    // Address used for server that listens for challenges
    address: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    // fail early if the socket file doesn't exist
    if !args.socket.exists() {
        return Err(anyhow!("socket file missing"));
    }

    let stream = UnixStream::connect(&args.socket)
        .context("connect to domain socket")?;
    debug!("connected to VmInstanceRotServer socket");
    let vm_instance_rot = VmInstanceRotSocket::new(stream);

    // creat TCP listener
    let challenge_listener =
        TcpListener::bind(&args.address).context("bind to TCP socket")?;
    debug!("Listening on TCP address{:?}", &args.address);

    let server = VmInstanceTcpServer::new(challenge_listener, vm_instance_rot);
    Ok(server.run()?)
}
