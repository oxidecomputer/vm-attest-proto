// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use log::{debug, info};
use std::io::{BufRead, BufReader, Write};
use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    // vsock port to connect to on the host
    #[clap(long, default_value_t = 1024)]
    port: u32,

    message: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let addr = VsockAddr::new(VMADDR_CID_HOST, args.port);
    let mut stream =
        VsockStream::connect(&addr).context("vsock stream connect")?;

    stream
        .write_all(args.message.as_bytes())
        .context("write message to vsock")?;
    debug!("message written to vsock");

    stream.write(b"\n").context("write message terminator")?;
    debug!("terminator written to vsock");

    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();
    let count = reader
        .read_line(&mut response)
        .context("read line from server")?;

    debug!("read {count} bytes");

    if count > 0 {
        info!("got response: {response}");
        Ok(())
    } else {
        Err(anyhow!("read 0 bytes: EOF"))
    }
}
