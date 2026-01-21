// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use log::{debug, info};
use std::io::{BufRead, BufReader, Write};
use vsock::{VsockAddr, VsockListener};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    // context ID
    #[clap(long)]
    cid: Option<u32>,

    // vsock port to listen on
    #[clap(default_value_t = 1024)]
    port: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let cid = args.cid.unwrap_or(libc::VMADDR_CID_ANY);
    let port = args.port;

    let listener = VsockListener::bind(&VsockAddr::new(cid, port))
        .with_context(|| format!("bind to cid,pid: ({cid},{port})"))?;

    debug!("listening on cid,port: ({cid},{port})");

    let mut msg = String::new();
    for client in listener.incoming() {
        let mut client = client?;

        loop {
            let mut reader = BufReader::new(&mut client);

            let count = reader.read_line(&mut msg)?;
            if count == 0 {
                debug!("read 0 bytes: EOF");
                break;
            }

            info!("got message: {msg}");

            client.write_all(msg.as_bytes())?;
            msg.clear();

            info!("message returned");
        }
    }

    Ok(())
}
