// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{self, Path, PathBuf};

/// Execute one of the `pki-playground` commands to generate part of the PKI
/// used for testing.
fn pki_gen_cmd(command: &str, cfg: &Path) -> Result<()> {
    if !fs::exists(cfg).with_context(|| {
        format!("failed to determin if file exists: {}", cfg.display())
    })? {
        return Err(anyhow!("missing PKI config file: {}", cfg.display()));
    }

    let mut cmd = std::process::Command::new("pki-playground");
    cmd.arg("--config");
    cmd.arg(cfg);
    cmd.arg(command);
    let output = cmd
        .output()
        .context("executing command \"pki-playground\"")?;

    if !output.status.success() {
        let stdout = String::from_utf8(output.stdout)
            .context("String from pki-playground stdout")?;
        println!("stdout: {stdout}");
        let stderr = String::from_utf8(output.stderr)
            .context("String from pki-playground stderr")?;
        println!("stderr: {stderr}");

        return Err(anyhow!("cmd failed: {cmd:?}"));
    }

    Ok(())
}

/// Execute one of the `attest-mock` commands to generate mock input data used
/// for testing.
fn attest_gen_cmd(command: &str, input: &Path, output: &str) -> Result<()> {
    if !fs::exists(input).with_context(|| {
        format!("failed to determin if file exists: {}", input.display())
    })? {
        return Err(anyhow!("missing config file: {}", input.display()));
    }

    // attest-mock "input" "cmd" > "output"
    let mut cmd = std::process::Command::new("attest-mock");
    cmd.arg(input).arg(command);
    let cmd_output =
        cmd.output().context("executing command \"attest-mock\"")?;

    if cmd_output.status.success() {
        std::fs::write(output, cmd_output.stdout).context("write {output}")
    } else {
        let stderr = String::from_utf8(cmd_output.stderr)
            .context("String from attest-mock stderr")?;
        println!("stderr: {stderr}");

        Err(anyhow!("cmd failed: {cmd:?}"))
    }
}

fn write_path_to_conf(mut file: &File, path: &Path, name: &str) -> Result<()> {
    if !fs::exists(path).with_context(|| {
        format!("checking existance of file: {}", path.display())
    })? {
        return Err(anyhow!("required file not present: {}", path.display()));
    }

    Ok(writeln!(
        file,
        "#[allow(dead_code)]\npub const {}: &str =\n    \"{}\";\n",
        name,
        path.display(),
    )?)
}

/// This path is where Oxide specific libraries live on helios systems.
/// The linker needs this path to find libipcc:
/// https://github.com/oxidecomputer/ipcc-rs/
#[cfg(target_os = "illumos")]
static OXIDE_PLATFORM: &str = "/usr/platform/oxide/lib/amd64/";

fn main() -> Result<()> {
    #[cfg(target_os = "illumos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-R{}", OXIDE_PLATFORM);
        println!("cargo:rustc-link-search={}", OXIDE_PLATFORM);
    }

    let cwd = env::current_dir().context("get current dir")?;
    let mut cwd = path::absolute(cwd).context("current_dir to absolute")?;

    // output directory where we put:
    // generated test inputs
    let mut out =
        PathBuf::from(env::var("OUT_DIR").context("Could not get OUT_DIR")?);
    env::set_current_dir(&out)
        .with_context(|| format!("chdir to {}", out.display()))?;

    // paths consumed by the library as const `&str`s go here
    out.push("config.rs");
    let config_out = File::create(&out)
        .with_context(|| format!("creating {}", out.display()))?;
    out.pop();

    cwd.push("test-data");
    cwd.push("config.kdl");
    let mut pki_cfg = cwd;
    // generate keys
    pki_gen_cmd("generate-key-pairs", &pki_cfg)?;
    out.push("test-alias.key.pem");
    write_path_to_conf(&config_out, &out, "ATTESTATION_SIGNER")
        .context("write variable w/ path to attestation signing key")?;
    out.pop();

    // generate certs
    pki_gen_cmd("generate-certificates", &pki_cfg)?;
    out.push("test-root.cert.pem");
    write_path_to_conf(&config_out, &out, "PKI_ROOT")
        .context("write PKI_ROOT const str to config.rs")?;
    out.pop();

    // generate cert chains
    pki_gen_cmd("generate-certificate-lists", &pki_cfg)?;
    pki_cfg.pop();
    out.push("test-alias.certlist.pem");
    write_path_to_conf(&config_out, &out, "SIGNER_PKIPATH")
        .context("write variable w/ path to attestation signing key")?;
    out.pop();

    // generate measurement log
    let mut log_cfg = pki_cfg;
    log_cfg.push("log.kdl");
    attest_gen_cmd("log", &log_cfg, "log.bin")?;
    log_cfg.pop();

    out.push("log.bin");
    write_path_to_conf(&config_out, &out, "LOG")
        .context("write variable w/ path to attestation signing key")?;
    out.pop();

    // generate the corpus of reference measurements
    let mut corim_cfg = log_cfg;
    corim_cfg.push("corim.kdl");
    attest_gen_cmd("corim", &corim_cfg, "corim.cbor")?;
    corim_cfg.pop();

    out.push("corim.cbor");
    write_path_to_conf(&config_out, &out, "CORIM").context(
        "write variable w/ path to reference integrity measurements",
    )?;
    out.pop();

    let mut vm_instance_cfg = corim_cfg;
    vm_instance_cfg.push("vm-instance-cfg.json");
    write_path_to_conf(&config_out, &vm_instance_cfg, "VM_INSTANCE_CFG")
        .context(
            "write variable w/ path to data attested by the InstanceRoT",
        )?;
    vm_instance_cfg.pop();

    Ok(())
}
