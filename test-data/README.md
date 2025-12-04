This directory contains static test input data.

## config.kdl

This file describes the PKI used by the mock implementation of the Oxide platform RoT.
It is processed by the [pki-playground](https://github.com/oxidecomputer/pki-playground) tool.
The PKI generated is intended to mimic the structure of our platform identity PKI as faithfully as possible.

The signing key associated with the leaf of the cert chain is used to sign attestations.
The root of the PKI is used as input to the cert chain verification process.

This cert chain also contains a single software measurement that the platform collects before the RoT measurement recording task is started.
This is input to the measurement log appraisal process.

## corim.kdl

This file is a textual representation of a reference integrity manifest.
It is processed by the [attest-mock](https://github.com/oxidecomputer/dice-util/tree/main/attest-mock) tool to generate a CoRIM document.
We publish CoRIM documents for each software release to aid in the appraisal process.
This particular spec will build a CoRIM that includes the measurements in the log we use for testing (see [config.kdl](#config.kdl) and [log.kdl](#log.kdl)).

## log.kdl

This file is a textual representation of a measurement log as produced by the Oxide platform RoT.
It is processed by the [attest-mock](https://github.com/oxidecomputer/dice-util/tree/main/attest-mock) tool to generate the hubpacked encoding of the measurment log used in the test module.

## vm-instance-cfg.json

This file is a JSON encoding of the metadata for a VM instance.
It is used in the test module as:
- input to the mock implementation of our trait
- our source of truth for VM instance configuration values (`vm_cfg`) in the attestation verification process
