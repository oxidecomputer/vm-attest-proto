## Tools

This directory has several tools that are useful for setting up two
demonstration / mock environments.

### vm-instance-rot

This is a mock implementation of the root of trust exposed to a virtual machine
(VM). It runs locally in a process accepting requests on either a unix domain
socket or on the host side of a vsock. The Oxide Platform RoT that backs this
server is a mock impl and is compiled into the tool.

### vm-instance

This tool acts as a client to the `vm-instance-rot`. It listens for qualifying
data (typically a nonce) sent from a challenger. These nonces are then combined
with a blob of data generated within the `vm-instance` to create the qualifying
data that's sent down to the `vm-instance-rot` where they're included in an
attestation from the Oxide Platform RoT.

### appraiser

The appraiser sends challenges in the form of qualifying data / nonces to the
`vm-instance`. It receives a `PlatformAttestation` in response. This attestation
is then appraised.

### configurations

These tools can be composed to demonstrate how the API works and how we intend
for it to be used.

#### host only

In this configuration all components run on a single host OS. The
`vm-instance-rot` and the `vm-instance` communicate over a unix domain socket.
The `appraiser` sends challenges to the `vm-instnace` over TCP.

#### virtal

To more accurately reflect the configuration we expect to deploy, the
`vm-instance` tool can be run in a VM with the help of the `debian-vm.sh`
script in the root of this repo. This requires that the `vm-instance-rot` be
configured to listen on a vsock.
