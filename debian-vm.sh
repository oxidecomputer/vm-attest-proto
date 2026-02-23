#!/usr/bin/env bash

# This script uses `debootstrap` to create a qcow2 to host the in-VM parts of
# this system. The disk produced by this script should be run under qemu with
# a command like:
#
# ```shell
# $ qemu-system-x86_64 -enable-kvm \
#     -m 2G \
#     -nographic \
#     -serial mon:stdio \
#     -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
#     -drive file=vm-instance.qcow2,if=virtio,readonly=on \
#     -net nic,model=virtio-net-pci,addr=0x3 \
#     -net bridge,br=br0 \
#     -device vhost-vsock-pci,guest-cid=3
# ```
#
# Your environment will likely require fixups for file paths
# Network configuration in the VM depends on the 'virtio-net-pci' configuration
# in the command above. By default 'virtio-net-pci' puts the device on bus 0,
# slot 3 but the example command is intended to make this explicit.

set -euo pipefail

if [ ! $# -ge 1 ]; then
    >&2 echo "disk image name is required"
    exit 1
fi

NAME="$1"
QCOW_FILE="$NAME".qcow2

# assumes pwd is `vm-attest-proto` src dir
cargo build

BINS="target/debug/vm-instance target/debug/appraiser"
for BIN in $BINS; do
    if [ ! -e "$BIN" ]; then
        >&2 echo "missing required file: $BIN"
        exit 1
    fi
done

qemu-img create -f qcow2 "$QCOW_FILE" 2G

if lsmod | awk '{print $2}' | grep '^nbd'; then
    sudo modprobe nbd
fi

# TODO: increment the integer part of the device name till we find an available
# one?
NBD_DEV=/dev/nbd0
if /usr/sbin/nbd-client --check "$NBD_DEV"; then
    >&2 echo "nbd device '$NBD_DEV' is in use"
    exit 1
fi
sudo qemu-nbd -c "$NBD_DEV" "$QCOW_FILE"

sudo parted -s -a optimal -- "$NBD_DEV" \
  mklabel gpt \
  mkpart primary fat32 1MiB 128MiB \
  mkpart primary ext4 128MiB -0 \
  name 1 uefi \
  name 2 root \
  set 1 esp on

sudo mkfs -t fat -F 32 -n EFI /dev/nbd0p1
sudo mkfs -t ext4 -L root /dev/nbd0p2

ROOT_UUID=$(sudo blkid | grep "^$NBD_DEV" | grep ' LABEL="root" ' | grep -o ' UUID="[^"]\+"' | sed -e 's/^ //')
EFI_UUID=$(sudo blkid | grep "^$NBD_DEV" | grep ' LABEL="EFI" ' | grep -o ' UUID="[^"]\+"' | sed -e 's/^ //')

BOOTSTRAP_ROOT="bootstrap-root"
mkdir "$BOOTSTRAP_ROOT"
sudo mount "$ROOT_UUID" "$BOOTSTRAP_ROOT"

# do the `debootstrap` thing
sudo debootstrap --arch amd64 stable "$BOOTSTRAP_ROOT" http://ftp.us.debian.org/debian

sudo mount -o bind,ro /dev "$BOOTSTRAP_ROOT"/dev
sudo mount -t proc /proc "$BOOTSTRAP_ROOT"/proc
sudo mount -t sysfs none "$BOOTSTRAP_ROOT"/sys

sudo LANG=C.UTF-8 chroot "$BOOTSTRAP_ROOT" /bin/bash -x <<EOS
set -euo pipefail

cat <<EOF > /etc/fstab
$ROOT_UUID / ext4 errors=remount-ro 0 1
$EFI_UUID /boot/efi vfat defaults 0 1
EOF

[[ -d /boot/efi ]] || mkdir /boot/efi
mount -a

# cloud-init will find the network interface from metadata but we must source
# the files from 'interfaces.d' to get debian to put them into effect
cat <<EOF > /etc/network/interfaces
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF

echo "vm-instance" > /etc/hostname

cat <<EOF > /etc/hosts
127.0.0.1       localhost
127.0.1.1       vm-instance

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

debconf-set-selections <<EOF
tzdata tzdata/Areas select America
tzdata tzdata/Zones/America select Los_Angeles
EOF

# This is necessary as tzdata will assume these are manually set and override the
# debconf values with their settings
rm -f /etc/localtime /etc/timezone
DEBCONF_NONINTERACTIVE_SEEN=true dpkg-reconfigure -f noninteractive tzdata

apt-get update

debconf-set-selections <<EOF
locales locales/locales_to_be_generated multiselect en_US.UTF-8 UTF-8
locales locales/default_environment_locale select en_US.UTF-8
EOF

# Stop anything overriding debconf's settings
rm -f /etc/default/locale /etc/locale.gen /etc/default/keyboard
DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes locales linux-image-amd64 grub-efi-amd64 overlayroot cloud-init

# Add console=ttyS0 so we get early boot messages on the serial console.
sed -i -e 's/^\\(GRUB_CMDLINE_LINUX="[^"]*\\)"$/\\1 console=ttyS0"/' /etc/default/grub

# configure 'overlayroot' to setup an 'overlayfs' backed by 'tmpfs' to make
# using this image less painful
cat <<EOF > /etc/overlayroot.conf
overlayroot=tmpfs
EOF

# 'overlayroot' requires this workaround to function properly on Debian 13
# https://github.com/systemd/systemd/issues/39558#issuecomment-3556323130
mkdir -p /etc/systemd/system.conf.d/
cat <<EOF > /etc/systemd/system.conf.d/overlayfs.conf
[Manager]
DefaultEnvironment="LIBMOUNT_FORCE_MOUNT2=always"
EOF

# Tell GRUB to use the serial console
cat - >>/etc/default/grub <<EOF
GRUB_TERMINAL="serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=9600 --stop=1"
GRUB_CMDLINE_LINUX="overlayroot=tmpfs"
EOF

grub-install --target=x86_64-efi
update-grub

# Copy the fallback bootloader to the default bootloader location.
# When we first boot our VM we will need this to initialise the boot options
# in the nvram:
mkdir /boot/efi/EFI/BOOT
cp /boot/efi/EFI/debian/fbx64.efi /boot/efi/EFI/BOOT/bootx64.efi

systemctl enable serial-getty@ttyS0.service
echo root:password | chpasswd
apt-get clean

cat <<EOF > /etc/systemd/system/vm-instance.service
[Unit]
Description=A simple daemon service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/vm-instance --verbose --retry --address "0.0.0.0:6666" vsock 3000
Restart=always
Type=simple

[Install]
WantedBy=multi-user.target
EOF

systemctl enable vm-instance.service

# done modifying the image / filesystems, configure fstab / mount to treat them
# as 'readonly'
cat <<EOF > /etc/fstab
$ROOT_UUID / ext4 defaults,ro 0 1
$EFI_UUID /boot/efi vfat defaults,ro 0 1
EOF

EOS

for BIN in $BINS; do
    sudo cp "$BIN" "$BOOTSTRAP_ROOT"/usr/local/bin
done

MNTS="dev proc sys"
for MNT in $MNTS; do
    sudo umount "$BOOTSTRAP_ROOT"/"$MNT"
done

EFI_ROOT="$BOOTSTRAP_ROOT"/boot/efi

sudo fstrim -v "$EFI_ROOT"
sudo fstrim -v "$BOOTSTRAP_ROOT"

sudo umount "$EFI_ROOT" "$BOOTSTRAP_ROOT"
rmdir "$BOOTSTRAP_ROOT"

sudo qemu-nbd -d "$NBD_DEV"

virt-sparsify --in-place "$QCOW_FILE"
qemu-img convert -f qcow2 -O raw "$QCOW_FILE" "$NAME".raw
gzip --stdout "$NAME".raw > "$NAME".raw.gz
