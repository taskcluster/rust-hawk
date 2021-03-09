#! /bin/bash

set -ex

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    openssh-client \
    libssl-dev \
    pkg-config

curl -sO https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
chmod +x rustup-init
./rustup-init -y --no-modify-path

# install stable
/root/.cargo/bin/rustup install 1.50.0
/root/.cargo/bin/rustup component add clippy
/root/.cargo/bin/rustup component add rustfmt

# install node (the version is not critical)
curl https://nodejs.org/dist/v6.11.1/node-v6.11.1-linux-x64.tar.xz | xz -d | tar -C /usr --strip=1 -xf -

# cleanup
apt-get remove --purge -y curl
apt-get autoremove -y

rm -rf \
    /setup.sh \
    rustup-init \
    /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/* \
    /root/.cargo/registry

mkdir /source
