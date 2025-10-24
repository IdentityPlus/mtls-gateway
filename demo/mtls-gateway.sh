#!/bin/sh

# Add Docker the repository to Apt sources:
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# install the necessary software
apt-get update
apt-get install -y mc ca-certificates docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# build the mTLS Gateway Docker image
mkdir -p /etc/mtls-gateway
mkdir -p /opt/identity.plus
cd /opt/identity.plus
curl https://raw.githubusercontent.com/IdentityPlus/mtls-gateway/refs/heads/main/bin/x86_64/ubuntu_24.04/Dockerfile > Dockerfile
docker build -t mtls-gateway .

# run mTLS Gateway service inside docker
# we map the config directory so that we can seamlessly upgrade the system with a docker rebuild/run
# without losing the configurations
docker run -d \
    -v /etc/mtls-gateway:/etc/mtls-gateway \
    --network host \
    --name mtls-gw \
    mtls-gateway
