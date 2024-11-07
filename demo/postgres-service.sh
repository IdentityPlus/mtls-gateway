#!/bin/sh

# disable password login for ssh
sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication no/g' /etc/ssh/sshd_config
service sshd restart

# Add Docker the repository to Apt sources:
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# install the necessary software
apt-get update
apt-get install -y mc ca-certificates docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

mkdir -p /media/data

# run postgres db service inside docker
docker run -d \
    --name postgres-container \
    -e TZ=UTC \
    -p 5432:5432 \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    ubuntu/postgres:14-22.04_beta
