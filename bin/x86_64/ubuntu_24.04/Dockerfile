FROM openresty/openresty:jammy-amd64

RUN apt update
RUN apt install -y cron supervisor

# download additional Lua modules (http in particular)
RUN opm get ledgetech/lua-resty-http

RUN mkdir /etc/mtls-gateway
RUN mkdir /opt/identity.plus
WORKDIR /opt/identity.plus
RUN curl -L https://github.com/IdentityPlus/mtls-gateway/archive/refs/heads/main.zip > mtls-gateway.zip
RUN unzip mtls-gateway.zip
RUN mv mtls-gateway-main mtls-gateway

RUN echo "[supervisord]" > /etc/supervisord.conf && \
    echo "nodaemon=true" >> /etc/supervisord.conf && \
    echo "" >> /etc/supervisord.conf && \
    echo "[program:mtls-gateway]" >> /etc/supervisord.conf && \
    echo "directory=/opt/identity.plus/mtls-gateway" >> /etc/supervisord.conf && \
    echo "stdout_logfile=/dev/stdout" >> /etc/supervisord.conf && \
    echo "stdout_logfile_maxbytes=0" >> /etc/supervisord.conf && \
    echo "stderr_logfile=/dev/stderr" >> /etc/supervisord.conf && \
    echo "stderr_logfile_maxbytes=0" >> /etc/supervisord.conf && \
    echo "command=/opt/identity.plus/mtls-gateway/bin/x86_64/ubuntu_24.04/mtls-gw" >> /etc/supervisord.conf

CMD ["/usr/bin/supervisord"]

