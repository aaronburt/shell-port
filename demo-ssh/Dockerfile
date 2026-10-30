FROM alpine:3.24
RUN apk add --no-cache openssh-server bash \
 && adduser -D -s /bin/bash demo \
 && echo "demo:$(head -c 32 /dev/urandom | base64)" | chpasswd \
 && mkdir -p /home/demo/.ssh /hostkeys \
 && chmod 700 /home/demo/.ssh
ARG AUTHORIZED_KEYS=authorized_keys
COPY ${AUTHORIZED_KEYS} /home/demo/.ssh/authorized_keys
RUN chown -R demo:demo /home/demo/.ssh && chmod 600 /home/demo/.ssh/authorized_keys
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
