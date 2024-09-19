FROM alpine:latest

RUN apk update && apk add --no-cache \
    qemu-system-aarch64 \
    libvirt \
    libvirt-daemon \
    libvirt-qemu \
    dnsmasq \
    bridge-utils \
    ebtables \
    iptables \
    iproute2 \
    bash \
    sudo \
    openssh-client \
    curl \
    dbus \
    openrc \
    py3-jinja2 \
    py3-pandas \
    py3-numpy \
    py3-matplotlib

COPY *.j2 /
COPY *.py /

RUN python ./generate_config.py

# RUN ln -sf /alpine/libvirt-experiment/test.py test.py
# RUN chmod +x /alpine/libvirt-experiment/test.py

CMD ["sh", "-c", "python /entrypoint.py && tail -f /dev/null"]
