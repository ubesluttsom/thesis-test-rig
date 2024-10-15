from config import configure_topology, networks, devices
from utils import *


def main():
    configure_topology(senders=3)
    broadcast("Starting openrc system and daemons ...")
    run("openrc sysinit")
    run("rc-service dbus start")
    run("rc-service virtlogd start")
    run("rc-service virtlockd start")
    run("rc-service libvirtd start")

    broadcast("Ensure daemon is fully up and running ...")
    wait_for_condition("virsh list >/dev/null 2>&1")

    broadcast("Defining and starting networks ...")
    for network in networks.keys():
        broadcast(f" | {network} ...")
        run(f"virsh net-define /{network}.xml")
        run(f"virsh net-start {network}")

    broadcast("Ensure networks are fully up ...")
    for network in networks.keys():
        broadcast(f" | {network} ...")
        wait_for_condition(f"virsh net-info {network} | grep -qE 'Active:\\s+yes'")

    broadcast("Removing previous instances ...")
    run("rm -f /alpine/alpine-rootfs/rootfs.img.TRANSIENT-*")

    broadcast("Defining and starting VMs ...")
    for device in devices.keys():
        broadcast(f" | {device} ...")
        run(f"virsh define /{device}.xml")
        run(f"virsh start {device}")

    broadcast("Adding hostnames of VMs to hostfile ...")
    with open("/etc/hosts", "a") as hosts_file:
        for device, data in devices.items():
            broadcast(f" | {device} ...")
            for _, ip in data["ips"].items():
                hosts_file.write(f"{ip} {device}\n")

    broadcast("Overriding default SSH config ...")
    with open("/etc/ssh/ssh_config.d/override.conf", "w") as ssh_config_file:
        ssh_config_file.write(
            """# /etc/ssh/ssh_config.d/override.conf
Host *
    LogLevel ERROR
    UserKnownHostsFile /dev/null
    IdentityFile /alpine/alpine-rootfs/vm_key
    StrictHostKeyChecking no
    User root
"""
        )

    broadcast("Waiting for all devices to be up and SSH-able ...")
    for device in devices.keys():
        broadcast(f" | {device} ...")
        wait_for_condition(f"nc -z {device} 22")

    broadcast("Setting up routing tables for routers ...")
    for device, data in devices.items():
        if "routes" in data:
            broadcast(f" | {device} ...")
            run(f"ssh {device} sysctl -w net.ipv4.ip_forward=1")
            # for subnet, next_hop in data["routes"].items():
            #     run(f"ssh {device} ip route add {subnet} via {next_hop}")

    broadcast("Add default gateways for end nodes ...")
    for device, data in devices.items():
        if "default_gateway" in data:
            broadcast(f" | {device} ...")
            run(
                f"ssh {device} ip route add default via {data['default_gateway']}"
            )

    broadcast("Activate PEP-DNA in test rig ...")
    for device in devices.keys():
        # run(f"ssh {device} /root/cong.sh lgc 100")
        if device.startswith("router"):
            broadcast(f" | {device} ...")
            run(f"ssh {device} /root/pepdna.sh")

    broadcast("\033[32mVM initialization finished!\033[0m")


if __name__ == "__main__":
    main()
