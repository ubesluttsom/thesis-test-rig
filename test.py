#!/usr/bin/env python3

from time import sleep
from pathlib import Path
from itertools import product

from utils import *
from config import configure_topology


def main():
    global hosts, routers, vms
    try:
        # Configure topology and create host symbols
        topology = configure_topology(senders=2)
        hosts, routers, vms = (topology.hosts, topology.routers, topology.vms)

        # Create a common timestamp for all log files of this run
        t = timestamp()

        # Ensure hosts are initialised properly
        base_configuration()

        # Execute actual tests
        execute_test(t, "lgc", max_rate=250)
        execute_test(t, "reno")
        execute_test(t, "lgcc", max_rate=250, min_rtt=2000, static_rtt=1)
        execute_test(t, "dctcp")
        execute_test(t, "bbr")
        execute_test(t, "cubic")

        green("Test complete!")
    except RuntimeError as e:
        print(e)
        error()


def execute_test(
    timestamp, congestion_control, max_rate=None, min_rtt=None, static_rtt=1
):
    blue(f"[{congestion_control.upper()}]")

    # Make sure no tests are currently running, and clean up old log files
    kill_ss()
    kill_ping()
    kill_iperf()
    rm_logs()

    # LGCC needs the PEP active
    if congestion_control == "lgcc":
        pepdna_enable()

    # Set the propper congestion control
    cong(congestion_control, max_rate, min_rtt, static_rtt)

    # Configure queing discipline based on selected congestion control
    if congestion_control in ["lgcc", "lgc", "dctcp"]:
        qdisc(congestion_control, red=True)
    else:  # CUBIC, Reno, BBR, ...
        fq_codel()

    # Start logging of `cwnd`
    start_ss(congestion_control)

    # Start logging of RTT from `ping`
    start_ping(congestion_control)

    # Do actual network performance tests
    iperf3(congestion_control)

    # Stop logging of RTT from `ping`, and stop logging of `cwnd`
    kill_ping()
    kill_ss()
    sleep(1)

    # Disable the PEP
    if congestion_control == "lgcc":
        pepdna_disable()

    # Fetch the logs of the test
    copy_logs(timestamp, congestion_control)


def error():
    red("[ERROR] Cleaning up ...")
    kill_iperf()
    kill_ss()
    kill_ping()
    exit(1)


def start_ss(cong):
    yellow(f"Start ss.sh on the VMs ...")
    for host in hosts:
        ssh(host, f"./ss.sh --daemon /root/ss_{cong}_{host}.log")


def kill_ss():
    yellow("Kill ./ss.sh on the VMs ...")
    for host in hosts:
        ssh(host, "pkill -f ss.sh")


def start_ping(cong, server="vm1"):
    yellow(f"Start ping on the VMs ...")
    for host in vms.keys() - {server}:
        logfile = f"/root/ping_{cong}_{host}.log"
        cmd = f"""
        date -u +%Y-%m-%dT%H:%M:%S.%3N > {logfile}
        nohup ping -i 0.1 -s 4 vm1 >> {logfile} &
        """
        ssh(host, cmd)


def kill_ping():
    yellow("Kill ping on the VMs ...")
    for host in hosts:
        ssh(host, "pkill -f ping")


def iperf3(cong, server="vm1", time=60, interval=20, reverse=False):
    yellow("Running iperf3 tests ...")

    processes = []

    for port, host in enumerate(vms.keys() - {server}, start=5210):
        yellow(f" | Starting flow {host} <-> {server} on port {port} ...")

        recv_log_path = f"/root/iperf3_{cong}_revc_{host}.log.json"
        sndr_log_path = f"/root/iperf3_{cong}_sndr_{host}.log.json"

        cmd_server = (
            f"iperf3 "
            f"--server "
            f"--daemon "
            f"--port {port} "
            f"--interval 0.1 "
            f"--json "
            f"--logfile {sndr_log_path if reverse else recv_log_path}"
        )
        cmd_client = (
            f"iperf3 "
            f"--client {server} "
            f"--port {port} "
            f"--time {time} "
            f"--interval 0.1 "
            f"{'--reverse ' if reverse else ''}"
            f"--json "
            f"--logfile {recv_log_path if reverse else sndr_log_path}"
        )

        ssh(server, cmd_server)
        processes.append(ssh(host, cmd_client, background=True))
        run(f"sleep {interval}")

    yellow(" | Waiting for the iperf3 flows to complete ...")
    for proc in processes:
        proc.wait()


def copy_logs(timestamp, suffix):
    def cat_files(hosts, basename):
        for host in hosts:
            files = ssh(host, f"ls {basename}", capture_output=True).stdout.split()
            for file in map(lambda b: b.decode("utf-8"), files):
                with Path(f"/alpine/data-analysis/logs/{timestamp}_{file}").open(
                    "w"
                ) as f:
                    ssh(host, f"cat {file}", stdout=f)

    yellow(f"Copy *_{suffix}.log* files ...")
    cat_files(hosts, "*.log")
    cat_files(hosts, "*.log.json")


def qdisc(
    congestion_control=None,
    bandwidth=150,
    rtt=0.045,
    red=True,
    quantum=300,
    ssh_class=False,
):
    """
    Configure the qdiscs.
    """

    yellow(f"Deleting existing qdiscs and activating special RED with ECN ...")
    for host, i in [(host, i) for host in hosts for i in range(len(hosts[host].macs))]:
        print(f"Configuring qdisc on {host}, eth{i}")

        # Remove existing qdiscs
        cmd = f"""
        tc qdisc del dev eth{i} root 2>/dev/null || true;
        """

        # Define handles
        htb_handle = "1:"
        default_classid = "1:10"
        red_handle = "11:"
        ssh_classid = "1:22"

        # Add HTB qdisc at root
        cmd += f"""
        tc qdisc add dev eth{i} root handle {htb_handle} htb default 10;
        """

        # Add default HTB class
        cmd += f"""
        tc class add dev eth{i} \
            parent {htb_handle} classid {default_classid} \
            htb rate {bandwidth}mbit ceil {bandwidth}mbit quantum {quantum};
        """

        # On end hosts, execute the command without configuring RED
        if host not in routers:
            ssh(host, cmd)
            continue

        # Configure SSH class if enabled
        if ssh_class:
            cmd += f"""
            # Class for SSH traffic, bypassing other AQMs
            tc class add dev eth{i} \
                parent {htb_handle} classid {ssh_classid} \
                htb rate 100mbit ceil 100mbit quantum {quantum};
            tc qdisc add dev eth{i} \
                parent {ssh_classid} handle 22: \
                fq;

            # Filter to match outgoing SSH traffic (port 22)
            tc filter add dev eth{i} \
                protocol ip prio 1 u32 match ip dport 22 0xffff \
                flowid {ssh_classid};

            # Filter to match incoming SSH traffic (port 22)
            tc filter add dev eth{i} \
                protocol ip prio 1 u32 match ip sport 22 0xffff \
                flowid {ssh_classid};
            """

        # Add RED to routers if enabled
        if red:
            maxp = 1.0  # mark all packets above `maxth` queue length
            avpkt = 1500  # Average packet size
            limit = avpkt * 100

            if congestion_control == "dctcp":
                # Default DCTCP configuration
                burst = 0
                k = max(round((((bandwidth * 1024) / avpkt) * rtt) / 7), 1)
                minth = avpkt * k
                maxth = avpkt * (k + 1)
            else:
                burst = 1
                minth = avpkt * 1
                maxth = avpkt * 30

            cmd += f"""
            tc qdisc add dev eth{i} \
                parent {default_classid} handle {red_handle} \
                red limit {limit} min {minth} max {maxth} avpkt {avpkt} \
                bandwidth {bandwidth}mbit ecn probability {maxp} burst {burst};
            """

        # Execute the command on the router
        ssh(host, cmd)


def fq_codel(bandwidth=300):
    """
    Configure FQ-CoDel with bandwidth limiting and ECN.

    Args:
        bandwidth (int): Link bandwidth in Mbits
        ssh_class (bool): Whether to create special filtering for SSH traffic
    """

    yellow(
        f"Deleting existing qdiscs and setting up FQ-CoDel with {bandwidth}Mbit limit..."
    )
    for host, i in [(host, i) for host in hosts for i in range(len(hosts[host].macs))]:
        print(f"Configuring qdisc on {host}, eth{i}")

        # Remove existing qdiscs
        cmd = f"""
        tc qdisc del dev eth{i} root 2>/dev/null || true;
        """

        # Add HTB root with bandwidth limit
        cmd += f"""
        tc qdisc add dev eth{i} root handle 1: htb default 10;
        tc class add dev eth{i} parent 1: classid 1:10 htb rate {bandwidth}mbit ceil {bandwidth}mbit quantum 300;
        """

        # Add FQ-CoDel with ECN under HTB
        cmd += f"""
        tc qdisc add dev eth{i} parent 1:10 fq_codel ecn;
        """

        # Execute the command on the host
        ssh(host, cmd)


def cleanup_ifb():
    """Remove Intermediate Functional Block devices."""
    for host, i in [(host, i) for host in hosts for i in range(len(hosts[host].macs))]:
        cmd = f"""
        tc qdisc del dev eth{i} ingress 2>/dev/null || true
        ip link set dev ifb{i} down 2>/dev/null || true
        ip link delete ifb{i} 2>/dev/null || true
        """
        ssh(host, cmd)


def base_configuration():
    cmd = f"""
    sysctl -w net.ipv4.tcp_ecn=1;
    sysctl -w net.ipv4.tcp_ecn_fallback=0;
    sysctl -w net.ipv4.tcp_no_metrics_save=1;
    sysctl -w net.ipv4.tcp_low_latency=1;
    # sysctl -w net.ipv4.tcp_tw_reuse=1;
    sysctl -w net.ipv4.tcp_autocorking=0;
    sysctl -w net.ipv4.tcp_fastopen=0;
    sysctl -w net.core.rmem_max={2**21};
    sysctl -w net.core.wmem_max={2**21};
    sysctl -w net.core.rmem_default={2**21};
    sysctl -w net.core.wmem_default={2**21};
    sysctl -w net.ipv4.tcp_rmem="{2**22} {2**22} {2**22}";
    sysctl -w net.ipv4.tcp_wmem="{2**21} {2**21} {2**21}";
    sysctl -w net.core.somaxconn=4096;
    sysctl -w net.core.netdev_max_backlog=1000;
    sysctl -w net.ipv4.tcp_max_syn_backlog=128;
    """

    """
    # Default system values:
    sysctl -w net.core.rmem_max=212992;
    sysctl -w net.core.wmem_max=212992;
    sysctl -w net.core.rmem_default=212992;
    sysctl -w net.core.wmem_default=212992;
    sysctl -w net.ipv4.tcp_rmem="4096	131072	6291456";
    sysctl -w net.ipv4.tcp_wmem="4096	16384	4194304";
    sysctl -w net.ipv4.tcp_mem="11097	14797	22194";
    sysctl -w net.ipv4.tcp_limit_output_bytes="1048576;
    sysctl -w net.core.somaxconn=4096;
    sysctl -w net.core.netdev_max_backlog=1000;
    sysctl -w net.ipv4.tcp_max_syn_backlog=128;
    """
    for host in hosts:
        ssh(host, cmd)


def cong(congestion_control, max_rate=None, min_rtt=None, static_rtt=1):
    yellow(f"Activating {(cc := congestion_control)} congestion control ...")
    for host in hosts:
        cmd = ""

        # Add congestion control
        cmd += f"sysctl -w net.ipv4.tcp_congestion_control={cc};"

        # Add extra configuration steps for LGC(C)
        if cc in ["lgc", "lgcc"]:
            # Set max rate
            if max_rate:
                cmd += f"sysctl -w net.ipv4.{cc}.{cc}_max_rate={max_rate};"

            if cc == "lgcc" and min_rtt:
                # Configure RTT
                cmd += f"sysctl -w net.ipv4.{cc}.{cc}_min_rtt={min_rtt};"
                cmd += f"sysctl -w net.ipv4.{cc}.{cc}_static_rtt={static_rtt};"

            # Exponential smoothing paramter (default: `round(0.05*2**16)`)
            α = round(0.05 * 2**16)
            cmd += f"echo {α} > /sys/module/tcp_{cc}/parameters/{cc}_alpha_16;"

            # Threshold: if percentage of CE marked packets are above this, be more
            # aggressive in reducing rate. (default: `round(0.8*2**16)`)
            thresh = round(0.8 * 2**16)
            cmd += f"echo {thresh} > /sys/module/tcp_{cc}/parameters/thresh_16;"

        cmd += "sysctl -p;"

        ssh(host, cmd)


def pepdna_enable():
    cmd = """
    if ! lsmod | grep -q '^pepdna'; then
        echo "Setting up PEP-DNA ..."

        echo "Create or flush the DIVERT chain"
        iptables -t mangle -N DIVERT 2>/dev/null || iptables -t mangle -F DIVERT

        echo "Configure DIVERT chain"
        iptables -t mangle -A DIVERT -j MARK --set-mark 1
        iptables -t mangle -A DIVERT -j ACCEPT

        echo "Add IP rule and route if they don't exist"
        ip rule list | grep -q 'fwmark 0x1 lookup 100' || ip rule add fwmark 1 lookup 100
        ip route show table 100 2>/dev/null | grep -q 'local 0.0.0.0/0 dev lo' || \
        ip route add local 0.0.0.0/0 dev lo table 100

        echo "Ensure the PREROUTING rules are in place (in correct order)"
        # First remove any existing rules
        iptables -t mangle -F PREROUTING

        # Add rules in correct order
        iptables -t mangle -A PREROUTING -p tcp ! --dport 22 -m socket -j DIVERT
        iptables -t mangle -A PREROUTING -p tcp ! --dport 22 -j TPROXY --tproxy-mark 1 --on-port 9999

        echo "Set sysctl variables to allow full transparency ..."
        sysctl -w net.ipv4.conf.all.route_localnet=1
        sysctl -w net.ipv4.ip_forward=1
        sysctl -w net.ipv4.ip_nonlocal_bind=1
        sysctl -w net.ipv4.conf.all.forwarding=1
        sysctl -w net.ipv4.conf.all.rp_filter=0

        echo "Loading PEP-DNA at the router node ..."
        modprobe pepdna port=9999 mode=0
    else
        echo "PEP-DNA is already enabled."
    fi
    """
    for router in routers:
        ssh(router, cmd)


def pepdna_disable():
    cmd = """
    if lsmod | grep -q '^pepdna'; then
        echo "Disabling PEP-DNA ..."

        # Remove the TPROXY rule if it exists
        iptables -t mangle -D PREROUTING -p tcp ! --dport 22 -j TPROXY --tproxy-mark 1 --on-port 9999 2>/dev/null || true

        # Remove the PREROUTING rule if it exists
        iptables -t mangle -D PREROUTING -p tcp ! --dport 22 -m socket -j DIVERT 2>/dev/null || true

        # Flush and delete the DIVERT chain if it exists
        iptables -t mangle -F DIVERT 2>/dev/null || true
        iptables -t mangle -X DIVERT 2>/dev/null || true

        # Remove the IP rule and route if they exist
        ip rule del fwmark 1 lookup 100 2>/dev/null || true
        ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

        echo "Resetting sysctl variables to default values ..."
        sysctl -w net.ipv4.conf.all.route_localnet=0
        sysctl -w net.ipv4.ip_nonlocal_bind=0
        sysctl -w net.ipv4.conf.all.rp_filter=1

        echo "Unloading PEP-DNA module ..."
        rmmod pepdna
    else
        echo "PEP-DNA is already disabled."
    fi
    """
    for router in routers:
        ssh(router, cmd)


def kill_iperf():
    yellow("Kill existing iperf3 instances ...")
    for host in hosts:
        ssh(host, "pkill iperf3 || true", check=False)


def rm_logs():
    yellow("Remove old log files ...")
    cmd = """
    rm -f /root/*.log;
    rm -f /root/*.log.json;
    """
    for host in hosts:
        ssh(host, cmd, check=False)


if __name__ == "__main__":
    main()
