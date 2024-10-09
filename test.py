#!/usr/bin/env python3

import subprocess
from pathlib import Path
from itertools import product

from config import *


def run(command, **kwargs):
    """Helper function to run shell commands"""
    return subprocess.run(command, shell=True, check=True, text=True, **kwargs)


def ssh(
    host, command, background=False, devnull=False, stdout=None, stderr=None, **kwargs
):
    """Helper to run SSH commands on a remote host"""
    cmd = ["ssh", host, command]

    stdout = subprocess.DEVNULL if devnull else stdout
    stderr = subprocess.DEVNULL if devnull else stderr

    if background:
        return subprocess.Popen(cmd, stdout=stdout, stderr=stderr, **kwargs)
    else:
        return subprocess.run(cmd, stdout=stdout, stderr=stderr, **kwargs)


def colored_output(message, color_code):
    print(f"\033[{color_code}m{message}\033[0m")


def blue(message):
    colored_output(message, "34")


def yellow(message):
    colored_output(message, "33")


def green(message):
    colored_output(message, "32")


def red(message):
    colored_output(message, "31")


def error():
    red("[ERROR] Cleaning up ...")
    stop_ss()
    exit(1)


def stop_ss():
    yellow("Kill ./ss.sh on the VMs ...")
    for host in hosts:
        ssh(host, "pkill -f ss.sh")


def start_ss(cong):
    yellow(f"Start ss.sh on the VMs ...")
    for host in hosts:
        ssh(host, f"./ss.sh --daemon /root/ss_{cong}_{host}.log")


def iperf3(cong, server="vm1", reverse=False):
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
            f"--time {60} "
            f"--interval 0.1 "
            f"{'--reverse ' if reverse else ''}"
            f"--json "
            f"--logfile {recv_log_path if reverse else sndr_log_path}"
        )

        ssh(server, cmd_server)
        processes.append(ssh(host, cmd_client, background=True))
        run("sleep 20")

    yellow(" | Waiting for the iperf3 flows to complete ...")
    for proc in processes:
        proc.wait()


def copy_logs(suffix):
    def cat_files(hosts, basename):
        for host in hosts:
            files = ssh(host, f"ls {basename}", capture_output=True).stdout.split()
            for file in map(lambda b: b.decode("utf-8"), files):
                with Path(f"/alpine/data-analysis/logs/{file}").open("w") as f:
                    ssh(host, f"cat {file}", stdout=f)

    yellow(f"Copy *_{suffix}.log* files ...")
    cat_files(hosts, "*.log")
    cat_files(hosts, "*.log.json")


def shq(bandwidth=50, rtt=3, delay=1):
    # Bandwidth is in Mbits. RTT and delay in ms.
    yellow(f"Deleting existing qdiscs and activating ShQ ...")
    for router, i in product(routers, range(3)):
        cmd = f"""
        tc qdisc del dev eth{i} root 2>/dev/null || true;
        tc qdisc add dev eth{i} root handle 1: htb default 10;
        tc class add dev eth{i} parent 1: classid 1:10 htb rate {bandwidth}mbit quantum 600;
        tc qdisc add dev eth{i} parent 1:10 handle 10: netem delay {delay}ms;
        tc qdisc add dev eth{i} parent 10: handle 11: shq limit 1000 interval {rtt} maxp 0.5 alpha 0.95 bandwidth {bandwidth}mbps ecn;
        echo 'yay' > /root/it_works;
        """
        # cmd = f"""
        # tc qdisc del dev eth{i} root 2>/dev/null || true;
        # tc qdisc add dev eth{i} root shq limit 1000 interval {rtt} maxp 0.8 alpha 0.95 bandwidth {bandwidth}mbps ecn;
        # """

        # Prioritize SSH traffic on port 22, bypassing both ShQ and bottleneck
        cmd += f"""
        # Class for SSH traffic, bypassing bottleneck and RED
        tc class add dev eth{i} parent 1: classid 1:22 htb rate 1000mbit ceil 1000mbit quantum 600;
        tc qdisc add dev eth{i} parent 1:22 handle 22: pfifo;

        # Filter to match outgoing SSH traffic (port 22)
        tc filter add dev eth{i} protocol ip prio 1 u32 match ip dport 22 0xffff flowid 1:22;

        # Filter to match incoming SSH traffic (port 22)
        tc filter add dev eth{i} protocol ip prio 1 u32 match ip sport 22 0xffff flowid 1:22;
        """
        ssh(router, cmd)


def qdisc(bandwidth=250, delay=0, red=True, quantum=300, ssh_class=False):
    """
    Configure the qdiscs.
    """
    yellow(f"Deleting existing qdiscs and activating special RED with ECN ...")
    for host, i in [(host, i) for host in hosts for i in range(len(hosts[host].macs))]:
        print(f"Configuring qdisc on {host}, eth{i}")

        # Last handle
        handle = "root"

        # Remove existing qdiscs
        cmd = f"""
        tc qdisc del dev eth{i} {handle} 2>/dev/null || true;
        """

        # Create the main HTB class for the traffic, with bandwidth limit
        cmd += f"""
        tc qdisc add dev eth{i} {handle} handle {(handle := "1:")} htb default 10;
        tc class add dev eth{i} parent {handle} classid {(handle := "1:10")} htb rate {bandwidth}mbit ceil {bandwidth}mbit quantum {quantum};
        """

        if ssh_class:
            # Prioritize SSH traffic on port 22, bypassing other AQMs and limits
            # (Let's not shoot ourselfs in the foot.)
            cmd += f"""
            # Class for SSH traffic, bypassing other AQMs
            tc class add dev eth{i} parent 1: classid 1:22 htb rate 100mbit ceil 100mbit quantum {quantum};
            tc qdisc add dev eth{i} parent 1:22 handle 22: fq;

            # Filter to match outgoing SSH traffic (port 22)
            tc filter add dev eth{i} protocol ip prio 1 u32 match ip dport 22 0xffff flowid 1:22;

            # Filter to match incoming SSH traffic (port 22)
            tc filter add dev eth{i} protocol ip prio 1 u32 match ip sport 22 0xffff flowid 1:22;
            """

        # On end hosts, execute the command without configuring RED or delay
        if host not in routers:
            cmd += f"""
            tc qdisc add dev eth{i} parent {handle} fq maxrate {bandwidth}mbit;
            """
            ssh(host, cmd)
            continue

        if delay:
            cmd += f"""
            tc qdisc add dev eth{i} parent {handle} handle {(handle := "10:")} netem delay {delay}ms;
            """

        # Add RED to routers.
        if red:
            # maxp = 1.0  # mark all packets above `maxth` queue length
            # avpkt = 1500  # 3629   # based on tcpdump analysis
            # burst = 1
            # minth = avpkt * 1
            # maxth = avpkt * 100
            # limit = avpkt * 1000  # hard queue length limit
            maxp = 1.0
            avpkt = 1500
            burst = 1
            k = 1
            minth = avpkt * k
            maxth = avpkt * (k+1)
            limit = avpkt * 16

            cmd += f"""
            tc qdisc add dev eth{i} parent {handle} handle {(handle := "11:")} red limit {limit} min {minth} max {maxth} avpkt {avpkt} bandwidth {bandwidth}mbit ecn probability {maxp} burst {burst};
            """

        # Execute the command on the router
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


def cong(congestion_control, lgc_max_rate=None, lgc_min_rtt=None):
    yellow(f"Activating {congestion_control} congestion control ...")
    for host in hosts:
        cmd = ""

        # Add congestion control (this will be formated appropriatly further down)
        cmd += f"sysctl -w net.ipv4.tcp_congestion_control={congestion_control};"

        # Add extra configuration steps for LGC(C)
        if congestion_control == "lgc":
            # Set max rate
            if lgc_max_rate:
                cmd += f"sysctl -w net.ipv4.lgc.lgc_max_rate={lgc_max_rate};"

            # Configure RTT
            rtt = (
                # int(lgc_min_rtt / 2)
                lgc_min_rtt
                if lgc_min_rtt and host in routers
                else lgc_min_rtt
            )
            if lgc_min_rtt:
                cmd += f"sysctl -w net.ipv4.lgc.lgc_min_rtt={rtt};"

            # Exponential smoothing paramter (default: `round(0.05*2**16)`)
            α = round(0.05 * 2**16)
            cmd += f"echo {α} > /sys/module/tcp_lgc/parameters/lgc_alpha_16;"

            # Threshold: if percentage of CE marked packets are above this, be more
            # aggressive in reducing rate. (default: `round(0.8*2**16)`)
            thresh = round(0.8 * 2**16)
            cmd += f"echo {thresh} > /sys/module/tcp_lgc/parameters/thresh_16;"

        cmd += "sysctl -p;"

        ssh(host, cmd)


def pepdna_enable():
    cmd = """
    if ! lsmod | grep -q '^pepdna'; then
        echo "Setting up PEP-DNA ..."

        # Create or flush the DIVERT chain
        iptables -t mangle -N DIVERT 2>/dev/null || iptables -t mangle -F DIVERT

        # Ensure the PREROUTING rules are in place
        iptables -t mangle -C PREROUTING -p tcp ! --dport 22 -m socket -j DIVERT 2>/dev/null || \
        iptables -t mangle -A PREROUTING -p tcp ! --dport 22 -m socket -j DIVERT

        iptables -t mangle -C DIVERT -j MARK --set-mark 1 2>/dev/null || \
        iptables -t mangle -A DIVERT -j MARK --set-mark 1

        iptables -t mangle -C DIVERT -j ACCEPT 2>/dev/null || \
        iptables -t mangle -A DIVERT -j ACCEPT

        # Add IP rule and route if they don't exist
        ip rule list | grep -q 'fwmark 0x1 lookup 100' || ip rule add fwmark 1 lookup 100
        ip route show table 100 | grep -q 'local 0.0.0.0/0 dev lo' || \
        ip route add local 0.0.0.0/0 dev lo table 100

        # Ensure the TPROXY rule is in place
        iptables -t mangle -C PREROUTING -p tcp ! --dport 22 -j TPROXY --tproxy-mark 1 --on-port 9999 2>/dev/null || \
        iptables -t mangle -A PREROUTING -p tcp ! --dport 22 -j TPROXY --tproxy-mark 1 --on-port 9999

        echo "Set sysctl variables to allow full transparency ..."
        sysctl -w net.ipv4.conf.all.route_localnet=1
        sysctl -w net.ipv4.ip_forward=1
        sysctl -w net.ipv4.ip_nonlocal_bind=1
        sysctl -w net.ipv4.conf.all.forwarding=1
        sysctl -w net.ipv4.conf.all.rp_filter=0

        echo "Loading local PEP-DNA at the router node ..."
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


def execute_test(scenario_name, congestion_control, max_rate=None, min_rtt=None):
    blue(f"[{scenario_name.upper()}]")
    kill_iperf_and_rm_logs()

    if scenario_name.upper() == "LGCC":
        pepdna_enable()

    cong(congestion_control, max_rate, min_rtt)

    if scenario_name.upper() in ["LGCC", "LGC", "DCTCP"]:
        qdisc(red=True)
    else:   # CUBIC, Reno, BBR, ...
        qdisc(red=False)

    start_ss(scenario_name)
    iperf3(scenario_name)
    stop_ss()

    if scenario_name.upper() == "LGCC":
        pepdna_disable()

    copy_logs(scenario_name)


def kill_iperf_and_rm_logs():
    yellow("Kill existing iperf3 instances on VMs and remove old log files ...")
    cmd = """
    pkill iperf3 || true;
    rm -f /root/*.log;
    rm -f /root/*.log.json;
    """
    for host in hosts:
        ssh(host, cmd, check=False)


def main():
    try:
        stop_ss()
        base_configuration()
        execute_test("lgcc", "lgc", 200, 21000)
        execute_test("dctcp", "dctcp")
        execute_test("cubic", "cubic")

        green("Test complete!")
    except subprocess.CalledProcessError as e:
        print(e)
        error()


if __name__ == "__main__":
    main()
