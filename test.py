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
            f"--time 60 "
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


def red_with_ecn(bandwidth=200, delay=10, last_link_cap=1):
    """
    Configure RED with a special configuration for ECN as described in LGCC paper.

    Parameters:
        bandwidth (int): Bandwidth in Mbits.
        delay (int): Delay in ms.
        last_link_cap (float): Capacity of last link (as percentage of bandwidth).
    """
    maxp = 1.0  # mark all packets above `maxth` queue length
    avpkt = 3000  # 3629   # based on tcpdump analysis
    burst = 1
    minth = avpkt * 1
    maxth = avpkt * 100
    limit = avpkt * 1000  # hard queue length limit
    quantum = 300  # how much bytes to serve from leaf at once

    yellow(f"Deleting existing qdiscs and activating special RED with ECN ...")
    for host, i in product(hosts, range(3)):
        # Remove existing qdiscs
        cmd = f"""
        tc qdisc del dev eth{i} root 2>/dev/null || true;
        tc qdisc add dev eth{i} root handle 1: htb default 10;
        """

        # Configure delay option and bandwidth limit
        if delay > 0:
            cmd += f"""
            # Create the main class for the traffic, with bandwidth limit and delay
            tc class add dev eth{i} parent 1: classid 1:10 htb rate {bandwidth}mbit ceil {bandwidth}mbit quantum {quantum};
            tc qdisc add dev eth{i} parent 1:10 handle 10: netem delay {delay}ms;
            """

            if (i == 0) and (host in routers):
                cmd += f"""
                tc qdisc add dev eth{i} parent 10: handle 11: red limit {limit} min {minth} max {maxth} avpkt {avpkt} bandwidth {bandwidth}mbit ecn probability {maxp} burst {burst};
                """

        else:
            # Create a default class under HTB for RED
            if (i == 0) and (host in routers) and (last_link_cap != 1):
                cmd += f"""
                # Add a default class for traffic, bottlenecked
                tc class add dev eth{i} parent 1: classid 1:10 htb rate {bandwidth*last_link_cap}mbit ceil {bandwidth*last_link_cap}mbit quantum {quantum};
                """
            else:
                cmd += f"""
                # Add a default class for traffic
                tc class add dev eth{i} parent 1: classid 1:10 htb rate {bandwidth}mbit ceil {bandwidth}mbit quantum {quantum};
                """

            if (i == 0) and (host in routers):
                cmd += f"""
                # Apply RED to the default class
                tc qdisc add dev eth{i} parent 1:10 handle 10: red limit {limit} min {minth} max {maxth} avpkt {avpkt} bandwidth {bandwidth}mbit ecn probability {maxp} burst {burst};
                """
        # Prioritize SSH traffic on port 22, bypassing both RED and bottleneck.
        # (Don't shoot ourselfs in the foot.)
        cmd += f"""
        # Class for SSH traffic, bypassing bottleneck and RED
        tc class add dev eth{i} parent 1: classid 1:22 htb rate 100mbit ceil 100mbit quantum {quantum};
        tc qdisc add dev eth{i} parent 1:22 handle 22: pfifo;

        # Filter to match outgoing SSH traffic (port 22)
        tc filter add dev eth{i} protocol ip prio 1 u32 match ip dport 22 0xffff flowid 1:22;

        # Filter to match incoming SSH traffic (port 22)
        tc filter add dev eth{i} protocol ip prio 1 u32 match ip sport 22 0xffff flowid 1:22;
        """

        # Execute the command on the router
        ssh(host, cmd)


def cong(cc, lgc_max_rate=None):
    yellow(f"Activating {cc} congestion control ...")

    cmd = f"""
    sysctl -w net.ipv4.tcp_ecn=1;
    sysctl -w net.ipv4.tcp_ecn_fallback=0;
    sysctl -w net.ipv4.tcp_no_metrics_save=1;
    sysctl -w net.ipv4.tcp_low_latency=1;
    sysctl -w net.ipv4.tcp_tw_reuse=1;
    sysctl -w net.ipv4.tcp_autocorking=0;
    sysctl -w net.ipv4.tcp_fastopen=0;
    sysctl -w net.ipv4.tcp_congestion_control={cc};
    sysctl -w net.ipv4.tcp_pacing_ss_ratio=200;
    sysctl -w net.ipv4.tcp_pacing_ca_ratio=120;
    """

    if cc == "lgc" and lgc_max_rate:
        cmd += f"sysctl -w net.ipv4.lgc.lgc_max_rate={lgc_max_rate};"

    # Exponential smoothing paramter (default: `round(0.05*2**16)`)
    α = round(0.05 * 2**16)
    cmd += f"echo {α} > /sys/module/tcp_lgc/parameters/lgc_alpha_16;"
    # Threshold: if percentage of CE marked packets are above this, be more
    # aggressive in reducing rate. (default: `round(0.8*2**16)`)
    thresh = round(0.8 * 2**16)
    cmd += f"echo {thresh} > /sys/module/tcp_lgc/parameters/thresh_16;"

    cmd += "sysctl -p;"

    for host in hosts:
        ssh(host, cmd)


def execute_test(scenario_name, congestion_control, lgc_max_rate=None):
    blue(f"[{scenario_name.upper()}]")
    kill_iperf_and_rm_logs()
    cong(congestion_control, lgc_max_rate)
    red_with_ecn()
    start_ss(scenario_name)
    iperf3(scenario_name)
    stop_ss()
    copy_logs(scenario_name)


def kill_iperf_and_rm_logs():
    yellow("Kill existing iperf3 instances on VMs and remove old log files ...")
    for host in hosts:
        cmd = """
        pkill iperf3 || true;
        rm -f /root/*.log;
        rm -f /root/*.log.json;
        """
        ssh(host, cmd, check=False)


def main():
    try:
        stop_ss()
        execute_test("lgcc", "lgc", 100)
        # execute_test("cubic", "cubic")

        green("Test complete!")
    except subprocess.CalledProcessError as e:
        print(e)
        error()


if __name__ == "__main__":
    main()
