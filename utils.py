import subprocess
from datetime import datetime

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


def timestamp():
    return datetime.now().replace(second=0, microsecond=0).strftime("%Y%m%d%H%M%S")


def wait_for_condition(command):
    """Wait until a condition is true"""
    while run(command, check=False).returncode != 0:
        subprocess.run("sleep 1", shell=True)


def broadcast(message):
    """Broadcast message to all attached shells"""
    yellow = "\033[33m"
    nc = "\033[0m"
    for tty in subprocess.run(
        "ls /dev/pts/*", shell=True, capture_output=True, text=True
    ).stdout.splitlines():
        run(f'echo -e "\\r{yellow}{message}{nc}" > {tty}', check=False)



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
