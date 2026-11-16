import sys
import subprocess

def block_device(ip):
    try:
        # This command adds a rule to the Linux Firewall (iptables)
        # to DROP (ignore) all packets coming from this specific IP
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"DEVICE BLOCKED: {ip}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        block_device(target_ip)