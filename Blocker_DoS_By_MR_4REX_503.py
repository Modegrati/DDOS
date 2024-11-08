#jalankan dengan mode root 
#tsu python your_script.py
#pip install iproute2
#gunakan python2
from scapy.all import *
from collections import defaultdict, deque
import subprocess
import time
import statistics
import os

THRESHOLD_FACTOR = 3  
TIME_WINDOW = 5  
SLIDING_WINDOW_SIZE = TIME_WINDOW * 10  

packet_counts = defaultdict(lambda: deque(maxlen=SLIDING_WINDOW_SIZE))
last_check_time = time.time()

def check_root():
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run it with 'tsu' in Termux.")
        exit(1)

def detect_and_block_ips(packet):
    global last_check_time
    current_time = time.time()

    if IP in packet:
        ip_src = packet[IP].src
        packet_counts[ip_src].append(current_time)

        if current_time - last_check_time >= 1:  
            for ip, timestamps in list(packet_counts.items()):
                if len(timestamps) >= SLIDING_WINDOW_SIZE:
                    packet_rates = [1 / (timestamps[i] - timestamps[i - 1]) for i in range(1, len(timestamps))]
                    mean_rate = statistics.mean(packet_rates)
                    std_dev = statistics.stdev(packet_rates)
                    threshold = mean_rate + THRESHOLD_FACTOR * std_dev

                    if mean_rate > threshold:
                        print(f"Detected potential DDoS attack from {ip}. Blocking IP...")
                        block_ip(ip)
            last_check_time = current_time

def block_ip(ip):
    try:
        subprocess.run(["ip", "route", "add", "blackhole", ip], check=True)
        print(f"Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip}: {e}")

if __name__ == "__main__":
    check_root()
    sniff(prn=detect_and_block_ips, store=0)
