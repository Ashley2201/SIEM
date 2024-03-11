import logging
from scapy.all import sniff
import psutil

logging.basicConfig(filename='system_network.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def packet_handler(packet):

    logging.info(f"Packet received: {packet.summary()}")
    if ICMP in packet:
        icmp_packet = packet[ICMP]
        if len(icmp_packet) > 65535:
            logging.warning("Ping of Death detected!")
        if packet[ICMP].type == 8:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"Ping detected from: {src_ip} to {dst_ip}")


def log_system_resources():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    disk_percent = psutil.disk_usage('/').percent

    if(cpu_percent >= 90):
        logging.warning(f"High CPU Usage: {cpu_percent}%")
    else:
        logging.info(f"CPU Usage: {cpu_percent}%")
    if(memory_percent > 80):
        logging.warning(f"High Memory Usage: {memory_percent}%")
    else:
        logging.info(f"Memory Usage: {memory_percent}%")
    if(disk_percent < 10):
        logging.warning(f"Low Disk Space: {100 - disk_percent}%")
    else:
        logging.info(f"Disk Usage: {disk_percent}%")

sniff(prn=packet_handler, store=False)


while True:
    log_system_resources()
