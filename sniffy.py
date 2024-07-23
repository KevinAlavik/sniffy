import argparse
import sys
import os
import netifaces
from scapy.all import *
from loguru import logger

def setup_logging(log_file=None, debug=False):
    logger.remove()
    
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        " - "
        "<level>{message}</level>"
    )
    
    log_level = "DEBUG" if debug else "INFO"
    
    logger.add(sys.stdout, format=log_format, level=log_level)
    
    if log_file:
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        logger.add(log_file, format=log_format, level=log_level, rotation="1 week", retention="1 month")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced IP packet sniffer with enhanced features.")
    parser.add_argument("target_ip", help="The IP address of the target to sniff.")
    parser.add_argument("--interface", help="Network interface to sniff on.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging for debugging.")
    parser.add_argument("--timeout", type=int, default=60, help="Duration to sniff in seconds. Default is 60 seconds.")
    parser.add_argument("--filter", help="Custom BPF filter for packets. E.g., 'tcp', 'udp', 'port 80'")
    parser.add_argument("--logfile", help="File to write logs to. If not provided, logs will be printed to console.")
    parser.add_argument("--show-dns", action="store_true", help="Show DNS details if present.")
    parser.add_argument("--packet-count", type=int, default=-1, help="Number of packets to capture. Default is unlimited.")
    parser.add_argument("--protocol", choices=['tcp', 'udp', 'icmp', 'arp', 'http', 'https', 'ftp', 'smtp'], help="Filter packets by protocol.")
    parser.add_argument("--full-payload", choices=['yes', 'no', 'true', 'false', 1, 0], default='no', help="If true verbose will output full payload (if there is a available one) as hex.")
    return parser.parse_args()

def protocol_name(proto: int) -> str:
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        0x0806: 'ARP',
        80: 'HTTP',
        443: 'HTTPS',
        21: 'FTP',
        25: 'SMTP'
    }
    return protocol_map.get(proto, f'Unknown ({proto})')

def log_packet_info(logger, packet_type: str, ip_layer: IP, packet_length: int):
    logger.info(
        f"TYPE: {packet_type:6} {ip_layer.src:15} -> {ip_layer.dst:15} "
        f"PROTOCOL: \"{protocol_name(ip_layer.proto):7}\" LENGTH: {packet_length:5} bytes"
    )

def log_detailed_info(logger, packet, args):
    try:
        if args.verbose:
            ip_layer = packet[IP]

            
            protocol_str = protocol_name(ip_layer.proto)
            length = len(packet)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            
            tcp_layer = packet[TCP] if packet.haslayer(TCP) else None
            udp_layer = packet[UDP] if packet.haslayer(UDP) else None
            icmp_layer = packet[ICMP] if packet.haslayer(ICMP) else None
            arp_layer = packet[ARP] if packet.haslayer(ARP) else None
            raw_layer = packet[Raw] if packet.haslayer(Raw) else None

            
            logger.debug(f"  Protocol:               {protocol_str}")
            logger.debug(f"  Length:                 {length} bytes")
            logger.debug(f"  Source IP:              {src_ip}")
            logger.debug(f"  Destination IP:         {dst_ip}")

            if tcp_layer:
                flags = str(tcp_layer.flags)
                logger.debug(f"  Source Port:            {tcp_layer.sport}")
                logger.debug(f"  Destination Port:       {tcp_layer.dport}")
                logger.debug(f"  Flags:                  {flags}")
                logger.debug(f"  Window Size:            {tcp_layer.window}")
                logger.debug(f"  Checksum:               {tcp_layer.chksum}")
                logger.debug(f"  Sequence Number:        {tcp_layer.seq}")
                logger.debug(f"  Acknowledgment Number:  {tcp_layer.ack}")

            if udp_layer:
                logger.debug(f"  Source Port:            {udp_layer.sport}")
                logger.debug(f"  Destination Port:       {udp_layer.dport}")
                logger.debug(f"  Length:                 {udp_layer.len}")
                logger.debug(f"  Checksum:               {udp_layer.chksum}")

            if icmp_layer:
                logger.debug(f"  Type:                   {icmp_layer.type}")
                logger.debug(f"  Code:                   {icmp_layer.code}")
                logger.debug(f"  Checksum:               {icmp_layer.chksum}")

            if arp_layer:
                logger.debug(f"  Hardware Type:          {arp_layer.hwtype}")
                logger.debug(f"  Protocol Type:          {arp_layer.ptype}")
                logger.debug(f"  Hardware Size:          {arp_layer.hwlen}")
                logger.debug(f"  Protocol Size:          {arp_layer.plen}")
                logger.debug(f"  Opcode:                 {arp_layer.opcode}")
                logger.debug(f"  Source MAC:             {arp_layer.hwsrc}")
                logger.debug(f"  Source IP:              {arp_layer.psrc}")
                logger.debug(f"  Destination MAC:        {arp_layer.hwdst}")
                logger.debug(f"  Destination IP:         {arp_layer.pdst}")

            if raw_layer:
                payload = raw_layer.load
                logger.debug(f"  Payload Length:         {len(payload)} bytes")
                logger.debug(f"  Payload Sample:         {payload[:20].hex()}...")
                if args.full_payload in ['yes', 'true', 1]:
                    logger.debug(f"  Payload Full:           {payload.hex()}")
                else:
                    logger.debug(f"  Payload Full:           <disabled>")
    except Exception as e:
        logger.error(f"Error in log_detailed_info: {e}")

def log_dns_details(logger, packet):
    try:
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:
                query_type = "Query"
            else:
                query_type = "Response"

            logger.debug(f"  DNS {query_type}:")
            if dns_layer.qr == 0:
                for i in range(dns_layer.qdcount):
                    query = dns_layer.qd[i]
                    logger.debug(f"    Name: {query.qname.decode(errors='ignore')}")
                    logger.debug(f"    Type: {query.qtype}")
                    logger.debug(f"    Class: {query.qclass}")
            else:
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]
                    logger.debug(f"    Name: {answer.rrname.decode(errors='ignore')}")
                    logger.debug(f"    Type: {answer.type}")
                    logger.debug(f"    Class: {answer.rclass}")
                    logger.debug(f"    TTL: {answer.ttl}")
                    if answer.type == 1:
                        logger.debug(f"    Address: {answer.rdata}")
                    elif answer.type == 5:
                        logger.debug(f"    CNAME: {answer.rdata.decode(errors='ignore')}")
                    elif answer.type == 2:
                        logger.debug(f"    NS: {answer.rdata.decode(errors='ignore')}")
                    elif answer.type == 12:
                        logger.debug(f"    PTR: {answer.rdata.decode(errors='ignore')}")
                    elif answer.type == 15:
                        logger.debug(f"    MX: {answer.rdata.decode(errors='ignore')}")
    except Exception as e:
        logger.error(f"Error in log_dns_details: {e}")

def process_packet(packet, target_ip: str, local_ip: str, logger, show_dns: bool, args):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            if ip_layer.src == target_ip or ip_layer.dst == target_ip:
                if ip_layer.src != local_ip and ip_layer.dst != local_ip:
                    packet_type = "SENT" if ip_layer.src == target_ip else "RECEIVED"
                    log_packet_info(logger, packet_type, ip_layer, len(packet))

                    if args.verbose:
                        log_detailed_info(logger, packet, args)

                    if show_dns:
                        log_dns_details(logger, packet)
        elif ARP in packet:
            arp_layer = packet[ARP]
            if arp_layer.psrc == target_ip or arp_layer.pdst == target_ip:
                packet_type = "SENT" if arp_layer.psrc == target_ip else "RECEIVED"
                logger.info(
                    f"TYPE: {packet_type:6} ARP: {arp_layer.psrc:15} -> {arp_layer.pdst:15} "
                    f"HW: {arp_layer.hwsrc} -> {arp_layer.hwdst}"
                )
                if args.verbose:
                    log_detailed_info(logger, packet, args)
    except Exception as e:
        logger.error(f"Error in process_packet: {e}")

def main():
    args = parse_arguments()
    setup_logging(log_file=args.logfile, debug=args.verbose)
    
    logger.info("Sniffy: A simple IP sniffer. Made by Kevin Alavik")

    local_ip = None
    try:
        if args.interface:
            addrs = netifaces.ifaddresses(args.interface)
            if netifaces.AF_INET not in addrs:
                logger.error(f"Error: {args.interface} does not have an IPv4 address.")
                sys.exit(1)
            local_ip = addrs[netifaces.AF_INET][0]["addr"]
            if local_ip != args.target_ip:
                logger.info(f"Using interface {args.interface} with IP address {local_ip}")
        else:
            logger.info("No specific network interface provided; using default.")
            local_ip = netifaces.ifaddresses(netifaces.interfaces()[0])[netifaces.AF_INET][0]["addr"]
    except Exception as e:
        logger.error(f"Error retrieving local IP address: {e}")
        sys.exit(1)

    sniff_filter = args.filter or ""
    if args.protocol:
        sniff_filter += f" and {args.protocol}"

    try:
        sniff(
            iface=args.interface,
            filter=sniff_filter,
            prn=lambda pkt: process_packet(pkt, args.target_ip, local_ip, logger, args.show_dns, args),
            timeout=args.timeout,
            count=args.packet_count
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.error(f"Exception details: {sys.exc_info()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
