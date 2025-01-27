#!/bin/env python3

# https://readthedocs.org/projects/scapy/downloads/pdf/latest/

from scapy.all import *
import argparse

help_message = "Syntax: sniffer.py -i <interface> -o <file.cap>"

# Set up argument parser
parser = argparse.ArgumentParser(prog="Packet Sniffer", description="Sniffing packets from a specified network interface")
parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to capture packets from")
parser.add_argument("-o", "--output", type=str, help="Output file to save captured packets (optional)")
args = parser.parse_args()

def start_sniffing(interface):
    """Start sniffing packets on a specific interface."""
    print(f"Started sniffing on interface: {interface}")
    capture = sniff(iface=interface, timeout=10)  # Sniff for 10 seconds (adjust as needed)
    return capture

def save_the_packets(capture, output_file):
    """Save captured packets to a file."""
    if output_file:
        wrpcap(output_file, capture)
        print(f"Captured packets saved to {output_file}")

def display_the_packets(capture):
    """Display captured packets."""
    if capture:
        capture.show()
    else:
        print("No packets were captured.")

# Main execution flow
def main():
    # Sniff packets on the specified interface
    capture = start_sniffing(args.interface)
    
    # Show summary of captured packets
    capture.summary()
    
    # Save or display the packets depending on whether the --output argument is given
    if args.output:
        save_the_packets(capture, args.output)
    else:
        display_the_packets(capture)

if __name__ == "__main__":
    main()
