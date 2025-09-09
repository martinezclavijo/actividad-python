#!/usr/bin/env python3
import argparse
import socket
import struct
import fcntl
import nmap

SAMPLE_PORTS = '21-23'

def get_interface_status(ifname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # En Python 3, ifname debe ser bytes para struct.pack
    ifname_bytes = ifname.encode('utf-8')
    ip_address = socket.inet_ntoa(fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname_bytes[:15])
    )[20:24])

    nm = nmap.PortScanner()
    nm.scan(ip_address, SAMPLE_PORTS)
    return nm[ip_address].state()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python networking utils')
    parser.add_argument('--ifname', action="store", dest="ifname", required=True)
    given_args = parser.parse_args()
    ifname = given_args.ifname
    status = get_interface_status(ifname)
    print("Interface [{}] is: {}".format(ifname, status))
