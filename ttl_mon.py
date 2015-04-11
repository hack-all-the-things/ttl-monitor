#!/usr/bin/env python

import pcapy
import dpkt
import sys
from optparse import OptionParser
from sys import exit, argv
from socket import inet_ntoa, inet_aton

local_addr = "127.0.0.1"
ttl_dict = {}
iplayout_dict = {}
target = None

class colors:
    WARNING = '\x1b[31m'
    END = '\033[0m'

def DEBUG(msg):
    print "[+] %s" % msg

def WARN(msg):
    print "%s[!] %s%s" % (colors.WARNING, msg, colors.END)

def parse_ttl(hdr, data):
    global local_addr, ttl_dict, iplayout_dict, target
    try:
        eth = dpkt.ethernet.Ethernet(data)
        ip = dpkt.ip.IP(str(eth.data))
        if ip.src == local_addr:
            return
        if target and ip.src != target:
            return
        if ip.src not in ttl_dict:
            ttl_dict[ip.src] = {ip.ttl: ip.data.sport}
            iplayout_dict[ip.src] = {ip.data.sport: ip.ttl}
        if ip.data.sport not in iplayout_dict[ip.src]:
            DEBUG("New port for ip %s: %d (%d)" % (inet_ntoa(ip.src), ip.data.sport, ip.ttl))
            iplayout_dict[ip.src][ip.data.sport] = ip.ttl
        elif iplayout_dict[ip.src][ip.data.sport] != ip.ttl:
            WARN("ROUTE CHANGED/FILTERED: %s:%d had a TTL of %d, but it changed to %d" % (inet_ntoa(ip.src),ip.data.sport, iplayout_dict[ip.src][ip.data.sport], ip.ttl))
        if ip.ttl not in ttl_dict[ip.src]:
            DEBUG("New ttl for ip %s:%d (%d)" % (inet_ntoa(ip.src), ip.data.sport, ip.ttl))
            ttl_dict[ip.src][ip.ttl] = ip.data.sport
            iplayout_dict[ip.src][ip.data.sport] = ip.ttl
    except Exception as e:
        pass

def main():
    global local_addr, target, iplayout_dict
    parser = OptionParser("usage: ttl_mon.py [options]")
    parser.add_option("-i", "--interface", dest="interface", default="eth0",
            help="Interface to listen to")
    parser.add_option("-l", "--local", dest="local", default="127.0.0.1",
            help="Local address to ignore")
    parser.add_option("-t", "--target", dest="target", default=None,
            help="Only record changes for this ip")
    (opts, args) = parser.parse_args()

    interface = opts.interface
    local_addr = inet_aton(opts.local)
    if opts.target:
        target = inet_aton(opts.target)
    pcap = pcapy.open_live(interface, 65536, False, 1)
    DEBUG("Starting TTL monitor...")
    DEBUG("Hack All The Things - http://www.hackallthethings.com/")
    DEBUG("http://github.com/hack-all-the-things/ttl-monitor\n\n")
    DEBUG("Listening on %s" % interface)
    try:
        pcap.loop(-1, parse_ttl)
    except KeyboardInterrupt:
        for ip in iplayout_dict:
            print "Network Layout Report for %s" % inet_ntoa(ip)
            # Hack to find the mode baseline. statistics.mode throws an error if > 1 is found.
            baseline = max(set(([iplayout_dict[ip][x] for x in iplayout_dict[ip]])))
            print "Host has a baseline TTL of %d" % baseline
            for port in iplayout_dict[ip]:
                if iplayout_dict[ip][port] > baseline:
                    print "\tPort %d: TTL %d is closer than host's baseline (filtered?)" % (port, iplayout_dict[ip][port])
                if iplayout_dict[ip][port] < baseline:
                    print "\tPort %d: TTL %d is further than host's baseline (Port forwarded?)" % (port, iplayout_dict[ip][port])
        exit(0)
    except Exception as e:
        raise
        WARN(e)
        exit(1)

if __name__ == "__main__":
    main()
