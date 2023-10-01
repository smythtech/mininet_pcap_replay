#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.clean import cleanup
from time import sleep
import os
import base64
from scapy.all import *
import argparse

conf.verb = 0

def handle_args():
  parser = argparse.ArgumentParser(prog="Mininet PCAP Replay", description="Replay a pcap file with a Mininet network.", epilog="Author: Dylan Smyth (https://github.com/smythtech)")
  parser.add_argument("-r", "--pcap", help="PCAP file to read.", required=True)
  parser.add_argument("-c", "--controller-ip", help="IP address of network controller to use.", required=True)
  parser.add_argument("-p", "--controller-port", help="Port number of network controller to use.", default=6653, type=int, required=False)
  parser.add_argument("-b", "--build-only", help="Drop to Mininet CLI after network is built (No pcap replay).", required=False, action='store_true')

  return parser.parse_args()

def load_pcap_data(pcap):
  host_data = {}
  pkt_data = []
  ip_ignore_list = ["255", "240", "239", "224"] # Quick ignore list for IPs that we don't care about (e.g. multicast addresses)
  host_count = 0
  previous_timestamp = 0
  for pkt in pcap:
    if(pkt.src not in host_data):
      ip = ""
      if(IP in pkt):
          ip = pkt[IP].src
      if(len(ip) > 0 and ip.split(".")[0]  not in ip_ignore_list):
        host_count+=1
        host_name = "h" + str(host_count)
        host_data[pkt.src] = [host_name, ip, host_name + "-eth0"]

    if((pkt.dst not in host_data) and (pkt.dst.lower() != "ff:ff:ff:ff:ff:ff")):
      ip = ""
      if(IP in pkt):
          ip = pkt[IP].dst
      if(len(ip) > 0 and ip.split(".")[0] not in ip_ignore_list):
        host_count+=1
        host_name = "h" + str(host_count)
        host_data[pkt.dst] = [host_name, ip, host_name + "-eth0"]

    delay = pkt.time - previous_timestamp
    pkt_data.append([host_data[pkt.src][0], delay, base64.b64encode(raw(pkt))])
    previous_timestamp = pkt.time

  pkt_data[0][1] = 0 # Set the initial delay to 0

  return host_data, pkt_data

def build_mn(host_data, switch_data, link_data, controller_data, pkt_data):
  net = Mininet()
  switches = []
  hosts = []
  host_adds = []
  host_link_map = {}

  print("\tAdding switches")
  for switch_name in switch_data:
    switches.append(net.addSwitch(switch_name, protocols="OpenFlow13"))

  print("\tAdding controllers")
  for c in controller_data:
    net.addController(c, controller=RemoteController, ip=controller_data[c][0], port=controller_data[c][1])


  # Can probably tidy this loop up a bit
  print("\tAdding hosts")
  for host_mac in host_data:
    h = host_data[host_mac]
    h.append(host_mac)
    host = net.addHost(h[0])
    l = net.addLink(host, switches[0])
    hosts.append(host)
    host_adds.append(h)
    host_link_map[h[0]] = l.intf2.name

  print("\tConfiguring packet output ports...", end="")
  for h in hosts:
    for pd in pkt_data:
      if(pd[0] == h.name):
        pd[0] = h # Set a reference to the host - we will use this later

  print("done")

  print("\tStarting network...", end="")
  net.start()
  print("done")

  # Need to do this after network start
  print("\tConfiguring addresses")
  for i in range(0, len(hosts)):
    hosts[i].setMAC(host_adds[i][3], intf=host_adds[i][2])
    hosts[i].setIP(host_adds[i][1], intf=host_adds[i][2])

  '''
  print("\tTesting connections")
  net.pingAll(timeout=1)
  '''

  print("\tMaking additional configurations")
  for host in hosts:
    # Prevent the network stack retransmitting segments
    host.cmd("echo 0 > /proc/sys/net/ipv4/tcp_retries2")
    # Add iptables rules to drop all incoming traffic to avoid unexpected behaviour.
    # https://superuser.com/questions/427458/deny-all-incoming-connections-with-iptables
    host.cmd("iptables -P INPUT DROP")
    host.cmd("iptables -P FORWARD DROP")
    host.cmd("iptables -P OUTPUT ACCPET")
    host.cmd("iptables -A INPUT -i lo -j ACCEPT")
    host.cmd("iptables -A OUTPUT -o lo -j ACCEPT")
    host.cmd("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

  print("\tFinished net build")

  return net, hosts

def do_pcap_replay(pkt_data):
  for pkt_d in pkt_data:
    sleep(float(pkt_d[1]))
    # Better way to do this? May add slight delay in sending but will do for now.
    pkt_d[0].cmd("python3 -c \"import base64; from scapy.sendrecv import sendp; sendp(base64.b64decode(" +  str(pkt_d[2]) + "), iface='" + pkt_d[0].intfNames()[0] + "')\"")

def main():
  args = handle_args()

  #TODO: Add config file loading here.

  try:
    print("[+] Reading pcap...")
    pcap = rdpcap(args.pcap)
  except:
    print("[!] Error: Could not open/read pcap file " + args.pcap)

  host_data, pkt_data = load_pcap_data(pcap)
  print("[+] Loaded data for " + str(len(host_data)) + " hosts.")

  #TODO: Parse config here
  switch_data = ["s1"]
  link_data = []
  controller_data = {}
  controller_data["c0"] = (args.controller_ip, args.controller_port) # Temp until we swap to using a config file

  print("[+] Building Mininet network...")
  net, hosts = build_mn(host_data, switch_data, link_data, controller_data, pkt_data)

  if(args.build_only):
    print("[+] Dropping to Mininet CLI.")
    CLI(net)
  else:
    print("[+] Replaying pcap")
    do_pcap_replay(pkt_data)
    print("[+] Finished")

  print("[+] Stopping network and cleaning up...", end="")
  net.stop()
  cleanup()
  print("done")

  print("\n[$] Bye")

if __name__ == '__main__':
  main()
