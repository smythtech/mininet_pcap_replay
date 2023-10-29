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
import signal
import json
# Stop warnings from scapy.
from warnings import filterwarnings
filterwarnings("ignore")
from scapy.all import *
import argparse

# Prevent verbose output from scapy.
conf.verb = 0

verbose = 0

def handle_args():
  parser = argparse.ArgumentParser(prog="mininet_pcap_replay.py", description="Replay a pcap file with a Mininet network.", epilog="Author: Dylan Smyth (https://github.com/smythtech)")
  parser.add_argument("-r", "--pcap", help="PCAP file to read.", required=True)
  parser.add_argument("-c", "--controller-ip", help="IP address of network controller to use.", required=True)
  parser.add_argument("-p", "--controller-port", help="Port number of network controller to use.", default=6653, type=int, required=False)
  parser.add_argument("-l", "--load-config", help="Topology configuration file to load.", required=False)
  parser.add_argument("-b", "--build-only", help="Drop to Mininet CLI after network is built (No pcap replay).", required=False, action='store_true')
  parser.add_argument("-g", "--generate-conf", help="Generate a configuration after network build. Will be printed after exiting Mininet CLI if using build-only mode.", required=False, action='store_true')
  parser.add_argument("-x", "--xterm", help="Start an xterm instance for all hosts.", required=False, action='store_true')
  parser.add_argument("-v", "--verbose", help="Show additional output.", required=False, action='store_true')
  parser.add_argument('--version', action='version', version='%(prog)s 1.3')

  return parser.parse_args()

def load_pcap_data(pcap, topo_config):
  if(len(topo_config) > 0):
    configured_hosts = topo_config["hosts"]
    host_count = len(configured_hosts)
  else:
    host_count = 0
  host_data = {}
  pkt_data = []
  ip_ignore_list = ["255", "240", "239", "224"] # Quick ignore list for IPs that we don't care about (e.g. multicast addresses)
  previous_timestamp = 0
  for pkt in pcap:
    if((hasattr(pkt, "src") == False) or (hasattr(pkt, "dst") == False)):
      print("[!] Error: The content of this pcap is not supported by this tool.")
      print("[!] The layer 2 source and destination addresses should be available for each packet.")
      exit()
    if(pkt.src not in host_data):
      ip = ""
      if(IP in pkt):
        ip = pkt[IP].src
      if((len(ip) >= 0) and (ip.split(".")[0] not in ip_ignore_list)):
        if((len(topo_config) > 0) and (pkt.src in configured_hosts)):
          host_name = configured_hosts[pkt.src]
        else:
          host_count+=1
          host_name = "h" + str(host_count)
        host_data[pkt.src] = [host_name, ip, host_name + "-eth0"]

    if((pkt.dst not in host_data) and (pkt.dst.lower() != "ff:ff:ff:ff:ff:ff")):
      ip = ""
      if(IP in pkt):
          ip = pkt[IP].dst
      if((len(ip) > 0) and (ip.split(".")[0] not in ip_ignore_list)):
        if((len(topo_config) > 0) and (pkt.dst in configured_hosts)):
          host_name = configured_hosts[pkt.dst]
        else:
          host_count+=1
          host_name = "h" + str(host_count)
        host_data[pkt.dst] = [host_name, ip, host_name + "-eth0"]

    delay = pkt.time - previous_timestamp
    pkt_data.append([host_data[pkt.src][0], delay, base64.b64encode(raw(pkt))])
    previous_timestamp = pkt.time

  pkt_data[0][1] = 0 # Set the initial delay to 0

  return host_data, pkt_data

def build_mn(host_data, switch_data, link_data, controller_data, pkt_data, xterm):
  net = Mininet()
  switches = []
  hosts = []
  host_adds = []
  host_link_map = {}

  print("\tAdding switches (OpenFlow 1.3)")
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
    hosts.append(host)
    host_adds.append(h)

  print("\tAdding links")
  try:
    linked = []
    # Add configured links
    for link in link_data:
      link_ends = link.split("-")
      l = net.addLink(link_ends[0], link_ends[1])
      if((link_ends[0] not in switch_data) and (link_ends[1] not in switch_data)):
        host_link_map[link_ends[0]] = l.intf2.name
      linked.append(link_ends[0])

    # Add non-configured links. All hosts to first switch
    for host in hosts:
      if(host.name not in linked):
        l = net.addLink(host.name, switches[0])
        host_link_map[host.name] = l.intf2.name
        linked.append(host.name)
  except KeyError as e:
    print("[!] Error adding links. Check config.")
    print(e)
    exit(1)

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

  print("\tMaking additional configurations")
  for host in hosts:
    # Prevent the network stack retransmitting segments
    if(xterm):
      host.cmd("xterm -fa 'Monospace' -fs 12 -xrm 'XTerm.vt100.allowTitleOps: false' -T '" + host.name + "' &")
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

def generate_topo_conf(net):
  topo_conf = {"hosts": {}, "switches": [], "links": []}

  for h in net.hosts:
    topo_conf["hosts"][h.MAC(intf=h.intfs[0])] = h.name

  for s in net.switches:
    topo_conf["switches"].append(s.name)

  for l in net.links:
    link = l.intf1.node.name + "-" + l.intf2.node.name
    topo_conf["links"].append(link)

  print(json.dumps(topo_conf, indent=2))

def do_pcap_replay(pkt_data):
  global verbose
  for pkt_d in pkt_data:
    if(pkt_d[1] > 0):
      if(verbose):
        print("[*] Waiting " + str(float(pkt_d[1])) + " seconds before sending next packet")
      sleep(float(pkt_d[1]))
    if(verbose):
      try:
        print("[*] Sending: " + Ether(base64.b64decode(pkt_d[2])).summary())
      except:
        print("[*] Seding unknown packet")
    # Better way to do this? May add slight delay in sending but will do for now.
    pkt_d[0].cmd("python3 -c \"import base64; from scapy.sendrecv import sendp; sendp(base64.b64decode(" +  str(pkt_d[2]) + "), iface='" + pkt_d[0].intfNames()[0] + "')\"")

def set_handler(net):
  def sig_handler(sig, frame):
    print("[+] Got ctrl+c")
    print("[+] Stopping network and cleaning up...", end="")
    net.stop()
    cleanup()
    print("done")
    exit()
  return sig_handler

def main():
  global verbose
  args = handle_args()

  if(args.verbose):
    verbose = 1
    print("[*] Verbose output enabled")

  topo_config = {}
  try:
    if(args.load_config):
      print(f"[+] Loading configuration file {args.load_config}")
      with open(args.load_config) as f:
        topo_config = json.loads(f.read())
      if(verbose):
        print("[*] Configuration file content loaded:")
        print(json.dumps(topo_config, indent=2))
  except Exception as e:
    print(f"[!] Error reading configuration file {args.load_config}")
    print(str(e))
    exit(1)

  try:
    print("[+] Reading pcap...")
    pcap = rdpcap(args.pcap)
  except Exception as e:
    print(f"[!] Error: Could not open/read pcap file {args.pcap}")
    print(str(e))
    exit(1)

  switch_data = ["s1"]
  link_data = []
  if(len(topo_config) > 0):
    print("[+] Topology configuration detected")
    print("[+] Host data will be loaded during pcap parsing")
    print("[+] Loading switch and link data")
    switch_data = topo_config["switches"]
    if(len(switch_data) == 0):
      print("\tNo switches detected in config")
    link_data = topo_config["links"]
    if(len(link_data) == 0):
      print("\tNo links detected in config")
  host_data, pkt_data = load_pcap_data(pcap, topo_config)
  print("[+] Loaded data for " + str(len(host_data)) + " hosts.")
  # Leaving the controller config out of the config file for now.
  controller_data = {}
  controller_data["c0"] = (args.controller_ip, args.controller_port)

  print("[+] Building Mininet network")
  net, hosts = build_mn(host_data, switch_data, link_data, controller_data, pkt_data, args.xterm)

  if(verbose):
    print("[*] Setting signal handler")
  signal.signal(signal.SIGINT, set_handler(net))

  if(args.build_only):
    print("[+] Dropping to Mininet CLI.")
    CLI(net)
    if(args.generate_conf):
      print("[+] Generating content for topo.conf file based on network build")
      generate_topo_conf(net)
  elif((args.build_only == False) and (args.generate_conf)):
    print("[+] Generating content for topo.conf file based on network build")
    generate_topo_conf(net)
  else:
    print("[+] Replaying pcap")
    try:
      do_pcap_replay(pkt_data)
    except AssertionError as e:
      print("[!] Got assertion error while replaying packet.")
      net.stop()
      cleanup()
      exit(1)
    print("[+] Finished")

  print("[+] Stopping network and cleaning up...", end="")
  net.stop()
  cleanup()
  print("done")

  print("\n[$] Bye")

if __name__ == '__main__':
  main()
