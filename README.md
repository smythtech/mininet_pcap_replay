# Mininet PCAP Replay

This tool allows a Mininet network to be built from host details contained within a pcap file. Packets contained within the pcap can then be replayed through the Mininet network.

## Why

Simulating realistic traffic in an SDN testbed can be difficult. This tool allows you to take a packet capture from any network and use this as the traffic within your SDN testbed. 

This is perfect for evaluating SDN applications against complex network scenarios involving multiple hosts and protocols.

Example use cases:
- Testing a statistics collection or load balancing application.
- Troubleshooting an error caused by certain network traffic.
- Test an attack detection solution against a pcap containing that attack without needing to carry out the attack yourself.


## Requirements
This tool requires the following:

- Python3
- Scapy3
- Mininet
- Mininet Python API (Installed through pip)

The following commands can be used to install the requirements:

	sudo apt-get install python3 python3-scapy mininet python3-pip
and

	sudo pip install mininet

An SDN controller will be required when using this tool. This was tested with ONOS version 2.7.0.

## Usage

	usage: mininet_pcap_replay.py [-h] -r PCAP -c CONTROLLER_IP [-p CONTROLLER_PORT] [-l LOAD_CONFIG] [-b] [-g] [-v] [--version]

	Replay a pcap file with a Mininet network.

	optional arguments:
	  -h, --help            show this help message and exit
	  -r PCAP, --pcap PCAP  PCAP file to read.
	  -c CONTROLLER_IP, --controller-ip CONTROLLER_IP
	                        IP address of network controller to use.
	  -p CONTROLLER_PORT, --controller-port CONTROLLER_PORT
	                        Port number of network controller to use.
	  -l LOAD_CONFIG, --load-config LOAD_CONFIG
	                        Topology configuration file to load
	  -b, --build-only      Drop to Mininet CLI after network is built (No pcap replay).
	  -g, --generate-conf   Generate a configuration after network build. Will be printed after exiting Mininet CLI if using build-only mode.
	  -v, --verbose         Show additional output.
	  --version             show program's version number and exit

## Topology Configuration
This tool can take a configuration file that defines connections within the generated network. Host-to-switch links and switch-to-switch links can be defined in this file.

The following is an example config:
```json
	{
  		"hosts": {
			"11:22:33:44:55:66": "h1",
			"77:88:99:00:aa:bb": "h2"
	  	},
  	"switches": [
		"s1",
		"s2",
		"s3",
		"s4"
	  ],
	  "links": [
		"h1-s1",
		"s1-s2",
		"s2-s3",
		"s3-s4",
		"h2-s4"
	  ]
	}
```

The above configuration will create a linear topology with a host connected at either end. In this configuration hosts 11:22:33:44:55:66 and 77:88:99:00:aa:bb exist within the pcap file being replayed. This configuration file allows you to place certain hosts at particular locations in the network. By default, all hosts will be added to switch s1 unless otherwise specificied.

Links should be defined with the name of the host node first i.e. host-switch 

## Limitations
This tool will rebuild the network in terms of addressing only. No services are launched on the Mininet hosts. The pcap replay is essentially a simulation of that network traffic. Attempts to actively interact with the traffic will not influence the traffic. For example, dropping TCP segments through a flow rule will not stop the host from sending future segments related to that TCP connection. 

Other limitations:
- Gateway address is not set on hosts. May impact "build only" mode.
- Hosts cannot be interacted with during the pcap replay.

## Todo

Planned tasks:
- ~Add signal handler for proper clean-up if user uses ctrl+c to stop pcap replay.~ Done
- ~Add config file to allow topology, controllers, etc to be specificed.~ Done.
- Add check to ensure gateway host receives correct IP address.
- Option to loop pcap replay until stopped.
- More testing with various pcaps.
- Optimize/clean-up code.

## Author
Dylan Smyth 
