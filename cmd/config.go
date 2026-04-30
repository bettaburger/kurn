package cmd 

import (
	"net"
)

type Packet struct {
	Timestamp  string
	Network    string 
	Direction  string 
	Protocol  string 
	Info 			 string
}

type InterfaceAddress struct {
	IP 				net.IP
	Netmask 	net.IPMask
	Broadaddr net.IP
	P2P 			net.IP 
}

