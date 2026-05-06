package layers

import (
	"net"
	"github.com/google/gopacket/layers"
	
)

// json hiding/deleting fields
// https://stackoverflow.com/questions/17306358/removing-fields-from-struct-or-hiding-them-in-json-response

type Header interface {
	LayerType() string 
}

type EthernetHeader struct {
  SrcMAC net.HardwareAddr // decode into hex
  DstMAC net.HardwareAddr // decode into hex
  Type   layers.EthernetType // filter this later 
	Length uint16
}

type IPv4Header struct {
  Version    uint8
  IHL        uint8
  TOS        uint8
  Length     uint16
  Id         uint16
  Flags      layers.IPv4Flag
  FragOffset uint16
  TTL        uint8
  Protocol   layers.IPProtocol
  Checksum   uint16
  SrcIP      net.IP
  DstIP      net.IP
}

type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32 // 
	Length       uint16
	NextHeader   layers.IPProtocol
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
	HopByHop     *layers.IPv6HopByHop
}

type TCPHeader struct {
  SrcPort, DstPort                           layers.TCPPort
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	sPort, dPort                               []byte
	Options                                    []layers.TCPOption
	Padding                                    []byte
	opts                                       [4]layers.TCPOption
}

type UDPHeader struct {
	SrcPort 		layers.UDPPort
	DstPort 		layers.UDPPort
	Length    	uint16
	Checksum  	uint16
}

type TLSHeader struct {
	ChangeCipherSpec []layers.TLSChangeCipherSpecRecord
	Handshake        []layers.TLSHandshakeRecord
	AppData          []layers.TLSAppDataRecord
	Alert            []layers.TLSAlertRecord
}