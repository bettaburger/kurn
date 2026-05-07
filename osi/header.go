package osi

import (
	"net"
	"github.com/google/gopacket/layers"
	"encoding/json"
	
)

type Header interface { LayerType() string }

type MACAddress net.HardwareAddr

func (m MACAddress) MarshalJSON() ([]byte, error) {
  return json.Marshal(net.HardwareAddr(m).String())
}

type EthernetHeader struct {
  Source MACAddress `json:"Source"`
  Destination MACAddress `json:"Destination"`
  Type   string `json:"Type"`
	Length uint16 `json:"Length"`
}

type IPv4Header struct {
  Version    uint8 `json:"Version"`
  IHL        uint8 `json:"Internet Header Length"`
  TOS        uint8 `json:"Type of Service"`
  Length     uint16 `json:"Length"`
  Id         uint16 `json:"Identification"`
  Flags      layers.IPv4Flag `json:"Flags"`
  FragOffset uint16 `json:"Fragment offset"`
  TTL        uint8 `json:"Time to Live"`
  Protocol   layers.IPProtocol `json:"Protocol"`
  Checksum   uint16 `json:"Header checksum"`
  Source      net.IP `json:"Source"`
  Destination net.IP `json:"Destination"`
}

type IPv6Header struct {
	Version      uint8 `json:"Version"`
	TrafficClass uint8 `json:"Traffic class"`
	FlowLabel    uint32 `json:"Flowlabel"`// 
	Length       uint16 `json:"Length"`
	NextHeader   layers.IPProtocol `json:"Next header"`
	HopLimit     uint8 `json:"Hop limit"`
	Source        net.IP `json:"Source"`
	Destination   net.IP `json:"Destination"`
	HopByHop     *layers.IPv6HopByHop `json:"Hop by hop"`
}

type TCPHeader struct {
  SrcPort                          layers.TCPPort `json:"Source port"`
	DstPort  													layers.TCPPort `json:"Destination port"`
	Seq                                        uint32 `json:"Seq"`
	Ack                                        uint32 `json:"ACK"`
	DataOffset                                 uint8 `json:"Data offset"`
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool `json:""`
	Window                                     uint16 `json:"Window"`
	Checksum                                   uint16 `json:"Checksum"`
	Urgent                                     uint16 `json:"Urgent"`
	sPort, dPort                               []byte `json:""`
	Options                                    []layers.TCPOption `json:""`
	Padding                                    []byte `json:""`
	opts                                       [4]layers.TCPOption `json:""`
}

type UDPHeader struct {
	SrcPort 		layers.UDPPort `json:"Source port"`
	DstPort 		layers.UDPPort `json:"Destination port"`
	Length    	uint16 `json:"Length"`
	Checksum  	uint16 `json:"Checksum"`
}

type TLSHeader struct {
	ChangeCipherSpec []layers.TLSChangeCipherSpecRecord `json:""`
	Handshake        []layers.TLSHandshakeRecord `json:""`
	AppData          []layers.TLSAppDataRecord `json:""`
	Alert            []layers.TLSAlertRecord `json:""`
}

func (h EthernetHeader) LayerType() string { return "Ethernet" }

func (h IPv4Header) LayerType() string { return "IPv4" }

func (h IPv6Header) LayerType() string { return "IPv6" }

func (h TCPHeader) LayerType() string { return "TCP" }

func (h UDPHeader) LayerType() string { return "UDP" }

func (h TLSHeader) LayerType() string { return "TLS" }
