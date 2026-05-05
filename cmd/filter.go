/*
group/filter packets by endpoint criteria
*/
package cmd

import (
	//"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)
//https://pkg.go.dev/honnef.co/go/pcap#Bytes

//returns the header for layer types
func getHeader(l gopacket.Layer) any {
	switch layer := l.(type) {
	case *layers.Ethernet: 
		h := EthernetHeader {
			SrcMAC: layer.SrcMAC, 
			DstMAC: layer.DstMAC,
		}
		// ethernet II  and llc header(802.3)
		if layer.Length > 0 {
			h.Length = layer.Length 
			h.Type = layers.EthernetTypeLLC
		} else {
			h.Type = layer.EthernetType
		}
		return h
		
	case *layers.IPv4:
		return IPv4Header {
			Version: layer.Version, 
			IHL: layer.IHL, 
			TOS: layer.TOS,
			Length:layer.Length, 
			Id: layer.Id, 
			Flags: layer.Flags,
			FragOffset: layer.FragOffset,
			TTL: layer.TTL, 
			Protocol: layer.Protocol, 
			Checksum: layer.Checksum,
			SrcIP: layer.SrcIP,
			DstIP: layer.DstIP, 
		} 

	case *layers.IPv6:
		return IPv6Header {
			Version: layer.Version, 
			TrafficClass: layer.TrafficClass,
			FlowLabel: layer.FlowLabel,
			Length: layer.Length, 
			NextHeader: layer.NextHeader,
			HopLimit: layer.HopLimit,
			SrcIP: layer.SrcIP,
			DstIP: layer.DstIP,
			HopByHop: layer.HopByHop,
		}

	case *layers.TCP:
		return TCPHeader {
			SrcPort: layer.SrcPort,
			DstPort: layer.DstPort,
		}
	
	case *layers.UDP:
		return UDPHeader {
			SrcPort: layer.SrcPort,
			DstPort: layer.DstPort,
			Length: layer.Length,
			Checksum: layer.Checksum,
		}

	case *layers.TLS: 
		return TLSHeader {
			ChangeCipherSpec: []layers.TLSChangeCipherSpecRecord{},
			Handshake:[]layers.TLSHandshakeRecord{},
			AppData: []layers.TLSAppDataRecord{},
			Alert: []layers.TLSAlertRecord{},
		}
	}
	return "no layer"
}





