/*
group/filter packets by endpoint criteria
*/
package server

import (
	//"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/bettaburger/kurn/osi"
)
//https://pkg.go.dev/honnef.co/go/pcap#Bytes

//returns the header for layer types
func getHeader(l gopacket.Layer) osi.Header {
	switch layer := l.(type) {
	case *layers.Ethernet: 
		h := osi.EthernetHeader {
			Source: osi.MACAddress(layer.SrcMAC),
			Destination: osi.MACAddress(layer.DstMAC),
		}
		// ethernet II  and llc header(802.3)
		if layer.Length > 0 {
			h.Length = layer.Length 
			h.Type = layers.EthernetTypeLLC.String()
		} else {
			h.Type = layer.EthernetType.String()
		}
		return h
		
	case *layers.IPv4:
		return osi.IPv4Header {
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
			Source: layer.SrcIP,
			Destination: layer.DstIP, 
		} 

	case *layers.IPv6:
		return osi.IPv6Header {
			Version: layer.Version, 
			TrafficClass: layer.TrafficClass,
			FlowLabel: layer.FlowLabel,
			Length: layer.Length, 
			NextHeader: layer.NextHeader,
			HopLimit: layer.HopLimit,
			Source: layer.SrcIP,
			Destination: layer.DstIP,
			HopByHop: layer.HopByHop,
		}

	case *layers.TCP:
		return osi.TCPHeader {
			SrcPort: layer.SrcPort,
			DstPort: layer.DstPort,
		}
	
	case *layers.UDP:
		return osi.UDPHeader {
			SrcPort: layer.SrcPort,
			DstPort: layer.DstPort,
			Length: layer.Length,
			Checksum: layer.Checksum,
		}

	case *layers.TLS: 
		return osi.TLSHeader {
			ChangeCipherSpec: []layers.TLSChangeCipherSpecRecord{},
			Handshake:[]layers.TLSHandshakeRecord{},
			AppData: []layers.TLSAppDataRecord{},
			Alert: []layers.TLSAlertRecord{},
		}
	}
	return nil
}





