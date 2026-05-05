/*
process each packet byte into layers
eth, ip, tcp, http
*/
package cmd

import (
	"fmt"
	"bytes"
	"os"
	"io"
	"encoding/json"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
)

var (
	read string
	totalPackets uint32
	packetNum uint32 

	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP
	udp layers.UDP
	tls layers.TLS
	payload gopacket.Payload 
	
)

func process(pf string) { // path to .pcap
	packetNum = 1
	file, err := os.Open(pf)
	if err != nil {
		fmt.Println("unable to open file", err) 
	}
	defer file.Close()

	buf, err := io.ReadAll(file)
		if err != nil {
			fmt.Println("cannot read file", err)
		}
		// convert []byte into a reader to supp all pcap file formats
		fileReader := bytes.NewReader(buf) 
		r, err := pcapgo.NewReader(fileReader)
		if err != nil {
			fmt.Println("file format unsupported", err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &tls, &payload)
	//decodedLayers := make([]gopacket.LayerType, 0, 10)
	decodedLayers := []gopacket.LayerType{}

	// parse every packet per layer 
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
      fmt.Println("Error reading packet data: ", err)
      continue
  	}
		fmt.Println("Decoding packet")
		// decoding packet 
		err = parser.DecodeLayers(data, &decodedLayers)
		for _, typ := range decodedLayers {
			switch typ {
        case layers.LayerTypeEthernet:
					PrintJSON(getHeader(&eth))

        case layers.LayerTypeIPv4:
          PrintJSON(getHeader(&ip4))

        case layers.LayerTypeIPv6:
          PrintJSON(getHeader(&ip6))
			
        case layers.LayerTypeTCP:
          PrintJSON(getHeader(&tcp))
		
        case layers.LayerTypeUDP:
          PrintJSON(getHeader(&udp))
      }
		}
		// packet 0....packet n
		fmt.Println("packet #: ",packetNum)

		if parser.Truncated {
      fmt.Println("  Packet has been truncated")
    }
    if err != nil {
      fmt.Println("  Error encountered:", err)
    }
		packetNum++
		totalPackets++
		} // end of parse	
		fmt.Println("total packets sent: ",totalPackets)
}

func PrintJSON(packet any) { 
	bytes, _ := json.MarshalIndent(packet, " ", "  ")
		fmt.Println(string(bytes)) 
}


