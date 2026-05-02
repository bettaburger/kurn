package cmd

import (
	"io"
	"fmt"
	"bytes"
	"os"
	"encoding/json"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/tcpassembly"
	//"github.com/google/gopacket/tcpassembly/tcpreader"

	"github.com/spf13/cobra"
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
	

	network string
	src string
	dst string
	protocol string
) 

var readPCAP = &cobra.Command {
	Use: "read", 
	Short: "parse pcap file into readable code ",
	RunE: func(cmd *cobra.Command, args []string) error {
		// simple -r cmd
		file, err := os.Open("./test/data/en0-capture2.pcap")
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
			data, capture, err := r.ReadPacketData()
			if err == io.EOF {
				break
			} else if err != nil {
      fmt.Println("Error reading packet data: ", err)
      continue
    }

		// decoding packet 
		err = parser.DecodeLayers(data, &decodedLayers)

		for _, typ := range decodedLayers {
			switch typ {
        case layers.LayerTypeEthernet:
          fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
					fmt.Println("Decoded payload:", payload.LayerContents())
					encodePayload(payload.LayerContents()) 
					network = "Eth" 

        case layers.LayerTypeIPv4:
          fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
					fmt.Println("Raw payload:", payload.LayerContents())
					encodePayload(payload.LayerContents()) 
					network = "IPv4"
					src = ip4.SrcIP.String()
					dst = ip4.DstIP.String()

        case layers.LayerTypeIPv6:
          fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
					fmt.Println("Raw payload:", payload.LayerContents())
					encodePayload(payload.LayerContents()) 
					network = "IPv6"
					src = ip6.SrcIP.String()
					dst = ip6.DstIP.String()
			
        case layers.LayerTypeTCP:
          protocol = fmt.Sprintf("TCP :%d To :%d ", tcp.SrcPort, tcp.DstPort)
					fmt.Println("Raw payload:", payload.LayerContents())
					encodePayload(payload.LayerContents()) 
		
        case layers.LayerTypeUDP:
          protocol = fmt.Sprintf("UDP :%d To :%d ", udp.SrcPort, udp.DstPort)
					fmt.Println("Raw payload:", payload.LayerContents())
					encodePayload(payload.LayerContents()) 
      }
		}
		// packet 0....packet n
		fmt.Println("packet #: ",packetNum)

		packet := Packet{
			Timestamp: capture.Timestamp.String(),
			Network:   network,
			Direction: fmt.Sprintf("From %s To %s", src, dst),
			Protocol: protocol,
			Info:      "",
		}

		PrintJSON(packet)

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
		return nil
	},
}

func PrintJSON(packet any) { 
	bytes, _ := json.MarshalIndent(packet, " ", "  ")
		fmt.Println(string(bytes)) 
}

func init() {
	rootCmd.AddCommand(readPCAP)
	readPCAP.Flags().StringVarP(&read, "read", "r", "READ", "parse pcap file")	// run via ./kurn read

}