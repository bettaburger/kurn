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
	"github.com/spf13/cobra"
)

//var packetList []Packet
var read string

var readPCAP = &cobra.Command {
	Use: "read", 
	Short: "parse pcap file into readable code ",
	RunE: func(cmd *cobra.Command, args []string) error {
		// simple -r cmd
		file, err := os.Open("./test/data/en0-capture2.pcap")
		if err != nil {
			fmt.Println("unable to open file", err)
		}

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

		var (
			eth layers.Ethernet
			ip4 layers.IPv4
			ip6 layers.IPv6
			tcp layers.TCP
			udp layers.UDP
			payload gopacket.Payload //at transport layer
		)

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)
		decodedLayers := make([]gopacket.LayerType, 0, 10)

		for {
			data, capture, err := r.ReadPacketData()
			if err == io.EOF {
				break
			} else if err != nil {
      	fmt.Println("Error reading packet data: ", err)
      continue
    }

		var (
			network string
			src string
			dst string
			protocol string
		) 

		// decoding packet 
		//decodedLayers = decodedLayers[:0]
		err = parser.DecodeLayers(data, &decodedLayers) 
		for _, typ := range decodedLayers {
			switch typ {
        case layers.LayerTypeEthernet:
          fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
					network = "Eth" 
        case layers.LayerTypeIPv4:
          fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
					network = "IPv4"
					src = ip4.SrcIP.String()
					dst = ip4.DstIP.String()
        case layers.LayerTypeIPv6:
          fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
					network = "IPv6"
					src = ip6.SrcIP.String()
					dst = ip6.DstIP.String()
        case layers.LayerTypeTCP:
          protocol = fmt.Sprintf("TCP :%d To :%d ", tcp.SrcPort, tcp.DstPort)
        case layers.LayerTypeUDP:
          protocol = fmt.Sprintf("UDP :%d To :%d ", udp.SrcPort, udp.DstPort)
      }
		}

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
		}
		return nil
	},
}

func PrintJSON(packet interface{}) { 
	bytes, _ := json.MarshalIndent(packet, " ", "  ")
		fmt.Println(string(bytes)) 
}

func init() {
	rootCmd.AddCommand(readPCAP)
	readPCAP.Flags().StringVarP(&read, "read", "r", "READ", "parse pcap file")	// run via ./kurn read

}