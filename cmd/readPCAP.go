package cmd

import (
	"fmt"
	"encoding/json"


	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

//var packetList []Packet
var read string

var readPCAP = &cobra.Command {
	Use: "read", 
	Short: "parse pcap file into readable code ",
	RunE: func(cmd *cobra.Command, args []string) error {
		// simple -r cmd
		pcapFile := "./test/data/en0-capture2.pcap"
		//output := exec.Command("tcpdump", "-r", pcapFile)
		if handle, err := pcap.OpenOffline(pcapFile); err !=nil {
			fmt.Printf("unable to read file path: ")
			return err
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				handlePacket(packet) // do something with packet here 
			}
			return nil
		}
	},
}

// function returns each layer 
func handlePacket(p gopacket.Packet) {
	network := p.NetworkLayer()
	transport := p.TransportLayer()
	application := p.ApplicationLayer()
	if err := p.ErrorLayer(); err != nil { // packet layer error 
		fmt.Println("packet layer error, partially decoded or unable to decode: ", err.Error())
	}

	packet := Packet{
	Timestamp: p.Metadata().CaptureInfo.Timestamp.String(),
	Network:   getLayerType(network),
	Direction: getFlow(network),
	Handshake: getLayerType(transport),
	Info:      getLayerType(application),
	}
	PrintJSON(packet)
}

func getLayerType(l gopacket.Layer) string {
	if l == nil {
		return ""
	}
	return l.LayerType().String()
}

func getFlow(n gopacket.NetworkLayer) string {
	if n == nil {
		return ""
	}
	return n.NetworkFlow().String()
}

func PrintJSON(obj interface{}) { 
	bytes, _ := json.MarshalIndent(obj, " ", "  ")
		fmt.Println(string(bytes)) 
}

func init() {
	rootCmd.AddCommand(readPCAP)
	readPCAP.Flags().StringVarP(&read, "read", "r", "READ", "parse pcap file")	// run via ./kurn read

}