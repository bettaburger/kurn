package cmd

import (
	"fmt"
	"bytes"
	"io"
	"os"
	"encoding/json"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
			packetSource := gopacket.NewPacketSource(r, layers.LayerTypeEthernet)
			for packet := range packetSource.Packets() {
				handlePacket(packet) // do something with packet here 
			}
			return nil
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
	//fmt. Printf("%#v\n", packet)
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
	// -\u003e = ->
	direction := n.NetworkFlow()
	source, destination := direction.Endpoints()
	return "From " + source.String() + " To " + destination.String()
}

func PrintJSON(packet interface{}) { 
	bytes, _ := json.MarshalIndent(packet, " ", "  ")
		fmt.Println(string(bytes)) 
}

func init() {
	rootCmd.AddCommand(readPCAP)
	readPCAP.Flags().StringVarP(&read, "read", "r", "READ", "parse pcap file")	// run via ./kurn read

}