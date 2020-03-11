package main

import (
	"fmt"
	//"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	dev := "en0"

	// TODO use net.InterfaceByIndex
	fmt.Printf("gopacket does not include lookupdev. so use %s\n", dev)

	if handle, err := pcap.OpenLive("en0", 1024, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 8000"); err != nil {  // optional
		panic(err)
	} else {
		defer handle.Close()
		// gopacket uses pcap_next_ex instead of pcap_next
		// pcap_next_ex is pcap_next with error handling

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		if packet, err := packetSource.NextPacket(); err != nil {
			panic(err)
		} else {

			//fmt.Printf("Packet TransportLayer.LayerType = %s\n", packet.TransportLayer().LayerType())
			fmt.Printf("Packet.Metadata().CaptureLength = %d\n", packet.Metadata().CaptureLength)
			fmt.Printf("Packet = %s\n", packet)
			//fmt.Printf("Packet LayerType = %s\n", packet.ApplicationLayer().LayerType())
		}


	}

}