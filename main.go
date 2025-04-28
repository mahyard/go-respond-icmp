// icmp_nfqueue.go
//
// This program listens to NFQUEUE number 0 for ICMP echo requests,
// crafts ICMP echo replies, sends them using a raw socket, and drops
// the original packet in the NFQUEUE. It is intended to be run on every node
// in a Kubernetes cluster (for example via a DaemonSet) to respond to ping
// requests for VIP addresses (e.g., MetalLB VIP) without affecting TCP traffic.
//
// Build with: go build -o icmp-responder icmp_nfqueue.go
// Containerize and run with proper capabilities:
//   - CAP_NET_ADMIN and CAP_NET_RAW are required.
//   - hostNetwork must be enabled.

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	nfqueue "github.com/AkihiroSuda/go-netfilter-queue"
)

// ICMP types
const (
	ICMPEchoRequest = 8
	ICMPEchoReply   = 0
)

func main() {
	// Create a new Netfilter Queue bound to queue number 0
	nfq, err := nfqueue.NewNFQueue(0, 100, nfqueue.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("Failed to open NFQUEUE: %v", err)
	}
	defer nfq.Close()

	log.Println("Listening for ICMP Echo Requests on NFQUEUE 0...")

	// Set up handling for OS signals (Ctrl+C, etc.)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Register callback for each packet
	packets := nfq.GetPackets()

	go func() {
		for p := range packets {
			handlePacket(p)
		}
	}()

	// Wait for signal to exit
	<-sigs
	log.Println("Shutting down ICMP Responder...")
}

func handlePacket(p nfqueue.NFPacket) {
	payload := p.Packet.Data()
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

	if ipLayer == nil || icmpLayer == nil {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	ip := ipLayer.(*layers.IPv4)
	icmp := icmpLayer.(*layers.ICMPv4)

	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	log.Printf("Received ICMP Echo Request from %s", ip.SrcIP)

	// Create ICMP Echo Reply
	newICMP := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       icmp.Id,
		Seq:      icmp.Seq,
	}

	// Send ICMP reply back
	sendICMPReply(ip.SrcIP, newICMP, icmp.Payload)

	// Drop the original request
	p.SetVerdict(nfqueue.NF_DROP)
}

func printPacket(payload []byte) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
	fmt.Println(packet.Dump())
}

func sendICMPReply(dstIP net.IP, icmp *layers.ICMPv4, payload []byte) {
	conn, err := net.Dial("ip4:icmp", dstIP.String())
	if err != nil {
		log.Printf("Failed to dial raw ICMP: %v", err)
		return
	}
	defer conn.Close()

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(buffer, opts,
		icmp,
		gopacket.Payload(payload),
	)
	if err != nil {
		log.Printf("Failed to serialize ICMP: %v", err)
		return
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Printf("Failed to send ICMP reply: %v", err)
	}
}
