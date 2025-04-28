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
	"encoding/binary"
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

// handlePacket processes each packet from the NFQUEUE
func handlePacketBK(p nfqueue.NFPacket) {
	payload := p.Packet.Data()

	// Parse the IPv4 header
	ipHeaderLen := int((payload[0] & 0x0F) * 4)
	protocol := payload[9]

	// Check if it's ICMP (protocol number 1)
	if protocol != 1 {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	// ICMP packet starts after the IP header
	icmpPayload := payload[ipHeaderLen:]

	// Check if it's an ICMP Echo Request
	icmpType := icmpPayload[0]
	if icmpType != ICMPEchoRequest {
		p.SetVerdict(nfqueue.NF_ACCEPT)
		return
	}

	log.Printf("Received ICMP Echo Request from %s", extractSrcIP(payload))

	// --- Dump original packet ---
	fmt.Println("====== ORIGINAL PACKET ======")
	printPacket(payload)

	// --- Fix: Swap Source/Destination IPs properly ---
	srcIP := make([]byte, 4)
	dstIP := make([]byte, 4)
	copy(srcIP, payload[12:16])
	copy(dstIP, payload[16:20])
	copy(payload[12:16], dstIP)
	copy(payload[16:20], srcIP)

	// --- Fix: Recalculate IP Header Checksum ---
	payload[10] = 0
	payload[11] = 0
	ipChecksum := calculateIPChecksum(payload[:ipHeaderLen])
	payload[10] = byte(ipChecksum >> 8)
	payload[11] = byte(ipChecksum & 0xFF)

	// --- Modify ICMP to EchoReply ---
	icmpPayload[0] = ICMPEchoReply
	icmpPayload[2] = 0
	icmpPayload[3] = 0
	icmpChecksum := calculateChecksum(icmpPayload)
	icmpPayload[2] = byte(icmpChecksum >> 8)
	icmpPayload[3] = byte(icmpChecksum & 0xFF)

	// --- Dump modified packet ---
	fmt.Println("====== MODIFIED PACKET ======")
	printPacket(payload)

	// --- Accept and inject modified packet ---
	p.SetVerdictWithPacket(nfqueue.NF_ACCEPT, payload)
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
		Payload:  icmp.Payload,
	}

	// Send ICMP reply back
	sendICMPReply(ip.SrcIP, newICMP)

	// Drop the original request
	p.SetVerdict(nfqueue.NF_DROP)
}

// extractSrcIP extracts the source IP address from IPv4 header
func extractSrcIP(payload []byte) net.IP {
	return net.IPv4(payload[12], payload[13], payload[14], payload[15])
}

// calculateChecksum calculates ICMP checksum
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func printPacket(payload []byte) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
	fmt.Println(packet.Dump())
}

func sendICMPReply(dstIP net.IP, icmp *layers.ICMPv4) {
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

	err = icmp.SerializeTo(buffer, opts)
	if err != nil {
		log.Printf("Failed to serialize ICMP: %v", err)
		return
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Printf("Failed to send ICMP reply: %v", err)
	}
}
