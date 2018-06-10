package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
)

const (
	BUFFERSIZE          = 1500
	MTU                 = "1300"
	UDP_CHECKSUM_OFFSET = 6
	TCP_CHECKSUM_OFFSET = 16
)

type TableEntry struct {
	targetedIp   net.IP
	targetedPort layers.TCPPort
	realPort     layers.TCPPort
}

var (
	targetedCidr      = flag.String("targeted-cidr", "", "cidr to listen and to proxy to localhosst. For example 192.168.42.0/24")
	gardeningCidr     = flag.String("gardening-cidr", "", "cidr used for internal gardening, it must have the same size than targetedCidr")
	targetedLoopback  net.IP
	targetedIpnet     *net.IPNet
	gardeningLoopback net.IP
	gardeningIpnet    *net.IPNet
	slash             int
	table             = [2]TableEntry{{net.IPv4(192, 168, 42, 42), 4242, 8042}, {net.IPv4(192, 168, 42, 43), 4242, 8043}}
)

func checkFlag() {
	flag.Parse()
	var err error

	if "" == *targetedCidr {
		flag.Usage()
		log.Fatalln("\ntargeted-cidr is not specified")
	}

	targetedLoopback, targetedIpnet, err = net.ParseCIDR(*targetedCidr)
	if err != nil {
		log.Fatalf("targeted-cidr: %s is not a valid cidr", targetedCidr)
	}

	gardeningLoopback, gardeningIpnet, err = net.ParseCIDR(*gardeningCidr)
	if err != nil {
		log.Fatalf("gardening-cidr: %s is not a valid cidr", gardeningCidr)
	}

	if "" == *gardeningCidr {
		flag.Usage()
		log.Fatalln("\ngardening-cidr ip is not specified")
	}

	targetedSlash, _ := targetedIpnet.Mask.Size()
	gardeningSlash, _ := gardeningIpnet.Mask.Size()
	if targetedSlash != gardeningSlash {
		log.Fatalln("gardeningCidr and targetedCidr must have the same slash")
	}

	log.Printf("%s %s", targetedLoopback, gardeningLoopback)
}

func runIP(args ...string) {
	cmd := exec.Command("/sbin/ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.Fatalln("Error running /sbin/ip:", err)
	}
}

func sendRawIPv4Packet(packet []byte) {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	ip := targetedLoopback.To4()
	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]},
	}
	err := syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		log.Fatal("Sendto:", err)
	}
	log.Printf("Packet routed")
}

func ipToInt(ip net.IP) uint32 {
	var result uint32
	err := binary.Read(bytes.NewReader(ip.To4()), binary.BigEndian, &result)
	if err != nil {
		panic(err)
	}

	return result
}

func intToIp(ip uint32) net.IP {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, ip)

	return net.IPv4(buf[0], buf[1], buf[2], buf[3])
}

func targetedIpToGardeningIp(targetedIp net.IP) net.IP {
	return translateInIpnet(targetedIp, gardeningIpnet)
}

func translateInIpnet(targetedIp net.IP, destIpNet *net.IPNet) net.IP {
	log.Printf("IIIIP %s", targetedIp)
	dep := ipToInt(targetedIp)
	var mask uint32 = 0
	slash, _ := destIpNet.Mask.Size()
	mask = ^(^mask << (32 - uint32(slash)))
	var ip_in_int uint32 = (dep & mask) | ipToInt(destIpNet.IP)

	return intToIp(ip_in_int)
}

func gardeningIpToTargetedIp(gardeningIp net.IP) net.IP {
	return translateInIpnet(gardeningIp, targetedIpnet)
}

func findPortIn(targetedIp net.IP, port layers.TCPPort) layers.TCPPort {
	for _, te := range table {
		if te.targetedIp.Equal(targetedIp) && port == te.targetedPort {
			log.Printf("IN: replace %d port by %d", te.targetedPort, te.realPort)
			return te.realPort
		}
	}

	return port
}

func findPortOut(targetedIp net.IP, port layers.TCPPort) layers.TCPPort {
	for _, te := range table {
		if te.targetedIp.Equal(targetedIp) && port == te.realPort {
			log.Printf("OUT: replace %d port by %d", te.realPort, te.targetedPort)
			return te.targetedPort
		}
	}

	return port
}

func routePacket(packet []byte) {
	p := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcpLayer := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if targetedIpnet.Contains(ipLayer.DstIP) {
		log.Printf("To real tcp socket")
		tcpLayer.DstPort = findPortIn(ipLayer.DstIP, tcpLayer.DstPort)
		ipLayer.SrcIP = targetedIpToGardeningIp(ipLayer.DstIP)
		ipLayer.DstIP = targetedLoopback
	} else if gardeningIpnet.Contains(ipLayer.DstIP) {
		log.Printf("From real tcp socket")
		ipLayer.SrcIP = gardeningIpToTargetedIp(ipLayer.DstIP)
		tcpLayer.SrcPort = findPortOut(ipLayer.SrcIP, tcpLayer.SrcPort)
		ipLayer.DstIP = targetedLoopback
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload([]byte(tcpLayer.LayerPayload())))
	if err != nil {
		panic(err)
	}
	log.Println("La tete du paquet maintenant")
	newPacket := buf.Bytes()
	logTcpPacket(newPacket)
	sendRawIPv4Packet(newPacket)
}

func configureRouteForTunInterface(tunName string) {
	log.Printf("Configuring route for: %s\n", tunName)
	runIP("link", "set", "dev", tunName, "mtu", MTU)
	runIP("addr", "add", *targetedCidr, "dev", tunName)
	runIP("addr", "add", *gardeningCidr, "dev", tunName)
	runIP("link", "set", "dev", tunName, "up")
}

func createTun() *water.Interface {
	config := water.Config{
		DeviceType: water.TUN,
	}
	tun, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	return tun
}

func isTcpPacket(packet []byte) bool {
	header, err := ipv4.ParseHeader(packet)
	if err != nil {
		log.Fatal(err)
	}

	return header.Protocol == 6
}

func logTcpPacket(packet []byte) {
	header, err := ipv4.ParseHeader(packet)
	if err != nil {
		log.Fatal(err)
	}

	tcpBody := packet[header.Len:]
	buf := bytes.NewReader(tcpBody)
	var srcPort uint16
	var dstPort uint16

	err = binary.Read(buf, binary.BigEndian, &srcPort)

	if err != nil {
		log.Fatal(err)
	}

	err = binary.Read(buf, binary.BigEndian, &dstPort)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("TCP Packet Received from IP %s -> %s |-> %d: %d\n", header.Src, header.Dst, srcPort, dstPort)

}

func main() {
	checkFlag()
	tun := createTun()
	configureRouteForTunInterface(tun.Name())

	packetBuffer := make([]byte, 2000)
	for {
		n, err := tun.Read(packetBuffer)
		if err != nil {
			log.Fatal(err)
		}

		packet := packetBuffer[:n]
		if isTcpPacket(packet) {
			log.Println("\n\n\n")
			logTcpPacket(packet)
			routePacket(packet)
		}
	}
}
