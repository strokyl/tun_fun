package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const (
	BUFFERSIZE          = 1500
	MTU                 = "1300"
	UDP_CHECKSUM_OFFSET = 6
	TCP_CHECKSUM_OFFSET = 16
)

type Binding struct {
	targetedIp   net.IP
	targetedPort layers.TCPPort
	realPort     layers.TCPPort
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%+v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	targetedCidr      = flag.String("targeted-cidr", "", "cidr to listen and to proxy to localhosst. For example 192.168.42.0/24")
	gardeningCidr     = flag.String("gardening-cidr", "", "cidr used for internal gardening, it must have the same size than targetedCidr")
	bindings          arrayFlags
	targetedLoopback  net.IP
	targetedIpnet     *net.IPNet
	gardeningLoopback net.IP
	gardeningIpnet    *net.IPNet
	slash             int
	table             []Binding
)

func parseBinding(s string) Binding {
	part := strings.Split(s, ":")
	if len(part) != 3 {
		log.Fatalf("%s is a invalid binding\n", s)
	}

	ip := net.ParseIP(part[0])

	if ip == nil {
		log.Fatalf("%s of binding %s is not a valid IP\n", part[0], s)
	}

	decimalBase := 10
	portUintSize := 16
	targetedPort, err := strconv.ParseUint(part[1], decimalBase, portUintSize)
	if err != nil {
		log.Fatalf("%s of binding %s is not a valid port\n", part[1], s)
	}

	realPort, err := strconv.ParseUint(part[2], decimalBase, portUintSize)
	if err != nil {
		log.Fatalf("%s of binding %s is not a valid port\n", part[2], s)
	}

	return Binding{
		ip,
		layers.TCPPort(targetedPort),
		layers.TCPPort(realPort),
	}
}

func checkFlag() {
	flag.Var(&bindings, "binding", "ex: --binding ip1:port1:port10 --binding ip2:port2:port12 will make tcp traffic for ip1:port1 go to localhost:port10 and traffic for ip1:port2 go to localhost:port12")
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

	if len(bindings) == 0 {
		flag.Usage()
		log.Fatalln("\nPlease specify at least one binding")
	}

	for _, bindingString := range bindings {
		binding := parseBinding(bindingString)
		if !targetedIpnet.Contains(binding.targetedIp) {
			log.Fatalf("%s binding is invalid because its IP is not in the targeted CIDR", bindingString)
		}
		table = append(table, binding)
	}

	targetedSlash, _ := targetedIpnet.Mask.Size()
	gardeningSlash, _ := gardeningIpnet.Mask.Size()
	if targetedSlash != gardeningSlash {
		log.Fatalln("gardeningCidr and targetedCidr must have the same slash")
	}

	log.Printf("%+v", table)
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

func findPortIn(targetedIp net.IP, port layers.TCPPort) (found bool, dstPort layers.TCPPort) {
	for _, te := range table {
		if te.targetedIp.Equal(targetedIp) && port == te.targetedPort {
			log.Printf("IN: replace %d port by %d", te.targetedPort, te.realPort)
			return true, te.realPort
		}
	}

	return false, 0
}

func findPortOut(targetedIp net.IP, port layers.TCPPort) (found bool, srcPort layers.TCPPort) {
	for _, te := range table {
		if te.targetedIp.Equal(targetedIp) && port == te.realPort {
			log.Printf("OUT: replace %d port by %d", te.realPort, te.targetedPort)
			return true, te.targetedPort
		}
	}

	return false, 0
}

func routePacket(packet []byte) {
	p := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcpLayer := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if targetedIpnet.Contains(ipLayer.DstIP) {
		found, dstPort := findPortIn(ipLayer.DstIP, tcpLayer.DstPort)
		if !found {
			return
		}
		tcpLayer.DstPort = dstPort
		ipLayer.SrcIP = targetedIpToGardeningIp(ipLayer.DstIP)
		ipLayer.DstIP = targetedLoopback
	} else if gardeningIpnet.Contains(ipLayer.DstIP) {
		ipLayer.SrcIP = gardeningIpToTargetedIp(ipLayer.DstIP)
		found, srcPort := findPortOut(ipLayer.SrcIP, tcpLayer.SrcPort)
		if !found {
			return
		}
		tcpLayer.SrcPort = srcPort
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
			routePacket(packet)
		}
	}
}
