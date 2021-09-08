package main

import (
	"flag"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	err     error
	timeout time.Duration = -1 * time.Second
	handle  *pcap.Handle
)

func detect(handle *pcap.Handle) {

	captured := make(map[string]gopacket.Packet)
	capturedId := make([]string, 0)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		ipLayer := packet.Layer(layers.LayerTypeIPv4)

		dnsLayer := packet.Layer(layers.LayerTypeDNS)

		if ipLayer != nil && dnsLayer != nil {

			dns, _ := dnsLayer.(*layers.DNS)

			if dns.QR {

				id := strconv.Itoa(int(dns.ID))

				if captured[id] != nil {

					oldPacket := captured[id]
					oldDnsLayer := oldPacket.Layer(layers.LayerTypeDNS)

					oldDns, _ := oldDnsLayer.(*layers.DNS)

					if reflect.DeepEqual(dns.Questions, oldDns.Questions) {

						l1 := make([]string, 0)
						l2 := make([]string, 0)

						ansCount := fmt.Sprintf("%d", dns.ANCount)
						len, _ := strconv.Atoi(ansCount)
						for i := 0; i < len; i++ {
							dnsrr := dns.Answers[i]
							if dnsrr.Type == 1 {
								l1 = append(l1, dnsrr.IP.String())
							}
						}

						oldAnsCount := strconv.Itoa(int(oldDns.ANCount))
						len, _ = strconv.Atoi(oldAnsCount)
						for i := 0; i < len; i++ {
							olddnsrr := oldDns.Answers[i]
							if olddnsrr.Type == 1 {
								l2 = append(l2, olddnsrr.IP.String())
							}
						}

						sort.Strings(l1)
						sort.Strings(l2)

						if !reflect.DeepEqual(l1, l2) {
							fmt.Println(oldPacket.Metadata().Timestamp, " DNS poisoning attempt TXID ", id, " Request ", string(dns.Questions[0].Name))
							fmt.Println("Answer1 ", l2)
							fmt.Println("Answer2 ", l1)
							delete(captured, id)
							remove(capturedId, id)

						}

					}
				} else {
					captured[id] = packet
					capturedId = append(capturedId, id)
					len := len(captured)
					if len > 200 {
						for i := 0; i < len-130; i++ {
							delete(captured, capturedId[i])
						}
						capturedId = capturedId[len-130:]
					}
				}
			}
		}
	}
}

func remove(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func main() {

	devices, _ := pcap.FindAllDevs()

	//Parse the command line arguments for i and f flags.
	interfacePtr := flag.String("i", devices[0].Name, "a string")
	filePtr := flag.String("r", "", "a string")

	flag.Parse()

	var filter = flag.Args()

	// Open file to read from; else Read from device instead of file
	if *filePtr != "" {
		handle, err = pcap.OpenOffline(*filePtr)
		fmt.Println("Reading from file", *filePtr)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
	} else if *interfacePtr != "" {
		fmt.Println("Listening on interface", *interfacePtr)
		handle, err = pcap.OpenLive(*interfacePtr, 65535, true, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
	}

	expression := "udp and src port 53"

	if len(filter) > 0 {
		expression += " and " + filter[0]
	}

	err = handle.SetBPFFilter(expression)
	fmt.Println("Filter is set to : ", expression)
	if err != nil {
		// not fatal
		fmt.Printf("Unable to set filter: %v\n", err.Error())
	}

	detect(handle)

}
