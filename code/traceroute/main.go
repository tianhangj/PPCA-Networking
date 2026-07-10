package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"golang.org/x/net/ipv4"
)

type IPPackage struct {
	VersionIHL     uint8
	TypeOfService  uint8
	TotalLength    uint16
	Identification uint16
	FlagsFragOffset uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SourceIP       net.IP
	DestinationIP  net.IP
	Data           []byte
}

type ICMP struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
	Data        []byte
}

type UDPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

func checksum(packet []byte) uint16 {
	if len(packet)%2 == 1 {
		packet = append(packet, 0)
	}
	var sum uint32
	for i := 0; i < len(packet); i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
func build_icmp_packet(id uint16, seq uint16, data []byte) []byte {
	buffer := []byte{8, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(buffer[4:6], id)
	binary.BigEndian.PutUint16(buffer[6:8], seq)
	buffer = append(buffer, data...)
	check := checksum(buffer)
	binary.BigEndian.PutUint16(buffer[2:4], check)
	return buffer
}
func parse_icmp_packet(packet []byte) (ICMP, error) {
	if len(packet) < 8 {
		return ICMP{}, fmt.Errorf("packet too short")
	}
	return ICMP{
		Type:        packet[0],
		Code:        packet[1],
		Checksum:    binary.BigEndian.Uint16(packet[2:4]),
		Identifier:  binary.BigEndian.Uint16(packet[4:6]),
		SequenceNum: binary.BigEndian.Uint16(packet[6:8]),
		Data:        packet[8:],
	}, nil
}
func parse_ip_header(packet []byte) (IPPackage, error) {
	if len(packet) < 20 {
		return IPPackage{}, fmt.Errorf("packet too short")
	}
	return IPPackage{
		VersionIHL:     packet[0],
		TypeOfService:  packet[1],
		TotalLength:    binary.BigEndian.Uint16(packet[2:4]),
		Identification: binary.BigEndian.Uint16(packet[4:6]),
		FlagsFragOffset: binary.BigEndian.Uint16(packet[6:8]),
		TTL:            packet[8],
		Protocol:       packet[9],
		HeaderChecksum: binary.BigEndian.Uint16(packet[10:12]),
		SourceIP:       net.IPv4(packet[12], packet[13], packet[14], packet[15]),
		DestinationIP:  net.IPv4(packet[16], packet[17], packet[18], packet[19]),
		Data:           packet[20:],
	}, nil
}
func parse_udp_header(packet []byte) (UDPHeader, error) {
	if len(packet) < 8 {
		return UDPHeader{}, fmt.Errorf("packet too short")
	}
	return UDPHeader{
		SourcePort:      binary.BigEndian.Uint16(packet[0:2]),
		DestinationPort: binary.BigEndian.Uint16(packet[2:4]),
		Length:          binary.BigEndian.Uint16(packet[4:6]),
		Checksum:        binary.BigEndian.Uint16(packet[6:8]),
	}, nil
}
func random_data(length int) []byte {
	data := make([]byte, length)
	binary.BigEndian.PutUint32(data[0:4], uint32(time.Now().Nanosecond()))
	for i := 0; i < length-4; i++ {
		data[i] = byte(rand.Intn(256))
	}
	return data
}
// UDP mode: port = ID + 33434
// ICMP mode: Seq = ID
// TTL = first_ttl + ID / nqueries
const (
	WAITING = 0
	TIMEOUT = 1
	RECEIVED_NOT_ARRIVE = 2
	RECEIVED = 3
)
type TraceData struct {
	State int
	ID uint16
	SendTime time.Time
	ReceiveTime time.Time
	IP net.IP
}

func main() {
	var max_hops int
	var nqueries int
	var timeout float64
	var icmp_mode bool
	var first_ttl int
	var data_len int = 60
	flag.IntVar(&max_hops, "m", 30, "最大 TTL（默认：30）")
	flag.IntVar(&nqueries, "q", 3, "每跳探测数（默认：3）")
	flag.Float64Var(&timeout, "w", 3.0, "超时秒数（默认：3.0）")
	flag.BoolVar(&icmp_mode, "I", false, "使用 ICMP Echo 模式（默认：UDP）")
	flag.IntVar(&first_ttl, "f", 1, "起始 TTL（默认：1）")
	flag.Parse()
	host := flag.Arg(0)
	Identifier := uint16(os.Getpid() & 0xffff)
	addr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		fmt.Printf("Cannot resolve %s: %v", host, err)
		return
	}
	conn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		fmt.Printf("Cannot listen on ICMP: %v", err)
		return
	}
	defer conn.Close()
	fmt.Printf("traceroute to %s (%s), %d hops max, %d byte packets\n", host, addr.String(), max_hops, data_len)
	for ttl := first_ttl; ttl <= max_hops; ttl++ {
		fmt.Printf("%2d  ", ttl)
		// receiver := make([]TraceData, nqueries)
		resultChan := make(chan TraceData, nqueries*2)
		stop := make(chan struct{})
		go func() {
			for {
			select {
			case <-stop:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second / 4.0))
				buffer := make([]byte, 1500)
				n, err := conn.Read(buffer)
				if err != nil {
					continue
				}
				ipPackage, err := parse_ip_header(buffer[:n])
				if err != nil {
					continue
				}
				icmp, err := parse_icmp_packet(ipPackage.Data)
				if err != nil {
					continue
				}
				originalIP, err := parse_ip_header(icmp.Data)
				if err != nil {
					continue
				}
				if icmp_mode {
					originalHeader, err := parse_icmp_packet(originalIP.Data)
					if err != nil {
						continue
					}
					if originalHeader.Identifier != Identifier {
						continue
					}
					reply_id := originalHeader.SequenceNum
					if int(reply_id) / nqueries != ttl-first_ttl {
						continue
					}
					switch icmp.Type {
					case 0:
						resultChan <- TraceData{State: RECEIVED, ID: reply_id, ReceiveTime: time.Now(), IP: ipPackage.SourceIP}
					case 11:
						resultChan <- TraceData{State: RECEIVED_NOT_ARRIVE, ID: reply_id, ReceiveTime: time.Now(), IP: ipPackage.SourceIP}
					}
				} else {
					originalHeader, err := parse_udp_header(originalIP.Data)
					if err != nil {
						continue
					}
					if originalHeader.DestinationPort < 33434 {
						continue
					}
					reply_id := originalHeader.DestinationPort - 33434
					if int(reply_id) / nqueries != ttl-first_ttl {
						continue
					}
					switch icmp.Type {
					case 3:
						resultChan <- TraceData{State: RECEIVED, ID: uint16(reply_id), ReceiveTime: time.Now(), IP: ipPackage.SourceIP}
					case 11:
						resultChan <- TraceData{State: RECEIVED_NOT_ARRIVE, ID: uint16(reply_id), ReceiveTime: time.Now(), IP: ipPackage.SourceIP}
					}
				}
				}
			}
		}()
		results := make([]TraceData, nqueries)
		ipv4.NewConn(conn).SetTTL(ttl)
		for i := 0; i < nqueries; i++ {
			var data []byte = random_data(data_len)
			if icmp_mode {
				icmp_packet := build_icmp_packet(Identifier, uint16((ttl-first_ttl)*nqueries+i), data)
				_, err := conn.WriteToIP(icmp_packet, addr)
				if err != nil {
					fmt.Printf("Error sending ICMP packet: %v\n", err)
					continue
				}
			} else {
				data = []byte("traceroute")
				udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: addr.IP, Port: 33434 + (ttl-first_ttl)*nqueries + i})
				if err != nil {
					continue
				}
				ipv4.NewConn(udpConn).SetTTL(ttl)
				defer udpConn.Close()
				_, err = udpConn.Write(data)
				if err != nil {
					continue
				}
			}
			results[i] = TraceData{State: WAITING, ID: uint16((ttl-first_ttl)*nqueries+i), SendTime: time.Now()}
			time.AfterFunc(time.Duration(timeout)*time.Second, func() {
				resultChan <- TraceData{State: TIMEOUT, ID: uint16((ttl-first_ttl)*nqueries+i)}
			})
		}
		receivedIPs := make(map[string][]float64)
		waiting := nqueries
		reached := false
		for {
			res := <-resultChan
			switch res.State {
			case RECEIVED:
				if results[res.ID%uint16(nqueries)].State == WAITING {
					waiting--
					results[res.ID%uint16(nqueries)].State = RECEIVED
					results[res.ID%uint16(nqueries)].ReceiveTime = res.ReceiveTime
					receivedIPs[res.IP.String()] = append(receivedIPs[res.IP.String()], res.ReceiveTime.Sub(results[res.ID%uint16(nqueries)].SendTime).Seconds()*1000)
					reached = true
				}
			case RECEIVED_NOT_ARRIVE:
				if results[res.ID%uint16(nqueries)].State == WAITING {
					waiting--
					results[res.ID%uint16(nqueries)].State = RECEIVED_NOT_ARRIVE
					results[res.ID%uint16(nqueries)].ReceiveTime = res.ReceiveTime
					receivedIPs[res.IP.String()] = append(receivedIPs[res.IP.String()], res.ReceiveTime.Sub(results[res.ID%uint16(nqueries)].SendTime).Seconds()*1000)
				}
			case TIMEOUT:
				if results[res.ID%uint16(nqueries)].State == WAITING {
					waiting--
					results[res.ID%uint16(nqueries)].State = TIMEOUT
					receivedIPs["*"] = append(receivedIPs["*"], -1)
				}
			}
			if waiting == 0 {
				stop <- struct{}{}
				for ip, times := range receivedIPs {
					if ip == "*" {
						for range times {
							fmt.Printf("*  ")
						}
					} else {
						fmt.Printf("%s  ", ip)
						for time := range times {
							fmt.Printf("%.3f ms  ", times[time])
						}
					}
					fmt.Printf("\n");
				}
				break
			}
			if reached {
				break
			}
		}
	}
}