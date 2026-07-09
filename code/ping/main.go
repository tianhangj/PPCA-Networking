package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

type ICMP struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
	Data        []byte
}

type IPHeader struct {
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
}

const (
	WAITING  = 0
	RECEIVED = 1
	TIMEOUT  = 2
	ERROR    = 3
)

type PingResult struct {
	State          int
	SendData       []byte
	SendTime       time.Time
	SendIdentifier uint16
	Seq            uint16
	TTL            int
	IP             net.IP
	Size           int
	ReceiveTime    time.Time
	icmp 		   ICMP
	err            string
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
func check_icmp_packet(icmp ICMP, pingResult *PingResult) bool {
	if pingResult != nil && pingResult.State != WAITING {
		return false
	}
	if icmp.Type != 0 || icmp.Identifier != pingResult.SendIdentifier {
		return false
	}
	if len(icmp.Data) != len(pingResult.SendData) {
		return false
	}
	for i := 0; i < len(icmp.Data); i++ {
		if icmp.Data[i] != pingResult.SendData[i] {
			return false
		}
	}
	buffer := []byte{icmp.Type, icmp.Code, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(buffer[4:6], icmp.Identifier)
	binary.BigEndian.PutUint16(buffer[6:8], icmp.SequenceNum)
	buffer = append(buffer, icmp.Data...)
	if icmp.Checksum != checksum(buffer) {
		return false
	}
	return true
}
func parse_ip_header(packet []byte) (IPHeader, error) {
	if len(packet) < 20 {
		return IPHeader{}, fmt.Errorf("packet too short")
	}
	return IPHeader{
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
	}, nil
}

func main() {
	defer func() {
        if r := recover(); r != nil {
            fmt.Fprintf(os.Stderr, "Panic: %v\n", r)
            debug.PrintStack()  // 这里会打印详细堆栈（包含行号）
            os.Exit(1)
        }
    }()
	var count int
	var interval float64
	var size int
	var timeout float64
	flag.IntVar(&count, "c", -1, "发送包数（默认：无限）")
	flag.Float64Var(&interval, "i", 1.0, "间隔秒数（默认：1.0）")
	flag.IntVar(&size, "s", 56, "Payload 字节数（默认：56）")
	flag.Float64Var(&timeout, "t", 1.0, "每包超时秒数（默认：2.0）")
	flag.Parse()
	host := flag.Arg(0)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)

	conn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	raddr, err := net.ResolveIPAddr("ip4", host)
	fmt.Printf("PING %s (%s): %d data bytes\n", host, raddr.String(), size)
	pingResults := make(map[uint16]*PingResult)
	timeChan := make(chan int, 16)
	pingResultChan := make(chan PingResult, 16)

	stopSend := make(chan struct{}, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Panic: %v\n", r)
				debug.PrintStack()
				os.Exit(1)
			}
		}()
		id := uint16(os.Getpid() & 0xffff)
		ticker := time.NewTicker(time.Duration(interval * float64(time.Second)))
		defer ticker.Stop()
		for i := 0; count == -1 || i < count; i++ {
			select {
			case <-stopSend:
				return
			case <-ticker.C:
				// send ping packet
				data := make([]byte, 8)
				sendTime := time.Now()
				binary.BigEndian.PutUint64(data, uint64(sendTime.Nanosecond()))
				for j := 0; j < size-8; j++ {
					data = append(data, byte(rand.Intn(256)))
				}
				icmp_packet := build_icmp_packet(id, uint16(i), data)
				// ipv4.NewConn(conn).SetTTL(3)
				n, err := conn.WriteToIP(icmp_packet, raddr)
				if err != nil || n != len(icmp_packet) {
					continue
				}
				pingResultChan <- PingResult{
					State:          WAITING,
					SendData:       data,
					SendTime:       sendTime,
					SendIdentifier: id,
					Seq:            uint16(i),
				}
				seq := i
				time.AfterFunc(time.Duration(timeout*float64(time.Second)), func() {
					timeChan <- seq
				})
			}
		}
	}()

	stopRead := make(chan struct{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Panic: %v\n", r)
				debug.PrintStack()
				os.Exit(1)
			}
		}()
		for {
			select {
			case <-stopRead:
				return
			default:
				buffer := make([]byte, 1500)
				conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
				n, err := conn.Read(buffer)
				if err != nil {
					continue
				}
				ipHeader, err := parse_ip_header(buffer[:20])
				icmp, err := parse_icmp_packet(buffer[20:n])
				if err != nil {
					continue
				}
				pingResultChan <- PingResult{
					State: RECEIVED,
					Seq:   icmp.SequenceNum,
					TTL:   int(ipHeader.TTL),
					IP:    ipHeader.SourceIP,
					Size:  n-20,
					ReceiveTime: time.Now(),
					icmp:  icmp,
				}
			}
		}
	}()

	// wait for reply
	sended := 0
	received := 0
	loss := 0
	defer func() {
		fmt.Printf("\n--- %s ping statistics ---\n", host)
		fmt.Printf("%d packets transmitted, %d received, %.2f%% packet loss\n", sended, received, float64(sended-received)/float64(sended)*100)
		if received != 0 {
			minTime := timeout * 1000
			maxTime := 0.0
			sumTime := 0.0
			sum2Time := 0.0
			for i := 0; i < sended; i++ {
				if pingResults[uint16(i)].State == RECEIVED {
					time := pingResults[uint16(i)].ReceiveTime.Sub(pingResults[uint16(i)].SendTime).Seconds() * 1000
					if time < minTime {
						minTime = time
					}
					if time > maxTime {
						maxTime = time
					}
					sumTime += time
					sum2Time += time * time
				}
			}
			fmt.Printf("round-trip min/avg/max/stddev = %.2f/%.2f/%.2f/%.2f ms\n", minTime, sumTime/float64(received), maxTime, math.Sqrt(sum2Time/float64(received)-(sumTime/float64(received))*(sumTime/float64(received))))
		}
	}()
	for {
		select {
		case <-sigChan:
			stopSend <- struct{}{}
			stopRead <- struct{}{}
			return
		case seq := <-timeChan:
			if pingResults[uint16(seq)].State == WAITING {
				pingResults[uint16(seq)].State = TIMEOUT
				loss++
			}
		case result := <-pingResultChan:
			if _, ok := pingResults[result.Seq]; !ok {
				pingResults[result.Seq] = &PingResult{}
			}
			if result.State == RECEIVED {
				if pingResults[result.Seq].State != WAITING {
					continue
				}
				if result.icmp.Code != 0 {
					// fmt.Println("Receive error")
					if (len(result.icmp.Data) != 28) {
						fmt.Println("Invalid ICMP error data length", len(result.icmp.Data))
						continue
					}
					originalICMP, err := parse_icmp_packet(result.icmp.Data[28:])
					if err != nil {
						continue
					}
					fmt.Printf("From %s icmp_seq=%d ", result.IP, originalICMP.SequenceNum)
					switch result.icmp.Type {
					case 3:
						switch result.icmp.Code {
						case 0:
							fmt.Printf("Destination Network Unreachable")
						case 1:
							fmt.Printf("Destination Host Unreachable")
						case 3:
							fmt.Printf("Destination Port Unreachable")
						case 4:
							fmt.Printf("Fragmentation Needed but DF Set")
						default:
							fmt.Printf("Destination Unreachable (Code %d)", result.icmp.Code)
						}
						pingResults[result.Seq].State = ERROR

					case 11:
						fmt.Printf("Time Exceeded (TTL expired) for seq %d", originalICMP.SequenceNum)
						pingResults[result.Seq].State = ERROR
					default:
						fmt.Printf("Received ICMP error type %d for seq %d", result.icmp.Type, originalICMP.SequenceNum)
						pingResults[result.Seq].State = ERROR
					}
				} else {
					if !check_icmp_packet(result.icmp, pingResults[result.icmp.SequenceNum]) {
						continue
					}
					pingResults[result.Seq].State = RECEIVED
					pingResults[result.Seq].TTL = result.TTL
					pingResults[result.Seq].IP = result.IP
					pingResults[result.Seq].Size = result.Size
					pingResults[result.Seq].ReceiveTime = result.ReceiveTime
					received++
					fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n", result.Size, result.IP.String(), result.Seq, result.TTL, result.ReceiveTime.Sub(pingResults[result.Seq].SendTime).Seconds()*1000)
				}
			}else {
				pingResults[result.Seq].State = WAITING
				pingResults[result.Seq].Seq = result.Seq
				pingResults[result.Seq].SendData = result.SendData
				pingResults[result.Seq].SendTime = result.SendTime
				pingResults[result.Seq].SendIdentifier = result.SendIdentifier
				sended++
			}
		}
		if count != -1 && sended == count && received+loss == count {
			return
		}
	}
}
