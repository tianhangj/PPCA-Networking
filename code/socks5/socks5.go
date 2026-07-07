package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
)

func forward(src io.Reader, dst io.Writer, done chan error) {
	_, err := io.Copy(dst, src)
	done <- err
}

func process(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	ver, err := reader.ReadByte()
	if ver != 0x05 || err != nil {
		fmt.Println("socks version not supported")
		return
	}
	nMethods, err := reader.ReadByte()
	if err != nil {
		fmt.Println("read nMethods failed, err:", err)
		return
	}
	methods := make([]byte, nMethods)
	n, err := io.ReadFull(reader, methods)
	if n != int(nMethods) || err != nil {
		fmt.Println("read methods failed, err:", err)
		return
	}
	supportNoAuth := false
	for _, method := range methods {
		if method == 0x00 {
			supportNoAuth = true
			_, err = writer.Write([]byte{0x05, 0x00})
			err = writer.Flush()
			if err != nil {
				fmt.Println("write to client failed, err:", err)
				return
			}
			break
		}
	}
	if !supportNoAuth {
		_, err = writer.Write([]byte{0x05, 0xFF})
		fmt.Println("no supported auth method")
		return
	}
	reader.ReadByte()
	cmd, err := reader.ReadByte()
	reader.ReadByte()
	readAddr := func(reader *bufio.Reader) (string, error) {
		var dspAddr string
		atyp, err := reader.ReadByte()
		if err != nil {
			return "", fmt.Errorf("read atyp failed, err: %v", err)
		}
		switch atyp {
		case 0x01:
			_dspAddr := make([]byte, net.IPv4len)
			n, err := io.ReadFull(reader, _dspAddr)
			if n != net.IPv4len || err != nil {
				return "", fmt.Errorf("read dspAddr failed, err: %v", err)
			}
			dspAddr = net.IP(_dspAddr).String()
		case 0x03:
			domainLen, err := reader.ReadByte()
			fmt.Println("domainLen:", domainLen)
			if err != nil {
				return "", fmt.Errorf("read domainLen failed, err: %v", err)
			}
			_dspAddr := make([]byte, int(domainLen))
			n, err := io.ReadFull(reader, _dspAddr)
			if n != int(domainLen) || err != nil {
				return "", fmt.Errorf("read dspAddr failed, err: %v", err)
			}
			dspAddr = string(_dspAddr)
			if dspAddr == "0" {
				dspAddr = "0.0.0.0"
			}
		case 0x04:
			_dspAddr := make([]byte, net.IPv6len)
			n, err := io.ReadFull(reader, _dspAddr)
			if n != net.IPv6len || err != nil {
				return "", fmt.Errorf("read dspAddr failed, err: %v", err)
			}
			dspAddr = net.IP(_dspAddr).String()
		default:
			fmt.Println("address type not supported")
			return "", errors.New("address type not supported")
		}
		return dspAddr, nil
	}
	dspAddr, err := readAddr(reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	var dspPort uint16
	err = binary.Read(reader, binary.BigEndian, &dspPort)
	if err != nil {
		fmt.Println("read port failed, err:", err)
		return
	}
	switch cmd {
	case 0x01:
		if dspPort == 0 {
			fmt.Println("invalid port")
			return
		}
		addr := net.JoinHostPort(dspAddr, fmt.Sprintf("%d", dspPort))
		fmt.Println("connect to", addr)
		serverConn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Println("connect to server failed, err:", err)
			return
		}
		defer serverConn.Close()
		serverWriter := bufio.NewWriter(serverConn)
		serverReader := bufio.NewReader(serverConn)
		writer.Write([]byte{0x05, 0x00, 0x00})
		if serverConn.LocalAddr().(*net.TCPAddr).IP.To4() != nil {
			writer.Write([]byte{0x01})
			writer.Write(serverConn.LocalAddr().(*net.TCPAddr).IP.To4())
		} else {
			writer.Write([]byte{0x04})
			writer.Write(serverConn.LocalAddr().(*net.TCPAddr).IP.To16())
		}
		binary.Write(writer, binary.BigEndian, uint16(serverConn.LocalAddr().(*net.TCPAddr).Port))
		err = writer.Flush()
		if err != nil {
			fmt.Println("flush connection failed, err:", err)
			return
		}
		done := make(chan error, 2)
		go forward(reader, serverWriter, done)
		go forward(serverReader, writer, done)
		for i := 0; i < 2; i++ {
			e := <-done
			if e != nil {
				fmt.Println("forward failed, err:", e)
				return
			}
		}
	case 0x02:
		fmt.Println("bind command not supported")
		return
	case 0x03:
		laddr := net.JoinHostPort(dspAddr, fmt.Sprintf("%d", dspPort))
		laddr = "0.0.0.0:0"
		fmt.Println("udp associate request to", laddr)
		udpAddr, err := net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			fmt.Println("resolve udp addr failed, err:", err)
			return
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			fmt.Println("listen udp failed, err:", err)
			return
		}
		fmt.Println("udp listen on", udpConn.LocalAddr())
		defer udpConn.Close()
		writer.Write([]byte{0x05, 0x00, 0x00})
		if udpConn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
			writer.Write([]byte{0x01})
			writer.Write(udpConn.LocalAddr().(*net.UDPAddr).IP.To4())
		} else {
			writer.Write([]byte{0x04})
			writer.Write(udpConn.LocalAddr().(*net.UDPAddr).IP.To16())
		}
		binary.Write(writer, binary.BigEndian, uint16(udpConn.LocalAddr().(*net.UDPAddr).Port))
		err = writer.Flush()
		if err != nil {
			fmt.Println("flush connection failed, err:", err)
			return
		}
		var firstPacket bool = true
		var clientUDPAddr net.UDPAddr
		done := make(chan int)
		go func() {
			buf := make([]byte, 65536)
			for len(done) == 0 {
				n, addr, err := udpConn.ReadFromUDP(buf)
				if err != nil {
					fmt.Println("read udp failed, err:", err)
					return
				}
				if firstPacket {
					clientUDPAddr = *addr
					firstPacket = false
				}
				if clientUDPAddr.IP.Equal(addr.IP) && clientUDPAddr.Port == addr.Port {
					if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
						fmt.Println("invalid udp request header, drop")
						continue
					}
					stream := bufio.NewReader(bytes.NewBuffer(buf[3:n]))
					dspAddr, err := readAddr(stream)
					if err != nil {
						fmt.Println("read udp dspAddr failed, err:", err)
						return
					}
					var dspPort uint16
					err = binary.Read(stream, binary.BigEndian, &dspPort)
					if err != nil {
						fmt.Println("read udp dspPort failed, err:", err)
						return
					}
					raddr := net.JoinHostPort(dspAddr, fmt.Sprintf("%d", dspPort))
					rUDPAddr, _ := net.ResolveUDPAddr("udp", raddr)
					payload, err := io.ReadAll(stream)
					udpConn.WriteToUDP(payload, rUDPAddr)
				} else {
					var packet bytes.Buffer = bytes.Buffer{}
					packet.Write([]byte{0x00, 0x00, 0x00})
					if addr.IP.To4() != nil {
						packet.Write([]byte{0x01})
						packet.Write(addr.IP.To4())
					} else {
						packet.Write([]byte{0x04})
						packet.Write(addr.IP.To16())
					}
					binary.Write(&packet, binary.BigEndian, uint16(addr.Port))
					packet.Write(buf[:n])
					udpConn.WriteToUDP(packet.Bytes(), &clientUDPAddr)
				}
			}
		}()
		for {
			buf := make([]byte, 65536)
			_, err := reader.Read(buf)
			if err != nil {
				fmt.Println("read from tcp failed, err:", err)
				done <- 1
				udpConn.Close()
				break
			}
		}
	default:
		fmt.Println("command not supported")
		return
	}
}

func main() {
	var port int
	flag.IntVar(&port, "port", 1080, "socks5 listen port")
	flag.Parse()
	listen, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Println("listen failed, err:", err)
		return
	}
	fmt.Println("socks5 listen on", listen.Addr())
	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println("accept failed, err:", err)
			continue
		}
		go process(conn)
	}
}
