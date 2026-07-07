package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
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

	var buf [512]byte
	n, err := reader.Read(buf[:])
	if n == 0 && err != nil {
		fmt.Println("read from client failed, err:", err)
		return
	}
	ver := buf[0]
	if ver != 0x05 {
		fmt.Println("socks version not supported")
		return
	}
	nMethods := int(buf[1])
	methods := buf[2 : 2+nMethods]
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
			n, err = reader.Read(buf[:])
			if n == 0 && err != nil {
				fmt.Println("read from client failed, err:", err)
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
	
	bytesBuffer := bytes.NewBuffer(buf[1:n])
	cmd := bytesBuffer.Next(1)
	bytesBuffer.Next(1)
	atyp := bytesBuffer.Next(1)
	var dspAddr string
	switch atyp[0] {
	case 0x01:
		dspAddr = net.IP(bytesBuffer.Next(net.IPv4len)).String()
	case 0x03:
		domainLen := int(bytesBuffer.Next(1)[0])
		dspAddr = string(bytesBuffer.Next(domainLen))
	case 0x04:
		dspAddr = net.IP(bytesBuffer.Next(net.IPv6len)).String()
	default:
		fmt.Println("address type not supported")
		return
	}
	var dspPort uint16
	err = binary.Read(bytesBuffer, binary.BigEndian, &dspPort)
	if err != nil {
		fmt.Println("read port failed, err:", err)
		return
	}
	switch cmd[0] {
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
		go io.Copy(serverWriter, reader)
		go io.Copy(writer, serverReader)
		done := make(chan error, 2)
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
		fmt.Println("UDP associate command not supported")
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
