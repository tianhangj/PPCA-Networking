package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type CertificateAuthority struct {
	RootCert *x509.Certificate
	RootKey  *rsa.PrivateKey
}

func (ca *CertificateAuthority) SignCertificate(domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"State"},
			Locality:           []string{"City"},
			CommonName:         domain,
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Duration(30) * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.RootCert, &priv.PublicKey, ca.RootKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func handleConnection(ca *CertificateAuthority, conn net.Conn, conID int, logger *log.Logger, rule *regexp.Regexp) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		logger.Printf("Connection %d: Error reading from client: %v", conID, err)
		return
	}
	linep := bytes.IndexByte(buf[:n], '\n')
	line := string(buf[:linep])
	parts := strings.Split(line, " ")
	method := parts[0]
	url := parts[1]
	if method != "CONNECT" {
		// Handle HTTP connection
		if strings.Contains(url, "://") {
			url = strings.Split(url, "://")[1]
		}
		host := strings.Split(url, "/")[0]
		if !strings.Contains(host, ":") {
			host = host + ":80"
		}
		logger.Printf("Connection %d: Handling HTTP connection to %s", conID, host)
		serverConn, err := net.Dial("tcp", host)
		if err != nil {
			return
		}
		defer serverConn.Close()
		url1 := strings.Split(url, "/")[1]
		firstline := method + " " + url1 + " " + parts[2] + "\r\n"
		serverConn.Write([]byte(firstline))
		serverConn.Write(buf[linep+1 : n])
		go io.Copy(serverConn, conn)
		io.Copy(conn, serverConn)
	} else {
		// Handle HTTPS connection
		domain := strings.Split(url, ":")[0]
		if !rule.MatchString(domain) {
			serverConn, err := net.Dial("tcp", url)
			if err != nil {
				return
			}
			defer serverConn.Close()
			conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go io.Copy(serverConn, conn)
			io.Copy(conn, serverConn)
			return
		}
		logger.Printf("Connection %d: Handling HTTPS connection to %s", conID, url)
		serverConn, err := tls.Dial("tcp", url, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer serverConn.Close()
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		cert, priv, err := ca.SignCertificate(domain)
		if err != nil {
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: priv}},
			ClientAuth: tls.NoClientCert,
			ServerName: domain,
		})
		err = tlsConn.Handshake()
		if err != nil {
			return
		}
		go func() {
			buffer := make([]byte, 1024)
			n, err := tlsConn.Read(buffer)
			if err != nil {
				return
			}
			logger.Printf("Connection %d: <-[%d] %s\n", conID, n, string(buffer[:n]))
			serverConn.Write(buffer[:n])
		}()
		buffer := make([]byte, 1024)
		for {
			n, err := serverConn.Read(buffer)
			if err != nil {
				return
			}
			logger.Printf("Connection %d: ->[%d] %s\n", conID, n, string(buffer[:n]))
			tlsConn.Write(buffer[:n])
		}
	}
}

func createCertificateAuthority(certPath, keyPath string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pub := &priv.PublicKey
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{"mitmproxy CA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		panic(err)
	}
	os.WriteFile(certPath, caBytes, 0644)
	caPrivBytes := x509.MarshalPKCS1PrivateKey(priv)
	os.WriteFile(keyPath, caPrivBytes, 0600)
}
func loadCertificateAuthority(certPath, keyPath string) *CertificateAuthority {
	caBytes, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		panic(err)
	}
	caPrivBytes, err := os.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	priv, err := x509.ParsePKCS1PrivateKey(caPrivBytes)
	if err != nil {
		panic(err)
	}
	return &CertificateAuthority{
		RootCert: cert,
		RootKey:  priv,
	}
}

func main() {
	var createCA bool
	var port int
	var ruleStr string
	flag.BoolVar(&createCA, "c", false, "Create a new CA certificate and key")
	flag.IntVar(&port, "p", 9000, "Port to listen on")
	flag.StringVar(&ruleStr, "r", ".*", "A regex expression to filter log")
	flag.Parse()
	if createCA {
		createCertificateAuthority("ca/rootCA.crt", "ca/rootCA.key")
		return
	}
	ca := loadCertificateAuthority("ca/rootCA.crt", "ca/rootCA.key")
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: port})
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	conID := 0
	logFile, err := os.OpenFile("logs/"+ time.Now().Format("2006-01-02_15-04-05") + ".log", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	logger := log.New(logFile, "", log.LstdFlags)
	rule, err := regexp.Compile(ruleStr)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		conID++
		go handleConnection(ca, conn, conID, logger, rule)
	}
}