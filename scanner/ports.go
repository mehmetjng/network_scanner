// File: scanner/ports.go
package scanner

import (
	"net"
	"strings"
	"sync"
	"time"

	"network-scanner/models"
	"network-scanner/utils"
)

var (
	// CommonPorts list - expanded
	CommonPorts = []int{
		20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
		143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 636, 993, 995, 1080,
		1194, 1433, 1521, 1723, 3306, 3389, 5060, 5061, 5432, 5900, 6379, 8000,
		8080, 8443, 8888, 9000, 9090, 27017, 50000,
	}

	// AllPorts for deep scan
	AllPorts = func() []int {
		ports := make([]int, 65535)
		for i := 0; i < 65535; i++ {
			ports[i] = i + 1
		}
		return ports
	}()

	// ServiceMap maps ports to service names - expanded
	ServiceMap = map[int]string{
		20:    "FTP-Data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP-Server",
		68:    "DHCP-Client",
		69:    "TFTP",
		80:    "HTTP",
		110:   "POP3",
		111:   "RPC",
		123:   "NTP",
		135:   "MSRPC",
		137:   "NetBIOS-NS",
		138:   "NetBIOS-DGM",
		139:   "NetBIOS-SSN",
		143:   "IMAP",
		161:   "SNMP",
		162:   "SNMP-Trap",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		514:   "Syslog",
		515:   "LPD",
		587:   "SMTP-Submission",
		636:   "LDAPS",
		993:   "IMAPS",
		995:   "POP3S",
		1080:  "SOCKS",
		1194:  "OpenVPN",
		1433:  "MSSQL",
		1521:  "Oracle",
		1723:  "PPTP",
		3306:  "MySQL",
		3389:  "RDP",
		5060:  "SIP",
		5061:  "SIP-TLS",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8000:  "HTTP-Alt",
		8080:  "HTTP-Proxy",
		8443:  "HTTPS-Alt",
		8888:  "HTTP-Alt2",
		9000:  "HTTP-Alt3",
		9090:  "WebSM",
		27017: "MongoDB",
		50000: "DB2",
	}
)

// ScanPorts scans specified ports on a host (IPv6 compatible)
func ScanPorts(ip string, ports []int, grabBanner bool) []models.PortInfo {
	var openPorts []models.PortInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			// Use IPv6-compatible address formatting
			address := utils.FormatAddress(ip, p)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err == nil {
				defer conn.Close()

				portInfo := models.PortInfo{
					Port:    p,
					Service: ServiceMap[p],
					State:   "open",
				}

				if portInfo.Service == "" {
					portInfo.Service = "unknown"
				}

				// Banner grabbing
				if grabBanner {
					conn.SetReadDeadline(time.Now().Add(3 * time.Second))

					// Send probe for some services
					sendProbe(conn, p)

					buf := make([]byte, 4096)
					n, _ := conn.Read(buf)
					if n > 0 {
						banner := strings.TrimSpace(string(buf[:n]))
						portInfo.Banner = banner
						portInfo.Version = extractVersion(banner, p)
					}
				}

				mu.Lock()
				openPorts = append(openPorts, portInfo)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

func sendProbe(conn net.Conn, port int) {
	// Send appropriate probes for services
	switch port {
	case 80, 8080, 8000, 8888:
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	case 21:
		// FTP responds automatically
	case 25, 587:
		conn.Write([]byte("EHLO scanner\r\n"))
	case 110:
		conn.Write([]byte("USER test\r\n"))
	case 22:
		// SSH sends banner automatically
	}
}

func extractVersion(banner string, port int) string {
	banner = strings.ToLower(banner)

	// SSH version detection
	if strings.Contains(banner, "ssh") {
		if idx := strings.Index(banner, "openssh"); idx != -1 && len(banner) > idx+20 {
			return banner[idx : idx+20]
		}
		return "SSH detected"
	}

	// Apache detection
	if strings.Contains(banner, "apache") {
		if idx := strings.Index(banner, "apache/"); idx != -1 && len(banner) > idx+15 {
			return banner[idx : idx+15]
		}
	}

	// Nginx detection
	if strings.Contains(banner, "nginx") {
		if idx := strings.Index(banner, "nginx/"); idx != -1 && len(banner) > idx+15 {
			return banner[idx : idx+15]
		}
	}

	// FTP detection
	if port == 21 && strings.Contains(banner, "ftp") {
		return banner[:min(len(banner), 50)]
	}

	// MySQL detection
	if port == 3306 {
		return "MySQL detected"
	}

	// PostgreSQL detection
	if port == 5432 {
		return "PostgreSQL detected"
	}

	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
