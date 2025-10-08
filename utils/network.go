// File: utils/network.go
package utils

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// GetLocalNetworkCIDR returns the local network CIDR
func GetLocalNetworkCIDR() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ip := ipnet.IP.String()
				if strings.HasPrefix(ip, "192.168.") ||
					strings.HasPrefix(ip, "10.") ||
					strings.HasPrefix(ip, "172.") {
					return ipnet.String()
				}
			}
		}
	}
	return ""
}

// IncrementIP increments an IP address by one
func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// FormatAddress formats an IP and port for net.Dial (handles IPv6)
func FormatAddress(ip string, port int) string {
	if strings.Contains(ip, ":") {
		// IPv6 address - needs brackets
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	// IPv4 address
	return fmt.Sprintf("%s:%d", ip, port)
}

// GetMACAddress retrieves MAC address for an IP
func GetMACAddress(ip string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("arp", "-a", ip)
	} else {
		cmd = exec.Command("arp", "-n", ip)
	}

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	macRegex := regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)
	mac := macRegex.FindString(string(output))
	return strings.ToUpper(mac)
}

// LookupVendor returns vendor name from MAC address (OUI lookup)
func LookupVendor(mac string) string {
	if mac == "" {
		return ""
	}

	// Expanded OUI database
	ouiMap := map[string]string{
		"00:50:56": "VMware",
		"08:00:27": "Oracle VirtualBox",
		"52:54:00": "QEMU Virtual NIC",
		"52:55:0A": "QEMU/KVM",
		"00:0C:29": "VMware",
		"00:1B:21": "Intel Corporation",
		"00:1C:42": "Parallels",
		"00:15:5D": "Microsoft Hyper-V",
		"B8:27:EB": "Raspberry Pi Foundation",
		"DC:A6:32": "Raspberry Pi Trading",
		"00:11:22": "Cimsys Inc",
		"00:1A:A0": "Dell Inc",
		"00:1B:63": "Apple Inc",
		"00:50:F2": "Microsoft Corporation",
		"00:E0:4C": "Realtek",
		"D8:BB:C1": "Hewlett Packard",
		"F0:DE:F1": "ASUSTek Computer",
		"00:03:93": "Apple Inc",
		"00:0D:93": "Apple Inc",
	}

	// Extract OUI (first 8 characters)
	if len(mac) >= 8 {
		oui := strings.ToUpper(mac[:8])
		if vendor, ok := ouiMap[oui]; ok {
			return vendor
		}
	}

	return "Unknown"
}

// ResolveHostname attempts to resolve IP to hostname
func ResolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// IsIPv6 checks if an IP address is IPv6
func IsIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}
