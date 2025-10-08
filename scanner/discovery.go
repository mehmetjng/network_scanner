// File: scanner/discovery.go
package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"network-scanner/models"
	"network-scanner/utils"
)

// DiscoverDevices finds all active devices on the network
func DiscoverDevices(cidr string, verbose bool) []models.Device {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var devices []models.Device
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); utils.IncrementIP(ip) {
		wg.Add(1)
		sem <- struct{}{}

		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			start := time.Now()
			if isHostAlive(ipStr) {
				latency := time.Since(start)

				device := models.Device{
					IP:        ipStr,
					LastSeen:  time.Now(),
					Latency:   fmt.Sprintf("%.2fms", float64(latency.Microseconds())/1000),
					IPVersion: "IPv4",
				}

				if utils.IsIPv6(ipStr) {
					device.IPVersion = "IPv6"
				}

				// Get hostname
				device.Hostname = utils.ResolveHostname(ipStr)

				// Get MAC address
				device.MAC = utils.GetMACAddress(ipStr)

				// Get vendor
				device.Vendor = utils.LookupVendor(device.MAC)

				mu.Lock()
				devices = append(devices, device)
				mu.Unlock()

				if verbose {
					fmt.Printf("[+] Found: %s (%s) - %s - %s\n",
						ipStr, device.Hostname, device.MAC, device.Vendor)
				}
			}
		}(ip.String())
	}

	wg.Wait()
	return devices
}

func isHostAlive(ip string) bool {
	// Try TCP connection first (using proper IPv6 formatting)
	timeout := 500 * time.Millisecond
	address := utils.FormatAddress(ip, 80)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// Try ICMP ping
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
	} else {
		if utils.IsIPv6(ip) {
			cmd = exec.Command("ping6", "-c", "1", "-W", "1", ip)
		} else {
			cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
		}
	}

	err = cmd.Run()
	return err == nil
}
