// File: main.go (COMPLETE VERSION)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"network-scanner/models"
	"network-scanner/scanner"
	"network-scanner/utils"
)

func main() {
	// Parse command line flags
	cidr := flag.String("cidr", "", "Network CIDR to scan (e.g., 192.168.1.0/24)")
	output := flag.String("output", "scan_results.json", "Output JSON file")
	verbose := flag.Bool("v", false, "Verbose output")
	quick := flag.Bool("quick", false, "Quick scan (skip banner grabbing)")
	deep := flag.Bool("deep", false, "Deep scan (scan all 65535 ports)")
	portRange := flag.String("ports", "common", "Ports to scan: 'common', 'all', or comma-separated list")
	htmlReport := flag.Bool("html", false, "Generate HTML report")
	flag.Parse()

	printBanner()

	// Get network CIDR
	networkCIDR := *cidr
	if networkCIDR == "" {
		networkCIDR = utils.GetLocalNetworkCIDR()
		if networkCIDR == "" {
			fmt.Println("❌ Error: Could not determine local network range")
			fmt.Println("Please specify using: -cidr 192.168.1.0/24")
			return
		}
	}

	fmt.Printf("🌐 Scanning network: %s\n", networkCIDR)
	if *verbose {
		fmt.Println("📊 Verbose mode enabled")
	}
	if *deep {
		fmt.Println("🔬 Deep scan mode enabled (all ports)")
	}
	fmt.Println()

	// Phase 1: Device Discovery
	fmt.Println("🔍 Phase 1: Discovering devices...")
	startTime := time.Now()
	devices := scanner.DiscoverDevices(networkCIDR, *verbose)

	if len(devices) == 0 {
		fmt.Println("\n❌ No devices found on the network")
		return
	}

	fmt.Printf("\n✅ Found %d device(s) in %v\n\n", len(devices), time.Since(startTime))

	// Phase 2: Port Scanning & Vulnerability Assessment
	fmt.Println("🔎 Phase 2: Port scanning and vulnerability assessment...")

	// Determine ports to scan
	var portsToScan []int
	if *deep {
		portsToScan = scanner.AllPorts
	} else {
		switch *portRange {
		case "common":
			portsToScan = scanner.CommonPorts
		case "all":
			portsToScan = scanner.AllPorts
		default:
			fmt.Println("Custom port list not fully implemented, using common ports")
			portsToScan = scanner.CommonPorts
		}
	}

	var wg sync.WaitGroup
	for i := range devices {
		wg.Add(1)
		go func(dev *models.Device) {
			defer wg.Done()
			scanDevice(dev, portsToScan, !*quick, *verbose)
		}(&devices[i])
	}
	wg.Wait()

	scanDuration := time.Since(startTime)

	// Sort devices by risk score (highest first)
	sort.Slice(devices, func(i, j int) bool {
		return scanner.CalculateRiskScore(&devices[i]) > scanner.CalculateRiskScore(&devices[j])
	})

	// Display results
	displayResults(devices, *verbose)

	// Generate network summary
	summary := generateNetworkSummary(devices, scanDuration)

	// Save to JSON
	if err := saveResults(devices, *output); err != nil {
		fmt.Printf("❌ Error saving results: %v\n", err)
	} else {
		fmt.Printf("\n💾 Results saved to: %s\n", *output)
	}

	// Save summary
	if err := saveSummary(summary, "scan_summary.json"); err != nil {
		fmt.Printf("❌ Error saving summary: %v\n", err)
	} else {
		fmt.Printf("💾 Summary saved to: scan_summary.json\n")
	}

	// Generate HTML report if requested
	if *htmlReport {
		if err := generateHTMLReport(devices, summary, "scan_report.html"); err != nil {
			fmt.Printf("❌ Error generating HTML report: %v\n", err)
		} else {
			fmt.Printf("📄 HTML report saved to: scan_report.html\n")
		}
	}

	// Summary
	printSummary(summary)
	printRecommendations(devices)
}

func scanDevice(device *models.Device, ports []int, grabBanner bool, verbose bool) {
	if verbose {
		fmt.Printf("[*] Scanning %s...\n", device.IP)
	}

	// Port scan
	device.OpenPorts = scanner.ScanPorts(device.IP, ports, grabBanner)

	// OS fingerprinting
	device.OS = scanner.GuessOS(device)

	// Vulnerability assessment
	device.Vulnerabilities = scanner.AssessVulnerabilities(device)
}

func displayResults(devices []models.Device, verbose bool) {
	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("📋 SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 90))

	for i, device := range devices {
		riskScore := scanner.CalculateRiskScore(&device)
		riskLevel := getRiskLevel(riskScore)

		fmt.Printf("\n🖥️  Device #%d - Risk Score: %d/100 %s\n", i+1, riskScore, riskLevel)
		fmt.Printf("├─ IP Address:  %s (%s)\n", device.IP, device.IPVersion)
		fmt.Printf("├─ MAC Address: %s\n", device.MAC)
		fmt.Printf("├─ Hostname:    %s\n", device.Hostname)
		fmt.Printf("├─ Vendor:      %s\n", device.Vendor)
		fmt.Printf("├─ OS Guess:    %s\n", device.OS)
		fmt.Printf("├─ Latency:     %s\n", device.Latency)

		// Open Ports
		if len(device.OpenPorts) > 0 {
			fmt.Printf("├─ Open Ports:  %d\n", len(device.OpenPorts))
			for _, port := range device.OpenPorts {
				fmt.Printf("│  ├─ %d/%s (%s)\n", port.Port, "tcp", port.Service)
				if verbose && port.Banner != "" {
					banner := port.Banner
					if len(banner) > 70 {
						banner = banner[:70] + "..."
					}
					fmt.Printf("│  │  └─ Banner: %s\n", banner)
				}
				if port.Version != "" {
					fmt.Printf("│  │  └─ Version: %s\n", port.Version)
				}
			}
		} else {
			fmt.Printf("├─ Open Ports:  None detected\n")
		}

		// Vulnerabilities
		if len(device.Vulnerabilities) > 0 {
			fmt.Printf("└─ Vulnerabilities: %d\n", len(device.Vulnerabilities))
			for j, vuln := range device.Vulnerabilities {
				icon := getSeverityIcon(vuln.Severity)

				prefix := "   ├─"
				if j == len(device.Vulnerabilities)-1 {
					prefix = "   └─"
				}

				fmt.Printf("%s %s [%s] %s\n", prefix, icon, vuln.Severity, vuln.Type)
				fmt.Printf("   │  ├─ %s\n", vuln.Description)
				if len(vuln.CVE) > 0 {
					fmt.Printf("   │  ├─ CVE: %s\n", strings.Join(vuln.CVE, ", "))
				}
				if vuln.Remediation != "" && verbose {
					fmt.Printf("   │  └─ 💡 %s\n", vuln.Remediation)
				}
			}
		} else {
			fmt.Printf("└─ Vulnerabilities: ✅ None detected\n")
		}

		fmt.Println(strings.Repeat("-", 90))
	}
}

func generateNetworkSummary(devices []models.Device, duration time.Duration) models.NetworkSummary {
	summary := models.NetworkSummary{
		TotalDevices: len(devices),
		VulnsByType:  make(map[string]int),
		ScanDuration: duration.String(),
	}

	maxVulns := 0
	mostVulnIP := ""

	for _, device := range devices {
		summary.TotalOpenPorts += len(device.OpenPorts)

		if len(device.Vulnerabilities) > maxVulns {
			maxVulns = len(device.Vulnerabilities)
			mostVulnIP = device.IP
		}

		for _, vuln := range device.Vulnerabilities {
			summary.TotalVulns++
			summary.VulnsByType[vuln.Type]++

			switch vuln.Severity {
			case "CRITICAL":
				summary.CriticalVulns++
			case "HIGH":
				summary.HighVulns++
			case "MEDIUM":
				summary.MediumVulns++
			case "LOW":
				summary.LowVulns++
			}
		}
	}

	summary.MostVulnerable = mostVulnIP

	// Calculate network risk score (0-100)
	riskScore := 0
	if summary.CriticalVulns > 0 {
		riskScore += 40
	}
	riskScore += summary.HighVulns * 5
	riskScore += summary.MediumVulns * 2
	riskScore += summary.LowVulns
	if riskScore > 100 {
		riskScore = 100
	}
	summary.NetworkRiskScore = riskScore

	return summary
}

func saveResults(devices []models.Device, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(devices)
}

func saveSummary(summary models.NetworkSummary, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func generateHTMLReport(devices []models.Device, summary models.NetworkSummary, filename string) error {
	// Basic HTML report generation
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Network Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        .summary { background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .device { border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; font-weight: bold; }
        .low { color: #28a745; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #007bff; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Network Security Scan Report</h1>
        <p>Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total Devices:</strong> ` + fmt.Sprintf("%d", summary.TotalDevices) + `</p>
            <p><strong>Total Vulnerabilities:</strong> ` + fmt.Sprintf("%d", summary.TotalVulns) + `</p>
            <p><strong>Critical:</strong> <span class="critical">` + fmt.Sprintf("%d", summary.CriticalVulns) + `</span></p>
            <p><strong>High:</strong> <span class="high">` + fmt.Sprintf("%d", summary.HighVulns) + `</span></p>
            <p><strong>Network Risk Score:</strong> ` + fmt.Sprintf("%d/100", summary.NetworkRiskScore) + `</p>
        </div>`

	for i, device := range devices {
		html += fmt.Sprintf(`
        <div class="device">
            <h3>Device #%d: %s</h3>
            <p><strong>IP:</strong> %s | <strong>MAC:</strong> %s | <strong>OS:</strong> %s</p>
            <p><strong>Open Ports:</strong> %d | <strong>Vulnerabilities:</strong> %d</p>
        </div>`, i+1, device.Hostname, device.IP, device.MAC, device.OS, len(device.OpenPorts), len(device.Vulnerabilities))
	}

	html += `
    </div>
</body>
</html>`

	return os.WriteFile(filename, []byte(html), 0644)
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════╗
║        Network Security Scanner v1.0 - Enhanced          ║
║     Comprehensive Device & Vulnerability Analysis        ║
║         IPv4/IPv6 Support • Deep Scanning • CVEs         ║
╚═══════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

func printSummary(summary models.NetworkSummary) {
	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("📊 NETWORK SECURITY SUMMARY")
	fmt.Println(strings.Repeat("=", 90))
	fmt.Printf("Total Devices Found:        %d\n", summary.TotalDevices)
	fmt.Printf("Total Open Ports:           %d\n", summary.TotalOpenPorts)
	fmt.Printf("Total Vulnerabilities:      %d\n", summary.TotalVulns)
	fmt.Printf("  ├─ Critical:              %d 🔴\n", summary.CriticalVulns)
	fmt.Printf("  ├─ High:                  %d 🟠\n", summary.HighVulns)
	fmt.Printf("  ├─ Medium:                %d 🟡\n", summary.MediumVulns)
	fmt.Printf("  └─ Low:                   %d 🟢\n", summary.LowVulns)
	fmt.Printf("\nMost Vulnerable Device:     %s\n", summary.MostVulnerable)
	fmt.Printf("Network Risk Score:         %d/100 %s\n", summary.NetworkRiskScore, getRiskLevel(summary.NetworkRiskScore))
	fmt.Printf("Scan Duration:              %s\n", summary.ScanDuration)
	fmt.Println(strings.Repeat("=", 90))
}

func printRecommendations(devices []models.Device) {
	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("💡 TOP PRIORITY RECOMMENDATIONS")
	fmt.Println(strings.Repeat("=", 90))

	criticalCount := 0
	for _, device := range devices {
		for _, vuln := range device.Vulnerabilities {
			if vuln.Severity == "CRITICAL" && criticalCount < 5 {
				fmt.Printf("\n🔴 CRITICAL - %s (%s)\n", device.IP, device.Hostname)
				fmt.Printf("   Issue: %s\n", vuln.Description)
				fmt.Printf("   Fix: %s\n", vuln.Remediation)
				criticalCount++
			}
		}
	}

	if criticalCount == 0 {
		fmt.Println("\n✅ No critical vulnerabilities found!")
	}

	fmt.Println("\n" + strings.Repeat("=", 90))
}

func getSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}

func getRiskLevel(score int) string {
	if score >= 80 {
		return "🔴 CRITICAL"
	} else if score >= 60 {
		return "🟠 HIGH"
	} else if score >= 40 {
		return "🟡 MEDIUM"
	} else if score >= 20 {
		return "🟢 LOW"
	}
	return "✅ MINIMAL"
}
