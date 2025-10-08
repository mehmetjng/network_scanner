package models

import "time"

// Device represents a discovered network device
type Device struct {
	IP              string          `json:"ip"`
	MAC             string          `json:"mac"`
	Hostname        string          `json:"hostname"`
	Vendor          string          `json:"vendor"`
	OpenPorts       []PortInfo      `json:"open_ports"`
	OS              string          `json:"os_guess"`
	Latency         string          `json:"latency"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	LastSeen        time.Time       `json:"last_seen"`
	IPVersion       string          `json:"ip_version"`
}

// PortInfo contains information about an open port
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
}

// Vulnerability represents a potential security issue
type Vulnerability struct {
	Severity    string   `json:"severity"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Port        int      `json:"port,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Impact      string   `json:"impact,omitempty"`
}

// ScanConfig holds scan configuration
type ScanConfig struct {
	CIDR           string
	Timeout        time.Duration
	MaxConcurrency int
	PortsToScan    []int
	EnableBanner   bool
	EnableOS       bool
	EnableVulnScan bool
	VerboseOutput  bool
	DeepScan       bool
}

// NetworkSummary holds overall network security status
type NetworkSummary struct {
	TotalDevices     int            `json:"total_devices"`
	TotalOpenPorts   int            `json:"total_open_ports"`
	TotalVulns       int            `json:"total_vulnerabilities"`
	CriticalVulns    int            `json:"critical_vulnerabilities"`
	HighVulns        int            `json:"high_vulnerabilities"`
	MediumVulns      int            `json:"medium_vulnerabilities"`
	LowVulns         int            `json:"low_vulnerabilities"`
	VulnsByType      map[string]int `json:"vulnerabilities_by_type"`
	MostVulnerable   string         `json:"most_vulnerable_device"`
	ScanDuration     string         `json:"scan_duration"`
	NetworkRiskScore int            `json:"network_risk_score"`
}
