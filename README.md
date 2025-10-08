# 🔍 Network Scanner

A powerful, fast, and easy-to-use network scanner written in Go. Discover devices, scan ports, grab service banners, and generate comprehensive reports of your local network.


✨ Features

- 🚀 **Fast Network Discovery** - Quickly identify active hosts on your network
- 🔌 **Port Scanning** - Detect open ports and running services
- 🏷️ **Banner Grabbing** - Identify service versions and details
- 📊 **Multiple Output Formats** - JSON and HTML reports
- 🎯 **Flexible Scanning Modes** - Quick scans or deep analysis
- 🌐 **CIDR Notation Support** - Scan specific network ranges
- 💬 **Verbose Logging** - Detailed output for troubleshooting

📋 Prerequisites

- Go 1.20 or higher
- Network access (some features may require elevated privileges)

🚀 Installation

Clone the Repository

```bash
git clone https://github.com/gatiella/network_scanner.git
cd network_scanner
```

Install Dependencies

```bash
go mod download
```

Build the Project

```bash
go build -o network_scanner
```

📖 Usage

Basic Scan

Scan your local network with default settings:

```bash
go run main.go
```

Or with the compiled binary:

```bash
./network_scanner
```

Verbose Scan with Specific CIDR

Scan a specific network range with detailed output:

```bash
go run main.go -cidr 192.168.1.0/24 -v
```

Deep Scan with HTML Report

Perform a comprehensive scan of all ports and generate an HTML report:

```bash
go run main.go -deep -html
```

Quick Scan

Fast scan without banner grabbing, with JSON output:

```bash
go run main.go -quick -output results.json
```

⚙️ Command-Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-cidr` | Network range to scan in CIDR notation | Auto-detect local network |
| `-v` | Enable verbose output | `false` |
| `-deep` | Scan all 65535 ports (slower but thorough) | `false` |
| `-quick` | Skip banner grabbing for faster scans | `false` |
| `-html` | Generate HTML report | `false` |
| `-output` | Specify output file path | `scan_results.json` |

📊 Output Examples

JSON Output

```json
{
  "scan_time": "2025-10-08T10:30:00Z",
  "network": "192.168.1.0/24",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "ports": [
        {
          "port": 80,
          "state": "open",
          "service": "http",
          "banner": "nginx/1.18.0"
        }
      ]
    }
  ]
}
```

HTML Report

The HTML report includes:
- Visual network topology
- Color-coded host status
- Expandable port details
- Service version information
- Export and filter capabilities

🔐 Security Considerations

⚠️ **Important**: This tool should only be used on networks you own or have explicit permission to scan. Unauthorized network scanning may be illegal in your jurisdiction.

- Always obtain proper authorization before scanning
- Be aware of your organization's security policies
- Use responsibly and ethically
🛠️ Development

Running Tests

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

🙏 Acknowledgments

- Built with ❤️ using Go
- Inspired by classic network scanning tools

📧 Contact

For questions, issues, or suggestions, please open an issue on GitHub.

---

Note: This tool is intended for legitimate network administration and security testing purposes only.