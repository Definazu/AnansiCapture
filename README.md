<h1 align="center">AnansiCapture</h1>
<p align="center">
<img alt="Static Badge" src="https://img.shields.io/badge/made_by-Definazu-red?style=for-the-badge&link=https%3A%2F%2Fgithub.com%2FDefinazu">
<img alt="GitHub License" src="https://img.shields.io/github/license/Definazu/AnansiCapture?style=for-the-badge">
<img alt="GitHub top language" src="https://img.shields.io/github/languages/top/Definazu/AnansiCapture?style=for-the-badge">
<img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/Definazu/AnansiCapture?style=for-the-badge">
</p>

## Definition
AnansiCapture is a powerful cross-platform Network Traffic Analysis (NTA) tool written in Rust. It provides both CLI and GUI interfaces for capturing, analyzing, and displaying network traffic in real-time. The tool is designed to be user-friendly while offering detailed packet inspection.

## Features
- Real-time packet capture and analysis
- Support for multiple protocols:
  - TCP, UDP, ICMP, ICMPv6
  - IPv4, IPv6
  - DNS, DHCP, HTTP, TLS
  - ARP, IGMP, SMB
- Color-coded protocol display
- Detailed packet information
- Cross-platform support (Linux, Windows, macOS) (**!Tested on Linux only!**)
- Both CLI and GUI interfaces

## Installation
### Prerequisites
- Rust (latest stable version)
- Cargo (Rust's package manager)
- libpcap (for packet capture)
- Node.js and npm (for GUI development)

### For Linux
1. **Install dependencies**:
```bash
# For Debian/Ubuntu
sudo apt-get update
sudo apt-get install libpcap-dev npm

# For Arch Linux
sudo pacman -S libpcap npm
```

2. **Clone the repository**:
```bash
git clone https://github.com/Definazu/AnansiCapture.git
cd AnansiCapture
```

3. **Build the project**:
```bash
cargo build --release
```

## Usage
### CLI Interface
```bash
# Show help
./target/release/anansi help

# Capture traffic on specific interface
./target/release/anansi capture -i wlan0

# Capture with specific filter (BPF syntax)
./target/release/anansi capture -i eth0 -f "port 80"
```

### GUI Interface
```bash
cd gui
npm install
npm run tauri dev
```

## Command Line Options
- `-i, --interface`: Specify network interface
- `-f, --filter`: Apply BPF filter
- `-d, --debug`: Enable debug mode
- `-h, --help`: Show help message

## Output Format
The tool displays captured packets in the following format:
```
Time Source -> Destination Protocol Length Info
12:15:25.637 192.168.0.103 -> 10.1.1.80 DNS 74 Standard query 0x45d8 api2.app.sh A
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.