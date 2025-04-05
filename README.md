# DesyncDiver

**Active HTTP Desynchronization Vulnerability Scanner**

![Banner](https://via.placeholder.com/800x200/2c3e50/ffffff?text=DesyncDiver)

DesyncDiver is a bash-based tool for detecting HTTP Request Smuggling (Desynchronization) vulnerabilities in web servers and proxy chains. It actively tests targets by sending specially crafted HTTP requests designed to identify parsing inconsistencies between front-end and back-end servers.

## Features

- **Advanced Payload Generation**: Creates and sends specially formatted HTTP requests that test for various desynchronization vulnerabilities
- **Multiple Vulnerability Detection**: Tests for CL-TE, TE-CL, TE-TE, CL-CL and other header-based HTTP request smuggling vectors
- **Detailed Reporting**: Generates comprehensive HTML reports with findings, recommendations, and technical details
- **Flexible Configuration**: Customize headers, cookies, HTTP methods, and other parameters to suit your testing needs

## Installation

DesyncDiver requires the following dependencies:
- bash
- curl
- netcat (nc)
- openssl
- sed
- grep
- awk

Most Linux distributions have these tools pre-installed. If not, you can install them using your package manager:

```bash
# For Debian/Ubuntu
sudo apt-get install bash curl netcat-openbsd openssl sed grep gawk

# For RHEL/CentOS/Fedora
sudo dnf install bash curl nc openssl sed grep gawk
```

To install DesyncDiver:

```bash
# Clone the repository
git clone https://github.com/reschjonas/DesyncDriver.git

# Navigate to the directory
cd desyncdiver

# Make the script executable
chmod +x desyncdiver.sh
```

## Usage

Basic usage:

```bash
./desyncdiver.sh -u https://example.com
```

Advanced usage with options:

```bash
./desyncdiver.sh -u https://example.com -v -t 15 -o ./my-results -p http://proxy:8080 -H "Authorization: Bearer token" -c "session=abc123"
```

### Options

| Option | Description |
|--------|-------------|
| `-u, --url <url>` | Target URL (required) |
| `-o, --output <dir>` | Output directory for results (default: ./results) |
| `-t, --timeout <sec>` | Request timeout in seconds (default: 10) |
| `-p, --proxy <proxy>` | Use proxy (format: http://host:port) |
| `-c, --cookies <cookies>` | Cookies to include with requests |
| `-H, --header <header>` | Additional headers (can be used multiple times) |
| `-m, --methods <methods>` | HTTP methods to test (default: GET,POST) |
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Display help message |

## Examples

Test a single website with default options:
```bash
./desyncdiver.sh -u https://example.com
```

Test with verbose output and custom timeout:
```bash
./desyncdiver.sh -u https://example.com -v -t 15
```

Test with custom headers and cookies:
```bash
./desyncdiver.sh -u https://example.com -H "X-Custom-Header: Value" -c "session=abc123"
```

## How It Works

DesyncDiver works by:

1. Generating specially crafted HTTP requests with various header combinations
2. Testing Content-Length and Transfer-Encoding header inconsistencies
3. Analyzing server responses for anomalies or unexpected behaviors
4. Identifying potential desynchronization vulnerabilities based on response patterns
5. Generating detailed reports with findings and recommendations

## Security Considerations

- **Authorization**: Always ensure you have proper authorization before testing any website
- **Legal Implications**: Unauthorized testing may be illegal in many jurisdictions
- **Impact**: HTTP Request Smuggling tests can potentially disrupt service operations

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the research on HTTP Request Smuggling by [James Kettle (PortSwigger)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- Thanks to the security community for documenting these vulnerabilities 