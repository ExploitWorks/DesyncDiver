#!/bin/bash

# DesyncDiver - Active HTTP Desynchronization Tester
# A tool for detecting HTTP Request Smuggling vulnerabilities

# Text styling
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
PURPLE="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color

# Script configuration
VERSION="1.0.0"
DEFAULT_TIMEOUT=10
DEFAULT_OUTPUT_DIR="./results"
TEMP_DIR="/tmp/desyncdiver"

# Function to display banner
show_banner() {
    echo -e "${BLUE}${BOLD}"
    echo "██████╗ ███████╗███████╗██╗   ██╗███╗   ██╗ ██████╗██████╗ ██╗██╗   ██╗███████╗██████╗ "
    echo "██╔══██╗██╔════╝██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝██╔══██╗██║██║   ██║██╔════╝██╔══██╗"
    echo "██║  ██║█████╗  ███████╗ ╚████╔╝ ██╔██╗ ██║██║     ██║  ██║██║██║   ██║█████╗  ██████╔╝"
    echo "██║  ██║██╔══╝  ╚════██║  ╚██╔╝  ██║╚██╗██║██║     ██║  ██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗"
    echo "██████╔╝███████╗███████║   ██║   ██║ ╚████║╚██████╗██████╔╝██║ ╚████╔╝ ███████╗██║  ██║"
    echo "╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═══╝ ╚═════╝╚═════╝ ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${BOLD}HTTP Desynchronization Vulnerability Scanner v${VERSION}${NC}"
    echo -e "${YELLOW}Actively tests for HTTP Request Smuggling vulnerabilities${NC}\n"
}

# Function to display usage information
show_usage() {
    echo -e "${BOLD}Usage:${NC}"
    echo -e "  ${0} [options] -u <target_url>"
    echo
    echo -e "${BOLD}Options:${NC}"
    echo -e "  -u, --url <url>             Target URL (required)"
    echo -e "  -o, --output <directory>    Output directory for results (default: ${DEFAULT_OUTPUT_DIR})"
    echo -e "  -t, --timeout <seconds>     Request timeout in seconds (default: ${DEFAULT_TIMEOUT})"
    echo -e "  -p, --proxy <proxy>         Use proxy (format: http://host:port)"
    echo -e "  -c, --cookies <cookies>     Cookies to include with requests"
    echo -e "  -H, --header <header>       Additional headers (can be used multiple times)"
    echo -e "  -m, --methods <methods>     HTTP methods to test (default: GET,POST)"
    echo -e "  -v, --verbose               Enable verbose output"
    echo -e "  -h, --help                  Display this help message"
    echo
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${0} -u https://example.com"
    echo -e "  ${0} -u https://example.com -v -t 15 -o ./my-results"
    echo -e "  ${0} -u https://example.com -H \"Authorization: Bearer token\" -c \"session=abc123\""
    echo
}

# Function to validate URL
validate_url() {
    local url=$1
    if [[ ! $url =~ ^https?:// ]]; then
        echo -e "${RED}Error: URL must start with http:// or https://${NC}"
        return 1
    fi
    return 0
}

# Function to create directory if it doesn't exist
create_dir_if_not_exists() {
    local dir=$1
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || { echo -e "${RED}Error: Could not create directory ${dir}${NC}"; return 1; }
    fi
    return 0
}

# Function to generate payload with different content-length/transfer-encoding combinations
generate_payload() {
    local method=$1
    local url=$2
    local payload_type=$3
    local host=$(echo "$url" | sed -E 's|^https?://([^/]+).*|\1|')
    local path=$(echo "$url" | sed -E 's|^https?://[^/]+(/.*)?|\1|')
    path=${path:-/}

    case "$payload_type" in
        "cl-te")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Content-Length: 4
Transfer-Encoding: chunked

1
A
0


EOF
            ;;
        "te-cl")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Transfer-Encoding: chunked
Content-Length: 6

0# Function to generate payload with different content-length/transfer-encoding combinations
generate_payload() {
    local method=$1
    local url=$2
    local payload_type=$3
    local host=$(echo "$url" | sed -E 's|^https?://([^/]+).*|\1|')
    local path=$(echo "$url" | sed -E 's|^https?://[^/]+(/.*)?|\1|')
    path=${path:-/}

    case "$payload_type" in
        "cl-te")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Content-Length: 4
Transfer-Encoding: chunked

1
A
0


EOF
            ;;
        "te-cl")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Transfer-Encoding: chunked
Content-Length: 6

0

X
EOF
            ;;
        "te-te")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Transfer-Encoding: identity
Transfer-Encoding: chunked

0


EOF
            ;;
        "cl-cl")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Content-Length: 5
Content-Length: 11

Hello
World
EOF
            ;;
        "space-te")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Transfer-Encoding : chunked

0


EOF
            ;;
        "crlf-te")
            printf "${method} ${path} HTTP/1.1\r
Host: ${host}\r
Transfer-Encoding: \r
 chunked\r
\r
0\r
\r
\r
"
            ;;
        *)
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}

EOF
            ;;
    esac
}
0


EOF
            ;;
        "cl-cl")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Content-Length: 5
Content-Length: 11

Hello
World
EOF
            ;;
        "space-te")
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}
Transfer-Encoding : chunked

0


EOF
            ;;
        "crlf-te")
            printf "${method} ${path} HTTP/1.1\r
Host: ${host}\r
Transfer-Encoding: \r
 chunked\r
\r
0\r
\r
\r
"
            ;;
        *)
            cat <<EOF
${method} ${path} HTTP/1.1
Host: ${host}

EOF
            ;;
    esac
}

# Function to send payload and analyze response
send_payload() {
    local url=$1
    local payload_type=$2
    local method=$3
    local timeout=$4
    local proxy=$5
    local additional_headers=$6
    local cookies=$7
    local verbose=$8
    local output_dir=$9
    
    local host=$(echo "$url" | sed -E 's|^https?://([^/]+).*|\1|')
    local port
    if [[ $url == https://* ]]; then
        port=443
    else
        port=80
    fi
    
    # Create temporary file for payload
    local payload_file="${TEMP_DIR}/payload_${payload_type}.txt"
    
    # Generate payload
    generate_payload "$method" "$url" "$payload_type" > "$payload_file"
    
    # Add custom headers
    if [[ -n "$additional_headers" ]]; then
        # Insert headers before the empty line
        sed -i '/^$/i '"$additional_headers"'' "$payload_file"
    fi
    
    # Add cookies
    if [[ -n "$cookies" ]]; then
        # Insert cookies before the empty line
        sed -i '/^$/i Cookie: '"$cookies"'' "$payload_file"
    fi
    
    local result_file="${TEMP_DIR}/response_${payload_type}.txt"
    
    if [[ "$verbose" == "true" ]]; then
        echo -e "${CYAN}[*] Sending ${payload_type} payload with ${method}...${NC}"
        echo -e "${CYAN}[*] Payload:${NC}"
        cat "$payload_file"
        echo
    else
        echo -e "${CYAN}[*] Testing ${BOLD}${payload_type}${NC} ${CYAN}payload...${NC}"
    fi
    
    # Prepare proxy args
    local proxy_args=""
    if [[ -n "$proxy" ]]; then
        proxy_args="-x $proxy"
    fi
    
    # Send request using curl or netcat based on payload type
    local response_code
    local response_size
    
    if [[ $url == https://* ]]; then
        # For HTTPS, use openssl s_client with a timeout
        { timeout "$timeout" bash -c "cat '$payload_file'; sleep 1" | timeout "$timeout" openssl s_client -quiet -connect "${host}:${port}" > "$result_file" 2>/dev/null; } || true
    else
        # For HTTP, use netcat with a timeout
        { timeout "$timeout" bash -c "cat '$payload_file'; sleep 1" | timeout "$timeout" nc "$host" "$port" > "$result_file"; } || true
    fi
    
    # Record the baseline response for comparison
    if [[ ! -f "${TEMP_DIR}/baseline_response.txt" ]]; then
        local baseline_file="${TEMP_DIR}/baseline_response.txt"
        # Send a normal request to establish baseline
        if [[ $url == https://* ]]; then
            timeout "$timeout" curl -s -k "$url" > "$baseline_file"
        else
            timeout "$timeout" curl -s "$url" > "$baseline_file"
        fi
        local baseline_size=$(wc -c < "$baseline_file")
        echo -e "${BLUE}[*] Established baseline response: ${baseline_size} bytes${NC}" 
    fi
    
    # Analyze response
    if [[ -s "$result_file" ]]; then
        response_code=$(grep -o "HTTP/[0-9.]* [0-9]*" "$result_file" | awk '{print $2}')
        response_size=$(wc -c < "$result_file")
        
        # Save detailed response to output directory
        cp "$result_file" "${output_dir}/${payload_type}_response.txt"
        
        # Extract server information to detect CDN/proxy
        local server_info=$(grep -E "Server:|X-Served-By:|Via:" "$result_file" | tr '\n' ' ')
        
        # Check for specific responses that indicate proper security handling
        local response_body=""
        if grep -q -e '^$' "$result_file"; then
            # Extract body content after the first empty line
            response_body=$(awk -v RS='^\r?\n$' 'NR==2{print}' "$result_file")
        else
            response_body=$(cat "$result_file")
        fi
        
        # Check for security responses that indicate proper handling
        local security_patterns=("broken chunked-encoding" "Bad Request" "Invalid Request" "line folding of header fields is not supported" "transfer-encoding header" "405 Not Allowed" "413 Payload Too Large" "400 Bad Request" "411 Length Required" "501 Not Implemented" "malformed" "invalid" "rejected" "length required" "too large" "not implemented" "not allowed")
        local is_security_response=false
        
        for pattern in "${security_patterns[@]}"; do
            if grep -q "$pattern" "$result_file"; then
                is_security_response=true
                break
            fi
        done
        
        # Check for CDN/proxy presence
        local cdn_patterns=("Varnish" "Fastly" "Cloudflare" "Akamai" "CloudFront" "cache" "CDN" "proxy")
        local has_cdn=false
        
        for pattern in "${cdn_patterns[@]}"; do
            if grep -i -q "$pattern" "$result_file"; then
                has_cdn=true
                break
            fi
        done
        
        # Analyze response
        if [[ -z "$response_code" ]]; then
            # No response code - could be a desync
            echo -e "${YELLOW}[!] ${BOLD}Unexpected response format${NC} ${YELLOW}for ${payload_type} payload${NC}"
            echo -e "${YELLOW}[!] This could indicate a desynchronization vulnerability${NC}"
            echo -e "${YELLOW}[!] Response size: ${response_size} bytes${NC}"
            if [[ "$has_cdn" == "true" ]]; then
                echo -e "${BLUE}[i] CDN detected: ${server_info}${NC}"
                echo -e "${BLUE}[i] This may be a false positive as CDNs often protect against request smuggling${NC}"
                return 1  # Likely a false positive
            fi
            return 0  # Potential vulnerability
        elif [[ "$response_code" == "40"* || "$response_code" == "50"* ]]; then
            # Error response - could be good or bad depending on context
            if [[ "$is_security_response" == "true" ]]; then
                echo -e "${BLUE}[-] Security response: HTTP ${response_code} - Proper handling of malformed request${NC}"
                echo -e "${BLUE}[-] This indicates the server is correctly rejecting invalid requests${NC}"
                return 1  # Not a vulnerability
            else
                # Check for known false positive patterns
                if [[ "$has_cdn" == "true" && ("$response_code" == "400" || "$response_code" == "405" || "$response_code" == "413") ]]; then
                    echo -e "${BLUE}[-] CDN protection: HTTP ${response_code} - ${server_info}${NC}"
                    return 1  # Not a vulnerability
                else
                    echo -e "${GREEN}[+] ${BOLD}Potential vulnerability detected${NC} ${GREEN}with ${payload_type} payload${NC}"
                    echo -e "${GREEN}[+] Response code: ${response_code}, Size: ${response_size} bytes${NC}"
                    return 0  # Potential vulnerability
                fi
            fi
        elif [[ "$response_code" == "20"* ]]; then
            # Successful response - check if suspicious
            if [[ "$payload_type" == "cl-te" || "$payload_type" == "te-cl" ]]; then
                # It's suspicious if malformed requests get 200 OK
                echo -e "${GREEN}[+] ${BOLD}Suspicious behavior:${NC} ${GREEN}Malformed ${payload_type} request got HTTP 200${NC}"
                echo -e "${GREEN}[+] This may indicate a desynchronization vulnerability${NC}"
                return 0  # Potential vulnerability
            else
                echo -e "${BLUE}[-] Normal response: HTTP ${response_code} (${response_size} bytes)${NC}"
                return 1  # No vulnerability detected
            fi
        else
            echo -e "${BLUE}[-] Normal response: HTTP ${response_code} (${response_size} bytes)${NC}"
            return 1  # No vulnerability detected
        fi
    else
        echo -e "${RED}[!] ${BOLD}No response received${NC} ${RED}for ${payload_type} payload${NC}"
        echo -e "${RED}[!] This could indicate a connection timeout, server timeout, or desynchronization${NC}"
        # For te-te payload, timeouts may indicate vulnerability but could also be network issues
        if [[ "$payload_type" == "te-te" ]]; then
            echo -e "${YELLOW}[!] Connection hung with ${BOLD}${payload_type}${NC} ${YELLOW}payload - requires manual verification${NC}"
            # Create empty response file to note the timeout
            echo "CONNECTION TIMED OUT - Requires manual verification" > "${output_dir}/${payload_type}_response.txt"
            return 1  # Mark as needing verification, not automatically a vulnerability
        fi
        return 2  # Error
    fi
}

# Function to create HTML report
create_report() {
    local output_dir=$1
    local target_url=$2
    local report_file="${output_dir}/desyncdiver_report.html"
    local vulnerable_payloads=$3
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Extract server information if available
    local server_info=""
    for payload_type in "${payload_types[@]}"; do
        local response_file="${output_dir}/${payload_type}_response.txt"
        if [[ -f "$response_file" ]]; then
            server_info=$(grep -E "Server:|X-Served-By:|Via:" "$response_file" | head -n 1)
            if [[ -n "$server_info" ]]; then
                break
            fi
        fi
    done
    
    # Check for CDN/proxy
    local cdn_detected=""
    if grep -q -E "Varnish|Fastly|Cloudflare|Akamai|CloudFront|cache|CDN|proxy" <(echo "$server_info"); then
        cdn_detected="CDN/proxy detected: $(echo "$server_info" | tr -d '\n')"
    fi
    
    # Generate the HTML report
    cat > "$report_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DesyncDiver - HTTP Desynchronization Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        header h1 {
            color: white;
            margin: 0;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .vulnerability {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .vulnerability h3 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .high {
            border-left: 5px solid #e74c3c;
        }
        .medium {
            border-left: 5px solid #f39c12;
        }
        .low {
            border-left: 5px solid #3498db;
        }
        .info {
            border-left: 5px solid #2ecc71;
        }
        .response {
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: monospace;
            white-space: pre-wrap;
            margin-top: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .explanation {
            background-color: #eaf2f8;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .note {
            font-style: italic;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <header>
        <h1>DesyncDiver Scan Report</h1>
        <p>HTTP Desynchronization Vulnerability Scanner</p>
    </header>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <table>
            <tr>
                <th>Target URL</th>
                <td>${target_url}</td>
            </tr>
            <tr>
                <th>Scan Date</th>
                <td>${timestamp}</td>
            </tr>
            <tr>
                <th>Vulnerabilities Found</th>
                <td>$(echo "$vulnerable_payloads" | wc -l)</td>
            </tr>
            <tr>
                <th>Server Information</th>
                <td>${server_info:-Unknown}</td>
            </tr>
            <tr>
                <th>CDN/Proxy</th>
                <td>${cdn_detected:-None detected}</td>
            </tr>
        </table>
        
        <div class="explanation">
            <p><strong>About HTTP Desynchronization:</strong> HTTP Request Smuggling (also known as desynchronization) is a technique for interfering with the way a website processes HTTP request sequences. It occurs when front-end and back-end systems interpret HTTP headers differently, allowing attackers to "smuggle" requests to the back-end server.</p>
            <p><strong>False Positives:</strong> Modern CDNs and security systems often implement protections that can trigger responses similar to vulnerable servers. This report attempts to distinguish between real vulnerabilities and proper security responses.</p>
        </div>
    </div>
    
    <h2>Findings</h2>
EOF

    # If no vulnerabilities found
    if [[ -z "$vulnerable_payloads" ]]; then
        cat >> "$report_file" <<EOF
    <div class="vulnerability info">
        <h3>No HTTP Desynchronization Vulnerabilities Detected</h3>
        <p>The target appears to be properly handling HTTP request headers and does not show signs of HTTP request smuggling vulnerabilities based on the tests performed.</p>
        
        <div class="explanation">
            <p><strong>Security Analysis:</strong> The target responded appropriately to malformed and malicious HTTP requests, indicating proper header validation and handling.</p>
EOF
        # If CDN detected, add specific note
        if [[ -n "$cdn_detected" ]]; then
            cat >> "$report_file" <<EOF
            <p><strong>CDN Protection:</strong> The target appears to be behind a CDN or proxy which provides additional protection against HTTP request smuggling attacks. CDNs typically implement strict HTTP parsing rules that prevent desynchronization attacks.</p>
EOF
        fi
        
        cat >> "$report_file" <<EOF
        </div>
    </div>
EOF
    else
        # Add each vulnerability
        while IFS= read -r payload_type; do
            response_file="${output_dir}/${payload_type}_response.txt"
            response_content=$(cat "$response_file" | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')
            
            # Extract response code
            response_code=$(grep -o "HTTP/[0-9.]* [0-9]*" "$response_file" | awk '{print $2}')
            
            # Determine if this is likely a false positive
            is_false_positive=false
            if grep -q -i -E "Varnish|Fastly|Cloudflare|Akamai|CloudFront|cache|CDN|proxy" "$response_file"; then
                if grep -q -E "broken chunked-encoding|Bad Request|Invalid Request|line folding|405 Not Allowed|413 Payload" "$response_file"; then
                    is_false_positive=true
                fi
            fi
            
            # Determine severity
            severity="medium"
            if [[ "$payload_type" == "cl-te" || "$payload_type" == "te-cl" ]]; then
                severity="high"
            elif [[ "$payload_type" == "cl-cl" || "$payload_type" == "te-te" ]]; then
                severity="medium"
            else
                severity="low"
            fi
            
            # Adjust severity if it's likely a false positive
            if [[ "$is_false_positive" == "true" ]]; then
                severity="low"
            fi
            
            cat >> "$report_file" <<EOF
    <div class="vulnerability ${severity}">
        <h3>Potential HTTP Desynchronization Vulnerability: ${payload_type}</h3>
        <p><strong>Severity:</strong> ${severity^}</p>
        <p><strong>Description:</strong> The server showed unexpected behavior when handling the ${payload_type} payload, which suggests it may be vulnerable to HTTP Request Smuggling attacks.</p>
        
        <h4>Technical Details</h4>
        <p>This vulnerability occurs when front-end and back-end servers interpret HTTP headers differently, allowing attackers to "smuggle" requests to the back-end server.</p>
EOF

            # Add false positive warning if applicable
            if [[ "$is_false_positive" == "true" ]]; then
                cat >> "$report_file" <<EOF
        <div class="explanation">
            <p><strong>Possible False Positive:</strong> The response indicates this may be a security feature rather than a vulnerability. The server is correctly rejecting malformed requests with appropriate error codes, which is the expected behavior for secure systems.</p>
        </div>
EOF
            fi
            
            # Add specific details based on payload type
            case "$payload_type" in
                "cl-te")
                    cat >> "$report_file" <<EOF
        <div class="explanation">
            <p><strong>CL-TE Attack Vector:</strong> This attack occurs when the front-end server uses the Content-Length header but the back-end server uses the Transfer-Encoding header. This specific test uses a chunked body that would be interpreted differently depending on which header is honored.</p>
        </div>
EOF
                    ;;
                "te-cl")
                    cat >> "$report_file" <<EOF
        <div class="explanation">
            <p><strong>TE-CL Attack Vector:</strong> This attack occurs when the front-end server uses the Transfer-Encoding header but the back-end server uses the Content-Length header. The conflicting headers can cause request desynchronization.</p>
        </div>
EOF
                    ;;
                "te-te")
                    cat >> "$report_file" <<EOF
        <div class="explanation">
            <p><strong>TE-TE Attack Vector:</strong> This attack uses duplicate or obfuscated Transfer-Encoding headers that may be processed differently by different servers. Some servers may honor only the first or the last header, leading to desynchronization.</p>
        </div>
EOF
                    ;;
                "cl-cl")
                    cat >> "$report_file" <<EOF
        <div class="explanation">
            <p><strong>CL-CL Attack Vector:</strong> This attack uses duplicate Content-Length headers with different values. If front-end and back-end servers honor different instances of the header, it can lead to request smuggling.</p>
        </div>
EOF
                    ;;
            esac
            
            cat >> "$report_file" <<EOF
        <h4>Server Response</h4>
        <div class="response">${response_content}</div>
        
        <h4>Recommendations</h4>
        <ul>
            <li>Ensure consistent HTTP header parsing across all servers in the chain</li>
            <li>Validate and sanitize all headers, especially Content-Length and Transfer-Encoding</li>
            <li>Consider implementing strict HTTP parsing rules</li>
            <li>Update web servers and proxies to the latest versions</li>
EOF

            # Add CDN recommendation if no CDN detected
            if ! grep -q -i -E "Varnish|Fastly|Cloudflare|Akamai|CloudFront|cache|CDN|proxy" "$response_file"; then
                cat >> "$report_file" <<EOF
            <li>Consider using a CDN or Web Application Firewall that provides protection against HTTP request smuggling</li>
EOF
            fi

            cat >> "$report_file" <<EOF
        </ul>
    </div>
EOF
        done <<< "$vulnerable_payloads"
    fi
    
    # Close the HTML
    cat >> "$report_file" <<EOF
    <div class="footer">
        <p>Generated by DesyncDiver v${VERSION} | ${timestamp}</p>
    </div>
</body>
</html>
EOF

    echo -e "${GREEN}[+] Report generated: ${report_file}${NC}"
}

# Main function
main() {
    # Default values
    local url=""
    local output_dir="$DEFAULT_OUTPUT_DIR"
    local timeout="$DEFAULT_TIMEOUT"
    local proxy=""
    local cookies=""
    local headers=""
    local methods="GET,POST"
    local verbose=false
    
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url)
                url="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            -p|--proxy)
                proxy="$2"
                shift 2
                ;;
            -c|--cookies)
                cookies="$2"
                shift 2
                ;;
            -H|--header)
                headers="${headers}${2}\n"
                shift 2
                ;;
            -m|--methods)
                methods="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                show_banner
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}Error: Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Show banner
    show_banner
    
    # Check required arguments
    if [[ -z "$url" ]]; then
        echo -e "${RED}Error: URL is required${NC}"
        show_usage
        exit 1
    fi
    
    # Validate URL
    validate_url "$url" || exit 1
    
    # Create output directory
    create_dir_if_not_exists "$output_dir" || exit 1
    
    # Create temporary directory
    create_dir_if_not_exists "$TEMP_DIR" || exit 1
    
    echo -e "${BLUE}[*] Target: ${BOLD}${url}${NC}"
    echo -e "${BLUE}[*] Output directory: ${output_dir}${NC}"
    echo -e "${BLUE}[*] Starting scan...${NC}\n"
    
    # Define payload types to test
    local payload_types=("cl-te" "te-cl" "te-te" "cl-cl" "space-te" "crlf-te")
    
    # List to store vulnerable payload types
    local vulnerable_payloads=""
    
    # Counter for real vulnerabilities vs false positives
    local potential_vulns=0
    
    # Check for CDN/WAF first
    local has_cdn=false
    local cdn_info=""
    
    echo -e "${BLUE}[*] Checking for CDN/WAF protection...${NC}"
    local headers_file="${TEMP_DIR}/headers.txt"
    if [[ $url == https://* ]]; then
        curl -s -I -k "$url" > "$headers_file"
    else
        curl -s -I "$url" > "$headers_file"
    fi
    
    if grep -q -i -E "Varnish|Fastly|Cloudflare|Akamai|CloudFront|cache|CDN|proxy|WAF" "$headers_file"; then
        has_cdn=true
        cdn_info=$(grep -E "Server:|X-Served-By:|Via:|CF-RAY:|X-Cache:|X-Powered-By:" "$headers_file" | tr '\n' ' ')
        echo -e "${BLUE}[*] CDN/WAF detected: ${BOLD}${cdn_info}${NC}"
        echo -e "${YELLOW}[!] Note: CDNs/WAFs often provide protection against HTTP desync attacks${NC}"
    else
        echo -e "${YELLOW}[!] No CDN/WAF detected - site may be more vulnerable to desync attacks${NC}"
    fi
    echo
    
    # Process each HTTP method
    IFS=',' read -ra method_array <<< "$methods"
    for method in "${method_array[@]}"; do
        echo -e "${PURPLE}[*] Testing with HTTP method: ${BOLD}${method}${NC}"
        
        # Process each payload type
        for payload_type in "${payload_types[@]}"; do
            # Send payload and check for vulnerability
            if send_payload "$url" "$payload_type" "$method" "$timeout" "$proxy" "$headers" "$cookies" "$verbose" "$output_dir"; then
                vulnerable_payloads="${vulnerable_payloads}${payload_type}\n"
                ((potential_vulns++))
            fi
            echo
        done
    done
    
    # Generate final report
    echo -e "${BLUE}[*] Scan completed. Generating report...${NC}"
    create_report "$output_dir" "$url" "$(echo -e "$vulnerable_payloads" | grep -v '^$')"
    
    # Cleanup temporary files
    rm -rf "$TEMP_DIR"
    
    echo -e "${GREEN}[+] Scan completed successfully!${NC}"
    
    # Show summary
    local vuln_count=$(echo -e "$vulnerable_payloads" | grep -v '^$' | wc -l)
    if [[ $vuln_count -gt 0 ]]; then
        if [[ "$has_cdn" == "true" ]]; then
            echo -e "${YELLOW}[!] ${BOLD}${vuln_count} potential issues detected, but may include false positives${NC}"
            echo -e "${YELLOW}[!] Target is protected by a CDN/WAF which reduces the risk${NC}"
        else
            echo -e "${RED}[!] ${BOLD}${vuln_count} potential vulnerabilities detected!${NC}"
        fi
        echo -e "${YELLOW}[!] Check the detailed report for analysis: ${output_dir}/desyncdiver_report.html${NC}"
    else
        echo -e "${GREEN}[+] No HTTP desynchronization vulnerabilities detected.${NC}"
        if [[ "$has_cdn" == "true" ]]; then
            echo -e "${GREEN}[+] Target is well-protected by CDN/WAF: ${cdn_info}${NC}"
        fi
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for required tools
    for cmd in curl nc openssl sed grep awk wc timeout; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing dependencies: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}Please install the required dependencies and try again.${NC}"
        exit 1
    fi
}

# Run dependency check
check_dependencies

# Run the main function with all arguments passed to the script
main "$@" 