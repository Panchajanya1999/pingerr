#!/bin/bash

# Copyright 2025 Panchajanya1999
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# DNS Speed Test Script with IPv6 Support
# Tests multiple DNS providers (IPv4 and IPv6) and finds the fastest one
# Compatible with Bash 3.2+ (macOS), Bash 4+ (Linux), and zsh

# Color codes for output
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[1;33m')
BLUE=$(printf '\033[0;34m')
CYAN=$(printf '\033[0;36m')
NC=$(printf '\033[0m') # No Color

# Number of tests per DNS server
TEST_COUNT=5

# Test domains (popular sites for comprehensive testing)
TEST_DOMAINS=(
    "google.com"
    "youtube.com"
    "facebook.com"
    "instagram.com"
    "chatgpt.com"
    "x.com"
    "whatsapp.com"
    "reddit.com"
    "wikipedia.org"
    "amazon.com"
    "tiktok.com"
    "pinterest.com"
    "cloudflare.com"
    "github.com"
    "netflix.com"
)

# Check for IPv6 connectivity
check_ipv6_connectivity() {
    echo -e "${CYAN}Checking IPv6 connectivity...${NC}"

    # Method 1: Check if device has IPv6 address
    if command -v ip &> /dev/null; then
        ipv6_addr=$(ip -6 addr show scope global 2>/dev/null | grep -oE 'inet6 [0-9a-f:]+' | head -1 | awk '{print $2}')
        if [ -n "$ipv6_addr" ]; then
            echo -e "${GREEN}✓ IPv6 address found: $ipv6_addr${NC}"
        else
            echo -e "${YELLOW}⚠ No global IPv6 address found on device${NC}"
        fi
    fi

    # Method 2: Try to ping Google's IPv6 DNS
    echo -e "Testing IPv6 connectivity to Google DNS (2001:4860:4860::8888)..."
    if ping -c 2 -W 2 2001:4860:4860::8888 &> /dev/null; then
        echo -e "${GREEN}✓ IPv6 connectivity is working!${NC}"
        echo ""
        return 0
    else
        echo -e "${YELLOW}✗ IPv6 connectivity not available${NC}"
        echo -e "${YELLOW}  IPv6 DNS servers will be skipped in this test${NC}"
        echo ""
        return 1
    fi
}

# IPv6 support flag
IPV6_ENABLED=0
check_ipv6_connectivity && IPV6_ENABLED=1

# DNS Servers to test (IPv4) - Using parallel arrays for Bash 3.2 compatibility
DNS_NAMES_IPV4=(
    "Google-Primary"
    "Google-Secondary"
    "Cloudflare-Primary"
    "Cloudflare-Secondary"
    "Cloudflare-Family-Primary"
    "Cloudflare-Family-Secondary"
    "Quad9-Primary"
    "Quad9-Secondary"
    "Quad9-Secured"
    "OpenDNS-Primary"
    "OpenDNS-Secondary"
    "OpenDNS-Family-Primary"
    "OpenDNS-Family-Secondary"
    "DNS.SB-Primary"
    "DNS.SB-Secondary"
    "NextDNS-Primary"
    "NextDNS-Secondary"
    "AdGuard-Primary"
    "AdGuard-Secondary"
    "AdGuard-Family-Primary"
    "AdGuard-Family-Secondary"
    "CleanBrowsing-Primary"
    "CleanBrowsing-Secondary"
    "CleanBrowsing-Family"
    "ControlD-Primary"
    "ControlD-Secondary"
    "ControlD-Malware"
    "RethinkDNS-Primary"
    "RethinkDNS-Secondary"
    "OpenBLD"
    "FlashStart-Primary"
    "FlashStart-Secondary"
    "Mullvad-Primary"
    "Mullvad-Secondary"
    "Mullvad-Base-Primary"
    "Mullvad-Base-Secondary"
    "IIJ-Primary"
    "IIJ-Secondary"
    "Foundation-Applied-Privacy"
    "Foundation-Applied-Privacy2"
    "Restena"
    "DNS-for-Family-Primary"
    "DNS-for-Family-Secondary"
    "Canadian-Shield-Primary"
    "Canadian-Shield-Secondary"
    "Digitale-Gesellschaft-Primary"
    "Digitale-Gesellschaft-Secondary"
    "Switch-Primary"
    "Switch-Secondary"
    "DNSPod-Primary"
    "DNSPod-Secondary"
    "AliDNS-Primary"
    "AliDNS-Secondary"
    "LibreDNS"
    "UncensoredDNS-Primary"
    "UncensoredDNS-Secondary"
    "DNS0.EU-Primary"
    "DNS0.EU-Secondary"
    "360-Primary"
    "360-Secondary"
    "Comodo-Primary"
    "Comodo-Secondary"
    "Neustar-Primary"
    "Neustar-Secondary"
    "Verisign-Primary"
    "Verisign-Secondary"
    "Yandex-Primary"
    "Yandex-Secondary"
    "Yandex-Safe-Primary"
    "Yandex-Safe-Secondary"
    "Hurricane-Electric"
    "puntCAT"
    "Freenom"
    "Level3-Primary"
    "Level3-Secondary"
    "DNS4IN-Primary"
    "DNS4IN-Secondary"
)
DNS_IPS_IPV4=(
    "8.8.8.8"
    "8.8.4.4"
    "1.1.1.1"
    "1.0.0.1"
    "1.1.1.3"
    "1.0.0.3"
    "9.9.9.9"
    "149.112.112.112"
    "9.9.9.11"
    "208.67.222.222"
    "208.67.220.220"
    "208.67.222.123"
    "208.67.220.123"
    "185.222.222.222"
    "45.11.45.11"
    "45.90.28.39"
    "45.90.30.39"
    "94.140.14.14"
    "94.140.15.15"
    "94.140.14.15"
    "94.140.15.16"
    "185.228.168.9"
    "185.228.169.9"
    "185.228.168.168"
    "76.76.2.0"
    "76.76.10.0"
    "76.76.2.1"
    "149.112.121.10"
    "149.112.122.10"
    "46.151.208.154"
    "185.236.104.104"
    "185.236.105.105"
    "194.242.2.2"
    "194.242.2.3"
    "194.242.2.4"
    "194.242.2.5"
    "103.2.57.5"
    "103.2.58.5"
    "37.252.185.229"
    "37.252.185.232"
    "158.64.1.29"
    "94.130.180.225"
    "78.47.64.161"
    "149.112.121.10"
    "149.112.122.10"
    "185.95.218.42"
    "185.95.218.43"
    "130.59.31.248"
    "130.59.31.251"
    "119.29.29.29"
    "119.28.28.28"
    "223.5.5.5"
    "223.6.6.6"
    "88.198.92.222"
    "91.239.100.100"
    "89.233.43.71"
    "193.110.81.0"
    "185.253.5.0"
    "101.226.4.6"
    "180.163.249.75"
    "8.26.56.26"
    "8.20.247.20"
    "156.154.70.1"
    "156.154.71.1"
    "64.6.64.6"
    "64.6.65.6"
    "77.88.8.8"
    "77.88.8.1"
    "77.88.8.88"
    "77.88.8.2"
    "74.82.42.42"
    "109.69.8.51"
    "80.80.80.80"
    "209.244.0.3"
    "209.244.0.4"
    "143.110.176.185"
    "68.183.246.1661"
)

# DNS Servers to test (IPv6)
DNS_NAMES_IPV6=(
    "Google-Primary-v6"
    "Google-Secondary-v6"
    "Cloudflare-Primary-v6"
    "Cloudflare-Secondary-v6"
    "Cloudflare-Family-Primary-v6"
    "Cloudflare-Family-Secondary-v6"
    "Quad9-Primary-v6"
    "Quad9-Secondary-v6"
    "Quad9-Secured-v6"
    "OpenDNS-Primary-v6"
    "OpenDNS-Secondary-v6"
    "OpenDNS-Family-v6"
    "AdGuard-Primary-v6"
    "AdGuard-Secondary-v6"
    "AdGuard-Family-Primary-v6"
    "AdGuard-Family-Secondary-v6"
    "DNS.SB-Primary-v6"
    "DNS.SB-Secondary-v6"
    "NextDNS-Primary-v6"
    "NextDNS-Secondary-v6"
    "CleanBrowsing-Primary-v6"
    "CleanBrowsing-Secondary-v6"
    "CleanBrowsing-Family-v6"
    "ControlD-Primary-v6"
    "ControlD-Secondary-v6"
    "ControlD-Malware-v6"
    "Mullvad-Primary-v6"
    "Mullvad-Secondary-v6"
    "Mullvad-Base-Primary-v6"
    "Mullvad-Base-Secondary-v6"
    "Digitale-Gesellschaft-Primary-v6"
    "Digitale-Gesellschaft-Secondary-v6"
    "Switch-Primary-v6"
    "Switch-Secondary-v6"
    "UncensoredDNS-Primary-v6"
    "UncensoredDNS-Secondary-v6"
    "DNS0.EU-Primary-v6"
    "DNS0.EU-Secondary-v6"
    "AliDNS-Primary-v6"
    "AliDNS-Secondary-v6"
    "Yandex-Primary-v6"
    "Yandex-Secondary-v6"
    "Yandex-Safe-Primary-v6"
    "Yandex-Safe-Secondary-v6"
    "Hurricane-Electric-v6"
    "Freenom-Primary-v6"
    "Freenom-Secondary-v6"
    "OpenNIC-Primary-v6"
    "OpenNIC-Secondary-v6"
    "Restena-v6"
    "DNS-for-Family-Primary-v6"
    "DNS-for-Family-Secondary-v6"
    "CleanBrowsing-Security-v6"
    "CleanBrowsing-Adult-v6"
    "CleanBrowsing-Family-Secondary-v6"
    "IIJ-Primary-v6"
    "IIJ-Secondary-v6"
    "Comodo-Primary-v6"
    "Comodo-Secondary-v6"
    "Neustar-Primary-v6"
    "Neustar-Secondary-v6"
    "DNS4IN-Primary-v6"
    "DNS4IN-Secondary-v6"
)
DNS_IPS_IPV6=(
    "2001:4860:4860::8888"
    "2001:4860:4860::8844"
    "2606:4700:4700::1111"
    "2606:4700:4700::1001"
    "2606:4700:4700::1113"
    "2606:4700:4700::1003"
    "2620:fe::fe"
    "2620:fe::9"
    "2620:fe::11"
    "2620:119:35::35"
    "2620:119:53::53"
    "2620:119:35::123"
    "2a10:50c0::ad1:ff"
    "2a10:50c0::ad2:ff"
    "2a10:50c0::bad1:ff"
    "2a10:50c0::bad2:ff"
    "2a09::"
    "2a11::"
    "2a07:a8c0::"
    "2a07:a8c1::"
    "2a0d:2a00:1::"
    "2a0d:2a00:2::"
    "2a0d:2a00:1::1"
    "2606:1a40::"
    "2606:1a40:1::"
    "2606:1a40::1"
    "2a07:e340::2"
    "2a07:e340::3"
    "2a07:e340::4"
    "2a07:e340::5"
    "2a05:fc84::42"
    "2a05:fc84::43"
    "2001:620:0:ff::2"
    "2001:620:0:ff::3"
    "2001:67c:28a4::"
    "2a01:3a0:53:53::"
    "2a0f:fc80::"
    "2a0f:fc81::"
    "2400:3200::1"
    "2400:3200:baba::1"
    "2a02:6b8::feed:0ff"
    "2a02:6b8:0:1::feed:0ff"
    "2a02:6b8::feed:bad"
    "2a02:6b8:0:1::feed:bad"
    "2001:470:20::2"
    "2a02:fe80:1010::1"
    "2a02:fe80:1010::2"
    "2a05:dfc7:5::53"
    "2a05:dfc7:5::5353"
    "2001:a18:1::29"
    "2a01:4f8:151:64e6::225"
    "2a01:4f8:141:316d::161"
    "2a0d:2a00:3::"
    "2a0d:2a00:1::2"
    "2a0d:2a00:2::2"
    "2001:240:bb8a:10::1"
    "2001:240:bb8a:20::1"
    "2606:4700:50::adf5:6f3"
    "2606:4700:50::adf5:6f4"
    "2620:74:1b::1:1"
    "2620:74:1c::2:2"
    "2400:6180:100:d0::c592:1001"
    "2400:6180:100:D0::C7E3:6001"
)

# Build combined DNS server arrays based on IPv6 availability
DNS_NAMES=()
DNS_IPS=()

# Add IPv4 servers
for i in "${!DNS_NAMES_IPV4[@]}"; do
    DNS_NAMES+=("${DNS_NAMES_IPV4[$i]}")
    DNS_IPS+=("${DNS_IPS_IPV4[$i]}")
done

# Add IPv6 servers if enabled
if [ $IPV6_ENABLED -eq 1 ]; then
    echo -e "${GREEN}IPv6 is enabled - including IPv6 DNS servers in tests${NC}"
    echo ""
    for i in "${!DNS_NAMES_IPV6[@]}"; do
        DNS_NAMES+=("${DNS_NAMES_IPV6[$i]}")
        DNS_IPS+=("${DNS_IPS_IPV6[$i]}")
    done
else
    echo -e "${YELLOW}IPv6 is disabled - testing IPv4 DNS servers only${NC}"
    echo ""
fi

# Results arrays (parallel arrays for Bash 3.2 compatibility)
RESULT_NAMES=()
RESULT_AVGS=()
RESULT_IPS=()
FAILED_NAMES=()
FAILED_IPS=()

# Check for required commands
if ! command -v dig &> /dev/null; then
    echo -e "${RED}Error: 'dig' not found. Please install dnsutils/bind-tools.${NC}"
    echo "On OpenWRT: opkg install bind-dig"
    echo "On Debian/Ubuntu: apt-get install dnsutils"
    echo "On RHEL/CentOS: yum install bind-utils"
    echo "On macOS: brew install bind"
    exit 1
fi

# Function to test DNS response time
test_dns() {
    local dns_server=$1
    local domain=$2
    local timeout=2

    # Use dig to test DNS server (works for both IPv4 and IPv6)
    if command -v dig &> /dev/null; then
        result=$(dig @"${dns_server}" "${domain}" +noall +stats +time=${timeout} 2>/dev/null | grep "Query time:" | awk '{print $4}')
    else
        echo "0"
        return 1
    fi

    # Return the time in ms, or 0 if failed
    if [ -z "$result" ]; then
        echo "0"
        return 1
    else
        echo "$result"
        return 0
    fi
}

# Function to calculate average
calculate_average() {
    local sum=0
    local count=0
    for val in "$@"; do
        if [ "$val" != "0" ]; then
            sum=$((sum + val))
            count=$((count + 1))
        fi
    done

    if [ $count -eq 0 ]; then
        echo "9999"  # Return high value for failed tests
    else
        echo $((sum / count))
    fi
}

# Function to check if DNS is IPv6
is_ipv6_dns() {
    local dns_name=$1
    case "$dns_name" in
        *-v6) return 0 ;;
        *) return 1 ;;
    esac
}

# Header
total_servers=${#DNS_NAMES[@]}
total_tests=$((total_servers * TEST_COUNT))
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}      DNS Speed Test - Testing ${total_servers} DNS Servers${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Total DNS Servers: ${total_servers} (IPv4: ${#DNS_NAMES_IPV4[@]}, IPv6: ${#DNS_NAMES_IPV6[@]})"
echo -e "Tests per server: ${TEST_COUNT}"
echo -e "Total tests to run: ${total_tests}"
echo -e "Test domains: ${#TEST_DOMAINS[@]} popular websites"
echo ""
echo -e "${YELLOW}This will take a few minutes to complete...${NC}"
echo ""

MAX_DNS_PARALLEL=10

# Create temporary directory for DNS test results
DNS_TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$DNS_TEMP_DIR"' EXIT

# Progress counter
current=0
total=${#DNS_NAMES[@]}
dns_job_count=0

# Test each DNS server
echo -e "${YELLOW}Starting DNS tests with parallel execution (max $MAX_DNS_PARALLEL concurrent)...${NC}"
echo ""

for i in "${!DNS_NAMES[@]}"; do
    dns_name="${DNS_NAMES[$i]}"
    dns_ip="${DNS_IPS[$i]}"
    current=$((current + 1))

    # Create temp file for this DNS server result (sanitize special characters)
    sanitized_name=$(echo "$dns_name" | tr '/ ' '__')
    dns_temp_file="$DNS_TEMP_DIR/${sanitized_name}.txt"

    # Launch DNS test in background
    {
        # Progress indicator
        printf "[%3d/%3d] Testing %-35s (%s) ... \n" "$current" "$total" "$dns_name" "$dns_ip"

        # Store results for this DNS server
        times=""
        failed=0

        # Test multiple times with different domains
        for j in $(seq 1 $TEST_COUNT); do
            # Rotate through test domains
            domain_index=$(( (j - 1) % ${#TEST_DOMAINS[@]} ))
            domain="${TEST_DOMAINS[$domain_index]}"

            response_time=$(test_dns "$dns_ip" "$domain")

            if [ "$response_time" == "0" ] || [ -z "$response_time" ]; then
                failed=$((failed + 1))
            else
                times="$times $response_time"
            fi
        done

        if [ -z "$times" ] || [ $failed -eq $TEST_COUNT ]; then
            printf "[%3d/%3d] %-35s (%s): %sFAILED%s\n" "$current" "$total" "$dns_name" "$dns_ip" "${RED}" "${NC}"
            echo "FAILED|$dns_name|$dns_ip" > "$dns_temp_file"
        else
            # shellcheck disable=SC2086
            # Note: $times intentionally unquoted - it contains space-separated values
            avg=$(calculate_average $times)
            printf "[%3d/%3d] %-35s (%s): ${GREEN}%4d ms${NC}\n" "$current" "$total" "$dns_name" "$dns_ip" "$avg"
            echo "SUCCESS|$dns_name|$avg|$dns_ip" > "$dns_temp_file"
        fi
    } &

    dns_job_count=$((dns_job_count + 1))

    # Limit parallel jobs
    if [ $dns_job_count -ge $MAX_DNS_PARALLEL ]; then
        wait -n 2>/dev/null || wait  # wait -n not available in Bash 3.2, fallback to wait
        dns_job_count=$((dns_job_count - 1))
    fi
done

# Wait for all remaining DNS test jobs
wait
echo -e "\n${GREEN}All DNS tests completed!${NC}\n"

# Collect results from temp files
echo "Processing DNS test results..."
for i in "${!DNS_NAMES[@]}"; do
    dns_name="${DNS_NAMES[$i]}"
    sanitized_name=$(echo "$dns_name" | tr '/ ' '__')
    dns_temp_file="$DNS_TEMP_DIR/${sanitized_name}.txt"
    if [ -f "$dns_temp_file" ]; then
        IFS='|' read -r status name data1 data2 < "$dns_temp_file"
        if [ "$status" == "FAILED" ]; then
            FAILED_NAMES+=("$name")
            FAILED_IPS+=("$data1")
        else
            RESULT_NAMES+=("$name")
            RESULT_AVGS+=("$data1")
            RESULT_IPS+=("$data2")
        fi
    fi
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                                    COMPLETE RESULTS (BEST → WORST)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Create sorted indices for results (sort by avg time)
# Build a sortable list and sort it
SORTED_RESULTS=""
for i in "${!RESULT_NAMES[@]}"; do
    SORTED_RESULTS="${SORTED_RESULTS}${RESULT_AVGS[$i]}|${RESULT_NAMES[$i]}|${RESULT_IPS[$i]}\n"
done
SORTED_RESULTS=$(echo -e "$SORTED_RESULTS" | sort -t'|' -k1 -n)

# Display IPv4 Results
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                              IPv4 DNS SERVERS                                     ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}IPv4 DNS Servers Ranked by Speed:${NC}"
echo -e "┌──────┬──────────────────────────────────────┬─────────────────────────────────────┬───────────┐"
echo -e "│ Rank │ DNS Server                           │ IP Address                          │ Avg Time  │"
echo -e "├──────┼──────────────────────────────────────┼─────────────────────────────────────┼───────────┤"

rank=1
ipv4_count=0
echo -e "$SORTED_RESULTS" | while IFS='|' read -r avg dns_name ip; do
    [ -z "$avg" ] && continue
    if ! is_ipv6_dns "$dns_name"; then
        # Color code based on speed
        if [ "$avg" -lt 50 ]; then
            time_color="${GREEN}"  # Excellent
        elif [ "$avg" -lt 100 ]; then
            time_color="${YELLOW}" # Good
        else
            time_color="${RED}"    # Slow
        fi

        printf "│ %-4d │ %-36s │ %-35s │ ${time_color}%7d ms${NC} │\n" "$rank" "$dns_name" "$ip" "$avg"
        rank=$((rank + 1))
        ipv4_count=$((ipv4_count + 1))
    fi
done

# Check if any IPv4 servers were displayed
ipv4_displayed=$(echo -e "$SORTED_RESULTS" | while IFS='|' read -r avg dns_name ip; do
    [ -z "$avg" ] && continue
    if ! is_ipv6_dns "$dns_name"; then
        echo "1"
        break
    fi
done)

if [ -z "$ipv4_displayed" ]; then
    echo -e "│      │ No IPv4 DNS servers working          │                                     │           │"
fi

echo -e "└──────┴──────────────────────────────────────┴─────────────────────────────────────┴───────────┘"
echo ""

# Display IPv6 Results
if [ $IPV6_ENABLED -eq 1 ]; then
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                              IPv6 DNS SERVERS                                     ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}IPv6 DNS Servers Ranked by Speed:${NC}"
    echo -e "┌──────┬──────────────────────────────────────┬─────────────────────────────────────┬───────────┐"
    echo -e "│ Rank │ DNS Server                           │ IP Address                          │ Avg Time  │"
    echo -e "├──────┼──────────────────────────────────────┼─────────────────────────────────────┼───────────┤"

    rank=1
    echo -e "$SORTED_RESULTS" | while IFS='|' read -r avg dns_name ip; do
        [ -z "$avg" ] && continue
        if is_ipv6_dns "$dns_name"; then
            # Color code based on speed
            if [ "$avg" -lt 50 ]; then
                time_color="${GREEN}"  # Excellent
            elif [ "$avg" -lt 100 ]; then
                time_color="${YELLOW}" # Good
            else
                time_color="${RED}"    # Slow
            fi

            printf "│ %-4d │ %-36s │ %-35s │ ${time_color}%7d ms${NC} │\n" "$rank" "$dns_name" "$ip" "$avg"
            rank=$((rank + 1))
        fi
    done

    # Check if any IPv6 servers were displayed
    ipv6_displayed=$(echo -e "$SORTED_RESULTS" | while IFS='|' read -r avg dns_name ip; do
        [ -z "$avg" ] && continue
        if is_ipv6_dns "$dns_name"; then
            echo "1"
            break
        fi
    done)

    if [ -z "$ipv6_displayed" ]; then
        echo -e "│      │ No IPv6 DNS servers working          │                                     │           │"
    fi

    echo -e "└──────┴──────────────────────────────────────┴─────────────────────────────────────┴───────────┘"
    echo ""
fi

# Statistics
working_count=${#RESULT_NAMES[@]}
failed_count=${#FAILED_NAMES[@]}
total_tested=$((working_count + failed_count))

# Count IPv4 and IPv6 separately
ipv4_working=0
ipv6_working=0
for dns_name in "${RESULT_NAMES[@]}"; do
    if is_ipv6_dns "$dns_name"; then
        ipv6_working=$((ipv6_working + 1))
    else
        ipv4_working=$((ipv4_working + 1))
    fi
done

echo -e "${GREEN}Statistics:${NC}"
echo -e "  Total Tested: $total_tested"
echo -e "  Working: ${GREEN}$working_count${NC} (IPv4: ${ipv4_working}, IPv6: ${ipv6_working})"
echo -e "  Failed: ${RED}$failed_count${NC}"
echo ""

# Show the best DNS servers
best_dns=$(echo -e "$SORTED_RESULTS" | head -1)
best_ipv4=$(echo -e "$SORTED_RESULTS" | while IFS='|' read -r avg dns_name ip; do
    [ -z "$avg" ] && continue
    if ! is_ipv6_dns "$dns_name"; then
        echo "$avg|$dns_name|$ip"
        break
    fi
done)
best_ipv6=$(echo -e "$SORTED_RESULTS" | while IFS='|' read -r avg dns_name ip; do
    [ -z "$avg" ] && continue
    if is_ipv6_dns "$dns_name"; then
        echo "$avg|$dns_name|$ip"
        break
    fi
done)

if [ -n "$best_dns" ]; then
    IFS='|' read -r avg name ip <<< "$best_dns"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🏆 BEST DNS SERVER OVERALL: $name${NC}"
    echo -e "   IP Address: $ip"
    echo -e "   Average Response Time: ${GREEN}$avg ms${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
fi

if [ -n "$best_ipv4" ]; then
    IFS='|' read -r avg name ip <<< "$best_ipv4"
    echo -e "${GREEN}🥇 BEST IPv4 DNS SERVER: $name${NC}"
    echo -e "   IP Address: $ip"
    echo -e "   Average Response Time: ${GREEN}$avg ms${NC}"
    echo ""
fi

if [ -n "$best_ipv6" ]; then
    IFS='|' read -r avg name ip <<< "$best_ipv6"
    echo -e "${GREEN}🥇 BEST IPv6 DNS SERVER: $name${NC}"
    echo -e "   IP Address: $ip"
    echo -e "   Average Response Time: ${GREEN}$avg ms${NC}"
    echo ""
fi

# Show failed DNS servers if any
if [ ${#FAILED_NAMES[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}Failed/Unreachable DNS Servers:${NC}"
    echo -e "┌─────────────────────────────────────┬─────────────────────────────────────┐"
    echo -e "│ DNS Server                           │ IP Address                          │"
    echo -e "├─────────────────────────────────────┼─────────────────────────────────────┤"
    for i in "${!FAILED_NAMES[@]}"; do
        printf "│ %-36s │ %-35s │\n" "${FAILED_NAMES[$i]}" "${FAILED_IPS[$i]}"
    done
    echo -e "└─────────────────────────────────────┴─────────────────────────────────────┘"
fi

echo ""
echo -e "${YELLOW}Test completed!${NC}"
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}CONFIGURATION RECOMMENDATION FOR OPENWRT:${NC}"
echo ""

# Get top 2 best performing DNS servers
primary_dns=""
secondary_dns=""
count=0

echo -e "$SORTED_RESULTS" | head -2 | while IFS='|' read -r avg name ip; do
    [ -z "$avg" ] && continue
    if [ $count -eq 0 ]; then
        echo "PRIMARY|$ip|$name|$avg"
    else
        echo "SECONDARY|$ip|$name|$avg"
    fi
    count=$((count + 1))
done > "$DNS_TEMP_DIR/recommendations.txt"

if [ -f "$DNS_TEMP_DIR/recommendations.txt" ]; then
    primary_line=$(grep "^PRIMARY" "$DNS_TEMP_DIR/recommendations.txt" 2>/dev/null)
    secondary_line=$(grep "^SECONDARY" "$DNS_TEMP_DIR/recommendations.txt" 2>/dev/null)

    if [ -n "$primary_line" ]; then
        IFS='|' read -r _ primary_dns primary_name primary_time <<< "$primary_line"
        echo -e "For optimal performance, configure your DNS as:"
        echo -e "  Primary DNS:   ${GREEN}$primary_dns${NC} ($primary_name - ${primary_time}ms)"

        if [ -n "$secondary_line" ]; then
            IFS='|' read -r _ secondary_dns secondary_name secondary_time <<< "$secondary_line"
            echo -e "  Secondary DNS: ${GREEN}$secondary_dns${NC} ($secondary_name - ${secondary_time}ms)"
        fi
    fi
fi
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"

# DNS-PING CORRELATION TEST
echo ""
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                                DNS-PING CORRELATION ANALYSIS${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Testing ping latency for working DNS servers and calculating correlation score...${NC}"
echo ""

# Function to test ping latency (works for both IPv4 and IPv6)
test_ping() {
    local ip=$1
    local count=3

    # Modern ping command works for both IPv4 and IPv6
    if command -v ping &> /dev/null; then
        result=$(ping -c ${count} -W 1 -q "${ip}" 2>/dev/null | grep "avg" | awk -F'/' '{print $5}' 2>/dev/null)
        if [ -n "$result" ]; then
            # Convert to integer (remove decimal part)
            echo "${result%%.*}"
        else
            echo "9999"  # Failed ping
        fi
    else
        echo "9999"
    fi
}

MAX_PARALLEL=20

# Create temporary directory for ping results
PING_TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$DNS_TEMP_DIR" "$PING_TEMP_DIR"' EXIT

# Progress for correlation test
current=0
tested_count=${#RESULT_NAMES[@]}
job_count=0

echo -e "Testing ping latency for $tested_count working DNS servers..."
echo ""
echo -e "${YELLOW}Launching parallel ping tests (max $MAX_PARALLEL concurrent)...${NC}"

# Test ping for each working DNS server
for i in "${!RESULT_NAMES[@]}"; do
    dns_name="${RESULT_NAMES[$i]}"
    dns_time="${RESULT_AVGS[$i]}"
    ip="${RESULT_IPS[$i]}"
    current=$((current + 1))

    # Create temp file for this result (sanitize special characters)
    sanitized_name=$(echo "$dns_name" | tr '/ ' '__')
    temp_file="$PING_TEMP_DIR/${sanitized_name}.txt"

    # Launch ping test in background
    {
        printf "[%3d/%3d] Pinging %-35s (%s) ... \n" "$current" "$tested_count" "$dns_name" "$ip"

        ping_time=$(test_ping "$ip")

        if [ "$ping_time" == "9999" ]; then
            printf "[%3d/%3d] %-35s (%s): %sFAILED%s\n" "$current" "$tested_count" "$dns_name" "$ip" "${RED}" "${NC}"
            # Skip failed ping servers - don't store in correlation results
        else
            printf "[%3d/%3d] %-35s (%s): ${GREEN}%4d ms${NC}\n" "$current" "$tested_count" "$dns_name" "$ip" "$ping_time"

            # Calculate correlation score (weighted average)
            # DNS query time is more important (70%) than ping (30%)
            correlation_score=$(( (dns_time * 70 + ping_time * 30) / 100 ))

            # Save results to temp file
            echo "${correlation_score}|${dns_name}|${dns_time}|${ping_time}|${ip}" > "$temp_file"
        fi
    } &

    job_count=$((job_count + 1))

    # Limit parallel jobs
    if [ $job_count -ge $MAX_PARALLEL ]; then
        wait -n 2>/dev/null || wait  # wait -n not available in Bash 3.2, fallback to wait
        job_count=$((job_count - 1))
    fi
done

# Wait for all remaining background jobs
wait
echo -e "\n${GREEN}All ping tests completed!${NC}\n"

# Collect and sort correlation results
echo "Processing results..."
CORR_SORTED=""
for i in "${!RESULT_NAMES[@]}"; do
    dns_name="${RESULT_NAMES[$i]}"
    sanitized_name=$(echo "$dns_name" | tr '/ ' '__')
    temp_file="$PING_TEMP_DIR/${sanitized_name}.txt"
    if [ -f "$temp_file" ]; then
        CORR_SORTED="${CORR_SORTED}$(cat "$temp_file")\n"
    fi
done
CORR_SORTED=$(echo -e "$CORR_SORTED" | sort -t'|' -k1 -n)

# Display IPv4 Correlation Results
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    IPv4 DNS-PING CORRELATION RESULTS                              ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}IPv4 DNS-Ping Correlation (Best → Worst):${NC}"
echo -e "┌──────┬──────────────────────────────────────┬─────────────────────────────────────┬──────────┬──────────┬────────────┬──────────────┐"
echo -e "│ Rank │ DNS Server                           │ IP Address                          │ DNS (ms) │ Ping(ms) │ Difference │ Score        │"
echo -e "├──────┼──────────────────────────────────────┼─────────────────────────────────────┼──────────┼──────────┼────────────┼──────────────┤"

rank=1
ipv4_corr_count=0
echo -e "$CORR_SORTED" | while IFS='|' read -r score dns_name dns_time ping_time ip; do
    [ -z "$score" ] && continue
    if ! is_ipv6_dns "$dns_name"; then
        # Calculate difference
        diff=$((ping_time - dns_time))
        ping_display="${ping_time}"

        # Color code the difference
        if [ $diff -lt 0 ]; then
            diff_color="${GREEN}"  # Ping faster than DNS (unusual but good)
        elif [ $diff -lt 50 ]; then
            diff_color="${GREEN}"  # Good correlation
        elif [ $diff -lt 150 ]; then
            diff_color="${YELLOW}" # Moderate difference
        else
            diff_color="${RED}"    # Poor correlation
        fi

        # Color code the score
        if [ "$score" -lt 50 ]; then
            score_color="${GREEN}"  # Excellent
        elif [ "$score" -lt 100 ]; then
            score_color="${YELLOW}" # Good
        else
            score_color="${RED}"    # Poor
        fi

        printf "│ %-4d │ %-36s │ %-35s │ %8s │ %8s │ ${diff_color}%10s${NC} │ ${score_color}%12d${NC} │\n" \
               "$rank" "$dns_name" "$ip" "$dns_time" "$ping_display" "$diff" "$score"

        rank=$((rank + 1))
        ipv4_corr_count=$((ipv4_corr_count + 1))
    fi
done

# Check if any IPv4 correlation results were displayed
ipv4_corr_displayed=$(echo -e "$CORR_SORTED" | while IFS='|' read -r score dns_name dns_time ping_time ip; do
    [ -z "$score" ] && continue
    if ! is_ipv6_dns "$dns_name"; then
        echo "1"
        break
    fi
done)

if [ -z "$ipv4_corr_displayed" ]; then
    echo -e "│      │ No IPv4 DNS servers with ping data  │                                     │          │          │            │              │"
fi

echo -e "└──────┴──────────────────────────────────────┴─────────────────────────────────────┴──────────┴──────────┴────────────┴──────────────┘"
echo ""

# Display IPv6 Correlation Results
if [ $IPV6_ENABLED -eq 1 ]; then
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    IPv6 DNS-PING CORRELATION RESULTS                              ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}IPv6 DNS-Ping Correlation (Best → Worst):${NC}"
    echo -e "┌──────┬──────────────────────────────────────┬─────────────────────────────────────┬──────────┬──────────┬────────────┬──────────────┐"
    echo -e "│ Rank │ DNS Server                           │ IP Address                          │ DNS (ms) │ Ping(ms) │ Difference │ Score        │"
    echo -e "├──────┼──────────────────────────────────────┼─────────────────────────────────────┼──────────┼──────────┼────────────┼──────────────┤"

    rank=1
    echo -e "$CORR_SORTED" | while IFS='|' read -r score dns_name dns_time ping_time ip; do
        [ -z "$score" ] && continue
        if is_ipv6_dns "$dns_name"; then
            # Calculate difference
            diff=$((ping_time - dns_time))
            ping_display="${ping_time}"

            # Color code the difference
            if [ $diff -lt 0 ]; then
                diff_color="${GREEN}"  # Ping faster than DNS (unusual but good)
            elif [ $diff -lt 50 ]; then
                diff_color="${GREEN}"  # Good correlation
            elif [ $diff -lt 150 ]; then
                diff_color="${YELLOW}" # Moderate difference
            else
                diff_color="${RED}"    # Poor correlation
            fi

            # Color code the score
            if [ "$score" -lt 50 ]; then
                score_color="${GREEN}"  # Excellent
            elif [ "$score" -lt 100 ]; then
                score_color="${YELLOW}" # Good
            else
                score_color="${RED}"    # Poor
            fi

            printf "│ %-4d │ %-36s │ %-35s │ %8s │ %8s │ ${diff_color}%10s${NC} │ ${score_color}%12d${NC} │\n" \
                   "$rank" "$dns_name" "$ip" "$dns_time" "$ping_display" "$diff" "$score"

            rank=$((rank + 1))
        fi
    done

    # Check if any IPv6 correlation results were displayed
    ipv6_corr_displayed=$(echo -e "$CORR_SORTED" | while IFS='|' read -r score dns_name dns_time ping_time ip; do
        [ -z "$score" ] && continue
        if is_ipv6_dns "$dns_name"; then
            echo "1"
            break
        fi
    done)

    if [ -z "$ipv6_corr_displayed" ]; then
        echo -e "│      │ No IPv6 DNS servers with ping data  │                                     │          │          │            │              │"
    fi

    echo -e "└──────┴──────────────────────────────────────┴─────────────────────────────────────┴──────────┴──────────┴────────────┴──────────────┘"
    echo ""
fi

echo ""
echo -e "${GREEN}Score Calculation:${NC}"
echo -e "  Score = (DNS Query Time × 70% + Ping Latency × 30%)"
echo -e "  Lower score = Better overall performance"
echo ""

# Find best correlation results
best_ipv4_corr=$(echo -e "$CORR_SORTED" | while IFS='|' read -r score dns_name dns_time ping_time ip; do
    [ -z "$score" ] && continue
    if ! is_ipv6_dns "$dns_name"; then
        echo "$score|$dns_name|$dns_time|$ping_time|$ip"
        break
    fi
done)

best_ipv6_corr=$(echo -e "$CORR_SORTED" | while IFS='|' read -r score dns_name dns_time ping_time ip; do
    [ -z "$score" ] && continue
    if is_ipv6_dns "$dns_name"; then
        echo "$score|$dns_name|$dns_time|$ping_time|$ip"
        break
    fi
done)

if [ -n "$best_ipv4_corr" ]; then
    IFS='|' read -r score name dns_time ping_time ip <<< "$best_ipv4_corr"
    echo -e "${GREEN}🥇 BEST IPv4 DNS SERVER (DNS+Network Performance):${NC}"
    echo -e "   Server: $name"
    echo -e "   IP: $ip"
    echo -e "   DNS Query: ${GREEN}${dns_time}ms${NC}, Ping: ${GREEN}${ping_time}ms${NC}, Score: ${GREEN}${score}${NC}"
    echo ""
fi

if [ -n "$best_ipv6_corr" ]; then
    IFS='|' read -r score name dns_time ping_time ip <<< "$best_ipv6_corr"
    echo -e "${GREEN}🥇 BEST IPv6 DNS SERVER (DNS+Network Performance):${NC}"
    echo -e "   Server: $name"
    echo -e "   IP: $ip"
    echo -e "   DNS Query: ${GREEN}${dns_time}ms${NC}, Ping: ${GREEN}${ping_time}ms${NC}, Score: ${GREEN}${score}${NC}"
    echo ""
fi

echo -e "${YELLOW}Analysis complete!${NC}"
