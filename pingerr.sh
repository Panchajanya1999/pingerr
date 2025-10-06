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
        ipv6_addr=$(ip -6 addr show scope global | grep -oP '(?<=inet6\s)[\da-f:]+' | head -1)
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
        echo -e "${YELLOW}✗ IPv6 connectivity test failed${NC}"
        echo -e "${YELLOW}  IPv6 DNS servers will be skipped in this test${NC}"
        echo ""
        return 1
    fi
}

# IPv6 support flag
IPV6_ENABLED=0
check_ipv6_connectivity && IPV6_ENABLED=1

# DNS Servers to test (IPv4)
declare -A DNS_SERVERS_IPV4=(
    ["Google-Primary"]="8.8.8.8"
    ["Google-Secondary"]="8.8.4.4"
    ["Cloudflare-Primary"]="1.1.1.1"
    ["Cloudflare-Secondary"]="1.0.0.1"
    ["Cloudflare-Family-Primary"]="1.1.1.3"
    ["Cloudflare-Family-Secondary"]="1.0.0.3"
    ["Quad9-Primary"]="9.9.9.9"
    ["Quad9-Secondary"]="149.112.112.112"
    ["Quad9-Secured"]="9.9.9.11"
    ["OpenDNS-Primary"]="208.67.222.222"
    ["OpenDNS-Secondary"]="208.67.220.220"
    ["OpenDNS-Family-Primary"]="208.67.222.123"
    ["OpenDNS-Family-Secondary"]="208.67.220.123"
    ["DNS.SB-Primary"]="185.222.222.222"
    ["DNS.SB-Secondary"]="45.11.45.11"
    ["NextDNS-Primary"]="45.90.28.39"
    ["NextDNS-Secondary"]="45.90.30.39"
    ["AdGuard-Primary"]="94.140.14.14"
    ["AdGuard-Secondary"]="94.140.15.15"
    ["AdGuard-Family-Primary"]="94.140.14.15"
    ["AdGuard-Family-Secondary"]="94.140.15.16"
    ["CleanBrowsing-Primary"]="185.228.168.9"
    ["CleanBrowsing-Secondary"]="185.228.169.9"
    ["CleanBrowsing-Family"]="185.228.168.168"
    ["ControlD-Primary"]="76.76.2.0"
    ["ControlD-Secondary"]="76.76.10.0"
    ["ControlD-Malware"]="76.76.2.1"
    ["RethinkDNS-Primary"]="149.112.121.10"
    ["RethinkDNS-Secondary"]="149.112.122.10"
    ["OpenBLD"]="46.151.208.154"
    ["FlashStart-Primary"]="185.236.104.104"
    ["FlashStart-Secondary"]="185.236.105.105"
    ["Mullvad-Primary"]="194.242.2.2"
    ["Mullvad-Secondary"]="194.242.2.3"
    ["Mullvad-Base-Primary"]="194.242.2.4"
    ["Mullvad-Base-Secondary"]="194.242.2.5"
    ["IIJ-Primary"]="103.2.57.5"
    ["IIJ-Secondary"]="103.2.58.5"
    ["Foundation-Applied-Privacy"]="37.252.185.229"
    ["Foundation-Applied-Privacy2"]="37.252.185.232"
    ["Restena"]="158.64.1.29"
    ["DNS-for-Family-Primary"]="94.130.180.225"
    ["DNS-for-Family-Secondary"]="78.47.64.161"
    ["Canadian-Shield-Primary"]="149.112.121.10"
    ["Canadian-Shield-Secondary"]="149.112.122.10"
    ["Digitale-Gesellschaft-Primary"]="185.95.218.42"
    ["Digitale-Gesellschaft-Secondary"]="185.95.218.43"
    ["Switch-Primary"]="130.59.31.248"
    ["Switch-Secondary"]="130.59.31.251"
    ["DNSPod-Primary"]="119.29.29.29"
    ["DNSPod-Secondary"]="119.28.28.28"
    ["AliDNS-Primary"]="223.5.5.5"
    ["AliDNS-Secondary"]="223.6.6.6"
    ["LibreDNS"]="88.198.92.222"
    ["UncensoredDNS-Primary"]="91.239.100.100"
    ["UncensoredDNS-Secondary"]="89.233.43.71"
    ["DNS0.EU-Primary"]="193.110.81.0"
    ["DNS0.EU-Secondary"]="185.253.5.0"
    ["360-Primary"]="101.226.4.6"
    ["360-Secondary"]="180.163.249.75"
    ["Comodo-Primary"]="8.26.56.26"
    ["Comodo-Secondary"]="8.20.247.20"
    ["Neustar-Primary"]="156.154.70.1"
    ["Neustar-Secondary"]="156.154.71.1"
    ["Verisign-Primary"]="64.6.64.6"
    ["Verisign-Secondary"]="64.6.65.6"
    ["Yandex-Primary"]="77.88.8.8"
    ["Yandex-Secondary"]="77.88.8.1"
    ["Yandex-Safe-Primary"]="77.88.8.88"
    ["Yandex-Safe-Secondary"]="77.88.8.2"
    ["Hurricane-Electric"]="74.82.42.42"
    ["puntCAT"]="109.69.8.51"
    ["Freenom"]="80.80.80.80"
    ["Level3-Primary"]="209.244.0.3"
    ["Level3-Secondary"]="209.244.0.4"
)

# DNS Servers to test (IPv6)
declare -A DNS_SERVERS_IPV6=(
    ["Google-Primary-v6"]="2001:4860:4860::8888"
    ["Google-Secondary-v6"]="2001:4860:4860::8844"
    ["Cloudflare-Primary-v6"]="2606:4700:4700::1111"
    ["Cloudflare-Secondary-v6"]="2606:4700:4700::1001"
    ["Cloudflare-Family-Primary-v6"]="2606:4700:4700::1113"
    ["Cloudflare-Family-Secondary-v6"]="2606:4700:4700::1003"
    ["Quad9-Primary-v6"]="2620:fe::fe"
    ["Quad9-Secondary-v6"]="2620:fe::9"
    ["Quad9-Secured-v6"]="2620:fe::11"
    ["OpenDNS-Primary-v6"]="2620:119:35::35"
    ["OpenDNS-Secondary-v6"]="2620:119:53::53"
    ["OpenDNS-Family-v6"]="2620:119:35::123"
    ["AdGuard-Primary-v6"]="2a10:50c0::ad1:ff"
    ["AdGuard-Secondary-v6"]="2a10:50c0::ad2:ff"
    ["AdGuard-Family-Primary-v6"]="2a10:50c0::bad1:ff"
    ["AdGuard-Family-Secondary-v6"]="2a10:50c0::bad2:ff"
    ["DNS.SB-Primary-v6"]="2a09::"
    ["DNS.SB-Secondary-v6"]="2a11::"
    ["NextDNS-Primary-v6"]="2a07:a8c0::"
    ["NextDNS-Secondary-v6"]="2a07:a8c1::"
    ["CleanBrowsing-Primary-v6"]="2a0d:2a00:1::"
    ["CleanBrowsing-Secondary-v6"]="2a0d:2a00:2::"
    ["CleanBrowsing-Family-v6"]="2a0d:2a00:1::1"
    ["ControlD-Primary-v6"]="2606:1a40::"
    ["ControlD-Secondary-v6"]="2606:1a40:1::"
    ["ControlD-Malware-v6"]="2606:1a40::1"
    ["Mullvad-Primary-v6"]="2a07:e340::2"
    ["Mullvad-Secondary-v6"]="2a07:e340::3"
    ["Mullvad-Base-Primary-v6"]="2a07:e340::4"
    ["Mullvad-Base-Secondary-v6"]="2a07:e340::5"
    ["Digitale-Gesellschaft-Primary-v6"]="2a05:fc84::42"
    ["Digitale-Gesellschaft-Secondary-v6"]="2a05:fc84::43"
    ["Switch-Primary-v6"]="2001:620:0:ff::2"
    ["Switch-Secondary-v6"]="2001:620:0:ff::3"
    ["UncensoredDNS-Primary-v6"]="2001:67c:28a4::"
    ["UncensoredDNS-Secondary-v6"]="2a01:3a0:53:53::"
    ["DNS0.EU-Primary-v6"]="2a0f:fc80::"
    ["DNS0.EU-Secondary-v6"]="2a0f:fc81::"
    ["AliDNS-Primary-v6"]="2400:3200::1"
    ["AliDNS-Secondary-v6"]="2400:3200:baba::1"
    ["Yandex-Primary-v6"]="2a02:6b8::feed:0ff"
    ["Yandex-Secondary-v6"]="2a02:6b8:0:1::feed:0ff"
    ["Yandex-Safe-Primary-v6"]="2a02:6b8::feed:bad"
    ["Yandex-Safe-Secondary-v6"]="2a02:6b8:0:1::feed:bad"
    ["Hurricane-Electric-v6"]="2001:470:20::2"
    ["Freenom-Primary-v6"]="2a02:fe80:1010::1"
    ["Freenom-Secondary-v6"]="2a02:fe80:1010::2"
    ["OpenNIC-Primary-v6"]="2a05:dfc7:5::53"
    ["OpenNIC-Secondary-v6"]="2a05:dfc7:5::5353"
    ["Restena-v6"]="2001:a18:1::29"
    ["DNS-for-Family-Primary-v6"]="2a01:4f8:151:64e6::225"
    ["DNS-for-Family-Secondary-v6"]="2a01:4f8:141:316d::161"
    ["CleanBrowsing-Security-v6"]="2a0d:2a00:3::"
    ["CleanBrowsing-Adult-v6"]="2a0d:2a00:1::2"
    ["CleanBrowsing-Family-Secondary-v6"]="2a0d:2a00:2::2"
    ["IIJ-Primary-v6"]="2001:240:bb8a:10::1"
    ["IIJ-Secondary-v6"]="2001:240:bb8a:20::1"
    ["Comodo-Primary-v6"]="2606:4700:50::adf5:6f3"
    ["Comodo-Secondary-v6"]="2606:4700:50::adf5:6f4"
    ["Neustar-Primary-v6"]="2620:74:1b::1:1"
    ["Neustar-Secondary-v6"]="2620:74:1c::2:2"
    ["Verisign-Primary-v6"]="2620:74:1b::1:1"
    ["Verisign-Secondary-v6"]="2620:74:1c::2:2"
)

# Merge DNS servers based on IPv6 availability
declare -A DNS_SERVERS
for key in "${!DNS_SERVERS_IPV4[@]}"; do
    DNS_SERVERS["$key"]="${DNS_SERVERS_IPV4[$key]}"
done

if [ $IPV6_ENABLED -eq 1 ]; then
    echo -e "${GREEN}IPv6 is enabled - including IPv6 DNS servers in tests${NC}"
    echo ""
    for key in "${!DNS_SERVERS_IPV6[@]}"; do
        DNS_SERVERS["$key"]="${DNS_SERVERS_IPV6[$key]}"
    done
else
    echo -e "${YELLOW}IPv6 is disabled - testing IPv4 DNS servers only${NC}"
    echo ""
fi

# Results arrays
declare -A DNS_RESULTS
declare -A DNS_FAILED

# Check for required commands
if ! command -v dig &> /dev/null; then
    echo -e "${RED}Error: 'dig' not found. Please install dnsutils/bind-tools.${NC}"
    echo "On OpenWRT: opkg install bind-dig"
    echo "On Debian/Ubuntu: apt-get install dnsutils"
    echo "On RHEL/CentOS: yum install bind-utils"
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

# Header
total_tests=$((${#DNS_SERVERS[@]} * TEST_COUNT))
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}      DNS Speed Test - Testing ${#DNS_SERVERS[@]} DNS Servers${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Total DNS Servers: ${#DNS_SERVERS[@]} (IPv4: ${#DNS_SERVERS_IPV4[@]}, IPv6: ${#DNS_SERVERS_IPV6[@]})"
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
total=${#DNS_SERVERS[@]}
dns_job_count=0

# Test each DNS server
echo -e "${YELLOW}Starting DNS tests with parallel execution (max $MAX_DNS_PARALLEL concurrent)...${NC}"
echo ""

for dns_name in "${!DNS_SERVERS[@]}"; do
    dns_ip="${DNS_SERVERS[$dns_name]}"
    current=$((current + 1))

    # Create temp file for this DNS server result (sanitize special characters)
    sanitized_name="${dns_name//[\/\ ]/_}"
    dns_temp_file="$DNS_TEMP_DIR/${sanitized_name}.txt"

    # Launch DNS test in background
    {
        # Progress indicator
        printf "[%3d/%3d] Testing %-35s (%s) ... \n" "$current" "$total" "$dns_name" "$dns_ip"

        # Store results for this DNS server
        times=""
        failed=0

        # Test multiple times with different domains
        for i in $(seq 1 $TEST_COUNT); do
            # Rotate through test domains
            domain_index=$(( (i - 1) % ${#TEST_DOMAINS[@]} ))
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
        wait -n  # Wait for at least one job to finish
        dns_job_count=$((dns_job_count - 1))
    fi
done

# Wait for all remaining DNS test jobs
wait
echo -e "\n${GREEN}All DNS tests completed!${NC}\n"

# Collect results from temp files
echo "Processing DNS test results..."
for dns_name in "${!DNS_SERVERS[@]}"; do
    sanitized_name="${dns_name//[\/\ ]/_}"
    dns_temp_file="$DNS_TEMP_DIR/${sanitized_name}.txt"
    if [ -f "$dns_temp_file" ]; then
        IFS='|' read -r status name data1 data2 < "$dns_temp_file"
        if [ "$status" == "FAILED" ]; then
            DNS_FAILED["$name"]="$data1"  # name -> ip
        else
            DNS_RESULTS["$name"]="$data1|$data2"  # name -> avg|ip
        fi
    fi
done

# Function to check if DNS is IPv6
is_ipv6_dns() {
    local dns_name=$1
    [[ "$dns_name" == *"-v6" ]]
}

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                                    COMPLETE RESULTS (BEST → WORST)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

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
for dns_name in $(for key in "${!DNS_RESULTS[@]}"; do
    if ! is_ipv6_dns "$key"; then
        echo "$key|${DNS_RESULTS[$key]}"
    fi
done | sort -t'|' -k2 -n | cut -d'|' -f1); do
    IFS='|' read -r avg ip <<< "${DNS_RESULTS[$dns_name]}"
    
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
done

if [ $ipv4_count -eq 0 ]; then
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
    ipv6_count=0
    for dns_name in $(for key in "${!DNS_RESULTS[@]}"; do
        if is_ipv6_dns "$key"; then
            echo "$key|${DNS_RESULTS[$key]}"
        fi
    done | sort -t'|' -k2 -n | cut -d'|' -f1); do
        IFS='|' read -r avg ip <<< "${DNS_RESULTS[$dns_name]}"
        
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
        ipv6_count=$((ipv6_count + 1))
    done

    if [ $ipv6_count -eq 0 ]; then
        echo -e "│      │ No IPv6 DNS servers working          │                                     │           │"
    fi

    echo -e "└──────┴──────────────────────────────────────┴─────────────────────────────────────┴───────────┘"
    echo ""
fi

# Statistics
working_count=${#DNS_RESULTS[@]}
failed_count=${#DNS_FAILED[@]}
total_tested=$((working_count + failed_count))

# Count IPv4 and IPv6 separately
ipv4_working=0
ipv6_working=0
for dns_name in "${!DNS_RESULTS[@]}"; do
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

# Show the best DNS server overall
best_dns=$(for key in "${!DNS_RESULTS[@]}"; do
    echo "$key|${DNS_RESULTS[$key]}"
done | sort -t'|' -k2 -n | head -1)

# Show the best IPv4 DNS server
best_ipv4=$(for key in "${!DNS_RESULTS[@]}"; do
    if ! is_ipv6_dns "$key"; then
        echo "$key|${DNS_RESULTS[$key]}"
    fi
done | sort -t'|' -k2 -n | head -1)

# Show the best IPv6 DNS server
best_ipv6=$(for key in "${!DNS_RESULTS[@]}"; do
    if is_ipv6_dns "$key"; then
        echo "$key|${DNS_RESULTS[$key]}"
    fi
done | sort -t'|' -k2 -n | head -1)

if [ -n "$best_dns" ]; then
    IFS='|' read -r name avg ip <<< "$best_dns"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🏆 BEST DNS SERVER OVERALL: $name${NC}"
    echo -e "   IP Address: $ip"
    echo -e "   Average Response Time: ${GREEN}$avg ms${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
fi

if [ -n "$best_ipv4" ]; then
    IFS='|' read -r name avg ip <<< "$best_ipv4"
    echo -e "${GREEN}🥇 BEST IPv4 DNS SERVER: $name${NC}"
    echo -e "   IP Address: $ip"
    echo -e "   Average Response Time: ${GREEN}$avg ms${NC}"
    echo ""
fi

if [ -n "$best_ipv6" ]; then
    IFS='|' read -r name avg ip <<< "$best_ipv6"
    echo -e "${GREEN}🥇 BEST IPv6 DNS SERVER: $name${NC}"
    echo -e "   IP Address: $ip"
    echo -e "   Average Response Time: ${GREEN}$avg ms${NC}"
    echo ""
fi

# Show failed DNS servers if any
if [ ${#DNS_FAILED[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}Failed/Unreachable DNS Servers:${NC}"
    echo -e "┌─────────────────────────────────────┬─────────────────────────────────────┐"
    echo -e "│ DNS Server                           │ IP Address                          │"
    echo -e "├─────────────────────────────────────┼─────────────────────────────────────┤"
    for dns_name in "${!DNS_FAILED[@]}"; do
        printf "│ %-36s │ %-35s │\n" "$dns_name" "${DNS_FAILED[$dns_name]}"
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
best_servers=$(for key in "${!DNS_RESULTS[@]}"; do
    echo "$key|${DNS_RESULTS[$key]}"
done | sort -t'|' -k2 -n | head -2)

primary_dns=""
secondary_dns=""
count=0

while IFS= read -r line; do
    IFS='|' read -r name avg ip <<< "$line"
    if [ $count -eq 0 ]; then
        primary_dns="$ip"
        primary_name="$name"
        primary_time="$avg"
    else
        secondary_dns="$ip"
        secondary_name="$name"
        secondary_time="$avg"
    fi
    count=$((count + 1))
done <<< "$best_servers"

if [ -n "$primary_dns" ]; then
    echo -e "For optimal performance, configure your DNS as:"
    echo -e "  Primary DNS:   ${GREEN}$primary_dns${NC} ($primary_name - ${primary_time}ms)"
    if [ -n "$secondary_dns" ]; then
        echo -e "  Secondary DNS: ${GREEN}$secondary_dns${NC} ($secondary_name - ${secondary_time}ms)"
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

# Store correlation results
declare -A CORRELATION_RESULTS

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

# Create temporary directory for results
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Progress for correlation test
current=0
tested_count=${#DNS_RESULTS[@]}
job_count=0

echo -e "Testing ping latency for $tested_count working DNS servers..."
echo ""
echo -e "${YELLOW}Launching parallel ping tests (max $MAX_PARALLEL concurrent)...${NC}"

# Test ping for each working DNS server
for dns_name in "${!DNS_RESULTS[@]}"; do
    IFS='|' read -r dns_time ip <<< "${DNS_RESULTS[$dns_name]}"
    current=$((current + 1))

    # Create temp file for this result (sanitize special characters)
    sanitized_name="${dns_name//[\/\ ]/_}"
    temp_file="$TEMP_DIR/${sanitized_name}.txt"

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
            echo "${dns_name}|${correlation_score}|${dns_time}|${ping_time}|${ip}" > "$temp_file"
        fi
    } &

    job_count=$((job_count + 1))

    # Limit parallel jobs
    if [ $job_count -ge $MAX_PARALLEL ]; then
        wait -n  # Wait for at least one job to finish
        job_count=$((job_count - 1))
    fi
done

# Wait for all remaining background jobs
wait
echo -e "\n${GREEN}All ping tests completed!${NC}\n"

# Collect results from temp files
echo "Processing results..."
for dns_name in "${!DNS_RESULTS[@]}"; do
    sanitized_name="${dns_name//[\/\ ]/_}"
    temp_file="$TEMP_DIR/${sanitized_name}.txt"
    if [ -f "$temp_file" ]; then
        IFS='|' read -r name score dns_time ping_time ip < "$temp_file"
        CORRELATION_RESULTS["$name"]="${score}|${dns_time}|${ping_time}|${ip}"
    fi
done

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
for dns_name in $(for key in "${!CORRELATION_RESULTS[@]}"; do
    if ! is_ipv6_dns "$key"; then
        echo "$key|${CORRELATION_RESULTS[$key]}"
    fi
done | sort -t'|' -k2 -n | cut -d'|' -f1); do
    IFS='|' read -r score dns_time ping_time ip <<< "${CORRELATION_RESULTS[$dns_name]}"
    
    # Calculate difference
    if [ "$ping_time" == "9999" ]; then
        diff="N/A"
        ping_display="FAILED"
        diff_color="${RED}"
    else
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
done

if [ $ipv4_corr_count -eq 0 ]; then
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
    ipv6_corr_count=0
    for dns_name in $(for key in "${!CORRELATION_RESULTS[@]}"; do
        if is_ipv6_dns "$key"; then
            echo "$key|${CORRELATION_RESULTS[$key]}"
        fi
    done | sort -t'|' -k2 -n | cut -d'|' -f1); do
        IFS='|' read -r score dns_time ping_time ip <<< "${CORRELATION_RESULTS[$dns_name]}"
        
        # Calculate difference
        if [ "$ping_time" == "9999" ]; then
            diff="N/A"
            ping_display="FAILED"
            diff_color="${RED}"
        else
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
        ipv6_corr_count=$((ipv6_corr_count + 1))
    done

    if [ $ipv6_corr_count -eq 0 ]; then
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

# Find best correlation overall
best_correlation=$(for key in "${!CORRELATION_RESULTS[@]}"; do
    echo "$key|${CORRELATION_RESULTS[$key]}"
done | sort -t'|' -k2 -n | head -1)

# Find best IPv4 correlation
best_ipv4_corr=$(for key in "${!CORRELATION_RESULTS[@]}"; do
    if ! is_ipv6_dns "$key"; then
        echo "$key|${CORRELATION_RESULTS[$key]}"
    fi
done | sort -t'|' -k2 -n | head -1)

# Find best IPv6 correlation
best_ipv6_corr=$(for key in "${!CORRELATION_RESULTS[@]}"; do
    if is_ipv6_dns "$key"; then
        echo "$key|${CORRELATION_RESULTS[$key]}"
    fi
done | sort -t'|' -k2 -n | head -1)

if [ -n "$best_ipv4_corr" ]; then
    IFS='|' read -r name score dns_time ping_time ip <<< "$best_ipv4_corr"
    echo -e "${GREEN}🥇 BEST IPv4 DNS SERVER (DNS+Network Performance):${NC}"
    echo -e "   Server: $name"
    echo -e "   IP: $ip"
    echo -e "   DNS Query: ${GREEN}${dns_time}ms${NC}, Ping: ${GREEN}${ping_time}ms${NC}, Score: ${GREEN}${score}${NC}"
    echo ""
fi

if [ -n "$best_ipv6_corr" ]; then
    IFS='|' read -r name score dns_time ping_time ip <<< "$best_ipv6_corr"
    echo -e "${GREEN}🥇 BEST IPv6 DNS SERVER (DNS+Network Performance):${NC}"
    echo -e "   Server: $name"
    echo -e "   IP: $ip"
    echo -e "   DNS Query: ${GREEN}${dns_time}ms${NC}, Ping: ${GREEN}${ping_time}ms${NC}, Score: ${GREEN}${score}${NC}"
    echo ""
fi

echo -e "${YELLOW}Analysis complete!${NC}"
