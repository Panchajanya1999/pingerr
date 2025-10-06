#!/bin/ash
# shellcheck shell=dash

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

# DNS Speed Test Script for OpenWRT (ash shell compatible)
# Tests multiple DNS providers (IPv4 and IPv6) and finds the fastest one

# Color codes for output (using printf format for ash compatibility)
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[1;33m')
BLUE=$(printf '\033[0;34m')
CYAN=$(printf '\033[0;36m')
NC=$(printf '\033[0m') # No Color

# Number of tests per DNS server
TEST_COUNT=5

# Test domains (popular sites for comprehensive testing)
TEST_DOMAINS="google.com youtube.com facebook.com instagram.com chatgpt.com x.com whatsapp.com reddit.com wikipedia.org amazon.com tiktok.com pinterest.com cloudflare.com github.com netflix.com"

# Convert to list for counting
# shellcheck disable=SC2086
# Note: $TEST_DOMAINS intentionally unquoted to split into array
set -- $TEST_DOMAINS
TEST_DOMAIN_COUNT=$#

# Check for IPv6 connectivity
check_ipv6_connectivity() {
    printf '%bChecking IPv6 connectivity...%b\n' "${CYAN}" "${NC}"
    
    # Method 1: Check if device has IPv6 address
    if command -v ip >/dev/null 2>&1; then
        ipv6_addr=$(ip -6 addr show scope global 2>/dev/null | grep -o 'inet6 [0-9a-f:]*' | head -1 | awk '{print $2}')
        if [ -n "$ipv6_addr" ]; then
            printf '%b[+] IPv6 address found: %s%b\n' "${GREEN}" "$ipv6_addr" "${NC}"
        else
            printf '%b[!] No global IPv6 address found on device%b\n' "${YELLOW}" "${NC}"
        fi
    fi
    
    # Method 2: Try to ping Google's IPv6 DNS
    printf 'Testing IPv6 connectivity to Google DNS (2001:4860:4860::8888)...\n'
    if ping -c 2 -W 2 2001:4860:4860::8888 >/dev/null 2>&1; then
        printf '%b[+] IPv6 connectivity is working!%b\n' "${GREEN}" "${NC}"
        echo ""
        return 0
    else
        printf '%b[-] IPv6 connectivity not avaailable%b\n' "${YELLOW}" "${NC}"
        printf '%b    IPv6 DNS servers will be skipped in this test%b\n' "${YELLOW}" "${NC}"
        echo ""
        return 1
    fi
}

# IPv6 support flag
IPV6_ENABLED=0
if check_ipv6_connectivity; then
    IPV6_ENABLED=1
fi

# DNS Servers to test (IPv4) - format: "Name|IP"
DNS_SERVERS_IPV4="
Google-Primary|8.8.8.8
Google-Secondary|8.8.4.4
Cloudflare-Primary|1.1.1.1
Cloudflare-Secondary|1.0.0.1
Cloudflare-Family-Primary|1.1.1.3
Cloudflare-Family-Secondary|1.0.0.3
Quad9-Primary|9.9.9.9
Quad9-Secondary|149.112.112.112
Quad9-Secured|9.9.9.11
OpenDNS-Primary|208.67.222.222
OpenDNS-Secondary|208.67.220.220
OpenDNS-Family-Primary|208.67.222.123
OpenDNS-Family-Secondary|208.67.220.123
DNS.SB-Primary|185.222.222.222
DNS.SB-Secondary|45.11.45.11
NextDNS-Primary|45.90.28.39
NextDNS-Secondary|45.90.30.39
AdGuard-Primary|94.140.14.14
AdGuard-Secondary|94.140.15.15
AdGuard-Family-Primary|94.140.14.15
AdGuard-Family-Secondary|94.140.15.16
CleanBrowsing-Primary|185.228.168.9
CleanBrowsing-Secondary|185.228.169.9
CleanBrowsing-Family|185.228.168.168
ControlD-Primary|76.76.2.0
ControlD-Secondary|76.76.10.0
ControlD-Malware|76.76.2.1
RethinkDNS-Primary|149.112.121.10
RethinkDNS-Secondary|149.112.122.10
OpenBLD|46.151.208.154
FlashStart-Primary|185.236.104.104
FlashStart-Secondary|185.236.105.105
Mullvad-Primary|194.242.2.2
Mullvad-Secondary|194.242.2.3
Mullvad-Base-Primary|194.242.2.4
Mullvad-Base-Secondary|194.242.2.5
IIJ-Primary|103.2.57.5
IIJ-Secondary|103.2.58.5
Foundation-Applied-Privacy|37.252.185.229
Foundation-Applied-Privacy2|37.252.185.232
Restena|158.64.1.29
DNS-for-Family-Primary|94.130.180.225
DNS-for-Family-Secondary|78.47.64.161
Canadian-Shield-Primary|149.112.121.10
Canadian-Shield-Secondary|149.112.122.10
Digitale-Gesellschaft-Primary|185.95.218.42
Digitale-Gesellschaft-Secondary|185.95.218.43
Switch-Primary|130.59.31.248
Switch-Secondary|130.59.31.251
DNSPod-Primary|119.29.29.29
DNSPod-Secondary|119.28.28.28
AliDNS-Primary|223.5.5.5
AliDNS-Secondary|223.6.6.6
LibreDNS|88.198.92.222
UncensoredDNS-Primary|91.239.100.100
UncensoredDNS-Secondary|89.233.43.71
DNS0.EU-Primary|193.110.81.0
DNS0.EU-Secondary|185.253.5.0
360-Primary|101.226.4.6
360-Secondary|180.163.249.75
Comodo-Primary|8.26.56.26
Comodo-Secondary|8.20.247.20
Neustar-Primary|156.154.70.1
Neustar-Secondary|156.154.71.1
Verisign-Primary|64.6.64.6
Verisign-Secondary|64.6.65.6
Yandex-Primary|77.88.8.8
Yandex-Secondary|77.88.8.1
Yandex-Safe-Primary|77.88.8.88
Yandex-Safe-Secondary|77.88.8.2
Hurricane-Electric|74.82.42.42
puntCAT|109.69.8.51
Freenom|80.80.80.80
Level3-Primary|209.244.0.3
Level3-Secondary|209.244.0.4
"

# DNS Servers to test (IPv6) - format: "Name|IP"
DNS_SERVERS_IPV6="
Google-Primary-v6|2001:4860:4860::8888
Google-Secondary-v6|2001:4860:4860::8844
Cloudflare-Primary-v6|2606:4700:4700::1111
Cloudflare-Secondary-v6|2606:4700:4700::1001
Cloudflare-Family-Primary-v6|2606:4700:4700::1113
Cloudflare-Family-Secondary-v6|2606:4700:4700::1003
Quad9-Primary-v6|2620:fe::fe
Quad9-Secondary-v6|2620:fe::9
Quad9-Secured-v6|2620:fe::11
OpenDNS-Primary-v6|2620:119:35::35
OpenDNS-Secondary-v6|2620:119:53::53
OpenDNS-Family-v6|2620:119:35::123
AdGuard-Primary-v6|2a10:50c0::ad1:ff
AdGuard-Secondary-v6|2a10:50c0::ad2:ff
AdGuard-Family-Primary-v6|2a10:50c0::bad1:ff
AdGuard-Family-Secondary-v6|2a10:50c0::bad2:ff
DNS.SB-Primary-v6|2a09::
DNS.SB-Secondary-v6|2a11::
NextDNS-Primary-v6|2a07:a8c0::
NextDNS-Secondary-v6|2a07:a8c1::
CleanBrowsing-Primary-v6|2a0d:2a00:1::
CleanBrowsing-Secondary-v6|2a0d:2a00:2::
CleanBrowsing-Family-v6|2a0d:2a00:1::1
ControlD-Primary-v6|2606:1a40::
ControlD-Secondary-v6|2606:1a40:1::
ControlD-Malware-v6|2606:1a40::1
Mullvad-Primary-v6|2a07:e340::2
Mullvad-Secondary-v6|2a07:e340::3
Mullvad-Base-Primary-v6|2a07:e340::4
Mullvad-Base-Secondary-v6|2a07:e340::5
Digitale-Gesellschaft-Primary-v6|2a05:fc84::42
Digitale-Gesellschaft-Secondary-v6|2a05:fc84::43
Switch-Primary-v6|2001:620:0:ff::2
Switch-Secondary-v6|2001:620:0:ff::3
UncensoredDNS-Primary-v6|2001:67c:28a4::
UncensoredDNS-Secondary-v6|2a01:3a0:53:53::
DNS0.EU-Primary-v6|2a0f:fc80::
DNS0.EU-Secondary-v6|2a0f:fc81::
AliDNS-Primary-v6|2400:3200::1
AliDNS-Secondary-v6|2400:3200:baba::1
Yandex-Primary-v6|2a02:6b8::feed:0ff
Yandex-Secondary-v6|2a02:6b8:0:1::feed:0ff
Yandex-Safe-Primary-v6|2a02:6b8::feed:bad
Yandex-Safe-Secondary-v6|2a02:6b8:0:1::feed:bad
Hurricane-Electric-v6|2001:470:20::2
Freenom-Primary-v6|2a02:fe80:1010::1
Freenom-Secondary-v6|2a02:fe80:1010::2
OpenNIC-Primary-v6|2a05:dfc7:5::53
OpenNIC-Secondary-v6|2a05:dfc7:5::5353
Restena-v6|2001:a18:1::29
DNS-for-Family-Primary-v6|2a01:4f8:151:64e6::225
DNS-for-Family-Secondary-v6|2a01:4f8:141:316d::161
CleanBrowsing-Security-v6|2a0d:2a00:3::
CleanBrowsing-Adult-v6|2a0d:2a00:1::2
CleanBrowsing-Family-Secondary-v6|2a0d:2a00:2::2
IIJ-Primary-v6|2001:240:bb8a:10::1
IIJ-Secondary-v6|2001:240:bb8a:20::1
Comodo-Primary-v6|2606:4700:50::adf5:6f3
Comodo-Secondary-v6|2606:4700:50::adf5:6f4
Neustar-Primary-v6|2620:74:1b::1:1
Neustar-Secondary-v6|2620:74:1c::2:2
"

# Merge DNS servers based on IPv6 availability
DNS_SERVERS="$DNS_SERVERS_IPV4"
DNS_IPV4_COUNT=$(echo "$DNS_SERVERS_IPV4" | grep -c -v "^$")
DNS_IPV6_COUNT=$(echo "$DNS_SERVERS_IPV6" | grep -c -v "^$")

if [ $IPV6_ENABLED -eq 1 ]; then
    printf '%bIPv6 is enabled - including IPv6 DNS servers in tests%b\n' "${GREEN}" "${NC}"
    echo ""
    DNS_SERVERS="${DNS_SERVERS}${DNS_SERVERS_IPV6}"
else
    printf '%bIPv6 is disabled - testing IPv4 DNS servers only%b\n' "${YELLOW}" "${NC}"
    echo ""
fi

# Check for required commands
if ! command -v dig >/dev/null 2>&1; then
    printf '%bError: %s not found. Please install dnsutils/bind-tools.%s\n' "${RED}" "'dig'" "${NC}"
    echo "On OpenWRT: opkg install bind-dig"
    echo "On Debian/Ubuntu: apt-get install dnsutils"
    echo "On RHEL/CentOS: yum install bind-utils"
    exit 1
fi

# Create temp files for results
RESULTS_FILE="/tmp/dns_results_$$"
FAILED_FILE="/tmp/dns_failed_$$"
CORRELATION_FILE="/tmp/dns_correlation_$$"

# Clean up temp files on exit
trap 'rm -f "$RESULTS_FILE" "$FAILED_FILE" "$CORRELATION_FILE"' EXIT

# Function to check if DNS is IPv6
is_ipv6_dns() {
    local dns_name=$1
    case "$dns_name" in
        *-v6) return 0 ;;
        *) return 1 ;;
    esac
}

# Function to count DNS servers
count_dns_servers() {
    echo "$DNS_SERVERS" | grep -c -v "^$"
}

# Function to get nth test domain
get_test_domain() {
    local index=$1
    local count=0
    for domain in $TEST_DOMAINS; do
        count=$((count + 1))
        if [ $count -eq "$index" ]; then
            echo "$domain"
            return
        fi
    done
    echo "google.com"  # fallback
}

# Function to test DNS response time
test_dns() {
    local dns_server=$1
    local domain=$2
    local timeout=2
    local result=""
    
    # Use dig to test DNS server (works for both IPv4 and IPv6)
    if command -v dig >/dev/null 2>&1; then
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
    local val
    
    for val in "$@"; do
        if [ "$val" != "0" ] && [ "$val" != "" ]; then
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

# Function to test ping latency (works for both IPv4 and IPv6)
test_ping() {
    local ip=$1
    local count=3
    local result=""
    
    # Modern ping command works for both IPv4 and IPv6
    if command -v ping >/dev/null 2>&1; then
        result=$(ping -c ${count} -W 1 -q "${ip}" 2>/dev/null | grep "avg" | awk -F'/' '{print $5}' 2>/dev/null)
        if [ -n "$result" ]; then
            # Convert to integer (remove decimal part)
            result=${result%%.*}
            echo "$result"
        else
            echo "9999"  # Failed ping
        fi
    else
        echo "9999"
    fi
}

# Count total DNS servers
DNS_COUNT=$(count_dns_servers)

# Header
total_tests=$((DNS_COUNT * TEST_COUNT))
printf '%b========================================================================%s\n' "${BLUE}" "${NC}"
printf '%b      DNS Speed Test - Testing %s DNS Servers%s\n' "${GREEN}" "${DNS_COUNT}" "${NC}"
printf '%b========================================================================%s\n' "${BLUE}" "${NC}"
echo ""
printf 'Total DNS Servers: %s (IPv4: %s, IPv6: %s)\n' "${DNS_COUNT}" "${DNS_IPV4_COUNT}" "${DNS_IPV6_COUNT}"
printf 'Tests per server: %s\n' "${TEST_COUNT}"
printf 'Total tests to run: %s\n' "${total_tests}"
printf 'Test domains: %s popular websites\n' "${TEST_DOMAIN_COUNT}"
echo ""
printf '%bThis will take a few minutes to complete...%s\n' "${YELLOW}" "${NC}"
echo ""

# Progress counter
current=0
total=$DNS_COUNT

# Test each DNS server
printf '%bStarting DNS tests...%s\n' "${YELLOW}" "${NC}"
echo ""

MAX_DNS_PARALLEL=10

# Create temp directory for DNS results
DNS_TEMP_DIR="/tmp/dns_temp_$$"
mkdir -p "$DNS_TEMP_DIR"
trap 'rm -rf "$DNS_TEMP_DIR"' EXIT

# Export for subshells
export DNS_TEMP_DIR

printf '%bLaunching parallel DNS tests (max %s concurrent)...%s\n' "${YELLOW}" "$MAX_DNS_PARALLEL" "${NC}"
echo ""

# Process each DNS server
job_count=0
echo "$DNS_SERVERS" | grep -v "^$" | while IFS='|' read -r dns_name dns_ip; do
    current=$((current + 1))

    # Create temp file for this DNS result - use MD5 hash for safe filename
    temp_file="$DNS_TEMP_DIR/$(echo "$dns_name" | md5sum | cut -d' ' -f1).txt"

    # Launch DNS test in background
    {
        # Progress indicator
        printf "[%3d/%3d] Testing %-35s (%s) ... \n" "$current" "$total" "$dns_name" "$dns_ip"

        # Store results for this DNS server
        times=""
        failed=0

        # Test multiple times with different domains
        i=1
        while [ $i -le $TEST_COUNT ]; do
            # Rotate through test domains
            domain_index=$(( (i - 1) % TEST_DOMAIN_COUNT + 1 ))
            domain=$(get_test_domain $domain_index)

            response_time=$(test_dns "$dns_ip" "$domain")

            if [ "$response_time" = "0" ] || [ -z "$response_time" ]; then
                failed=$((failed + 1))
            else
                times="$times $response_time"
            fi
            i=$((i + 1))
        done

        if [ -z "$times" ] || [ $failed -eq $TEST_COUNT ]; then
            echo "FAILED|$dns_name|$dns_ip" > "$temp_file"
            printf "[%3d/%3d] %-35s (%s): %bFAILED%s\n" "$current" "$total" "$dns_name" "$dns_ip" "${RED}" "${NC}"
        else
            # shellcheck disable=SC2086
            # Note: $times intentionally unquoted - it contains space-separated values
            avg=$(calculate_average $times)
            echo "SUCCESS|$dns_name|$avg|$dns_ip" > "$temp_file"
            printf "[%3d/%3d] %-35s (%s): ${GREEN}%4d ms${NC}\n" "$current" "$total" "$dns_name" "$dns_ip" "$avg"
        fi
    } &

    job_count=$((job_count + 1))

    # Limit parallel jobs (ash doesn't have wait -n, so use job count)
    if [ $job_count -ge $MAX_DNS_PARALLEL ]; then
        wait
        job_count=0
    fi
done

# Wait for all remaining jobs
wait

printf '\n%bAll DNS tests completed!%s\n' "${GREEN}" "${NC}"
echo ""

# Collect results from temp files
echo "Processing DNS test results..."
# Use find to locate all txt files in temp directory
if [ -d "$DNS_TEMP_DIR" ]; then
    find "$DNS_TEMP_DIR" -name "*.txt" -type f 2>/dev/null | while read -r temp_file; do
        if [ -f "$temp_file" ]; then
            IFS='|' read -r status name data1 data2 < "$temp_file"
            case "$status" in
                FAILED)
                    echo "$name|$data1" >> $FAILED_FILE
                    ;;
                SUCCESS)
                    echo "$name|$data1|$data2" >> $RESULTS_FILE
                    ;;
            esac
        fi
    done
fi

echo ""
printf '%b========================================================================%s\n' "${BLUE}" "${NC}"
printf '%b                        COMPLETE RESULTS (BEST => WORST)%s\n' "${GREEN}" "${NC}"
printf '%b========================================================================%s\n' "${BLUE}" "${NC}"
echo ""

# Display IPv4 Results
printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
printf '%b|                          IPv4 DNS SERVERS                                    |%s\n' "${CYAN}" "${NC}"
printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
echo ""

if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    printf '%bIPv4 DNS Servers Ranked by Speed:%s\n' "${GREEN}" "${NC}"
    printf '+------+--------------------------------------+-------------------------------------+-----------+\n'
    printf '| Rank | DNS Server                           | IP Address                          | Avg Time  |\n'
    printf '+------+--------------------------------------+-------------------------------------+-----------+\n'
    
    rank=1
    ipv4_count=0
    sort -t'|' -k2 -n $RESULTS_FILE | while IFS='|' read -r dns_name avg ip; do
        if ! is_ipv6_dns "$dns_name"; then
            # Color code based on speed
            if [ "$avg" -lt 50 ]; then
                time_color="${GREEN}"  # Excellent
            elif [ "$avg" -lt 100 ]; then
                time_color="${YELLOW}" # Good
            else
                time_color="${RED}"    # Slow
            fi
            
            printf "| %-4d | %-36s | %-35s | ${time_color}%7d ms${NC} |\n" "$rank" "$dns_name" "$ip" "$avg"
            rank=$((rank + 1))
            ipv4_count=$((ipv4_count + 1))
        fi
    done
    
    if [ $ipv4_count -eq 0 ]; then
        printf '|      | No IPv4 DNS servers working          |                                     |           |\n'
    fi
    
    printf '+------+--------------------------------------+-------------------------------------+-----------+\n'
    echo ""
fi

# Display IPv6 Results
if [ $IPV6_ENABLED -eq 1 ]; then
    printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
    printf '%b|                          IPv6 DNS SERVERS                                    |%s\n' "${CYAN}" "${NC}"
    printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
    echo ""
    
    if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
        printf '%bIPv6 DNS Servers Ranked by Speed:%s\n' "${GREEN}" "${NC}"
        printf '+------+--------------------------------------+-------------------------------------+-----------+\n'
        printf '| Rank | DNS Server                           | IP Address                          | Avg Time  |\n'
        printf '+------+--------------------------------------+-------------------------------------+-----------+\n'
        
        rank=1
        ipv6_count=0
        sort -t'|' -k2 -n $RESULTS_FILE | while IFS='|' read -r dns_name avg ip; do
            if is_ipv6_dns "$dns_name"; then
                # Color code based on speed
                if [ "$avg" -lt 50 ]; then
                    time_color="${GREEN}"  # Excellent
                elif [ "$avg" -lt 100 ]; then
                    time_color="${YELLOW}" # Good
                else
                    time_color="${RED}"    # Slow
                fi
                
                printf "| %-4d | %-36s | %-35s | ${time_color}%7d ms${NC} |\n" "$rank" "$dns_name" "$ip" "$avg"
                rank=$((rank + 1))
                ipv6_count=$((ipv6_count + 1))
            fi
        done
        
        if [ $ipv6_count -eq 0 ]; then
            printf '|      | No IPv6 DNS servers working          |                                     |           |\n'
        fi
        
        printf '+------+--------------------------------------+-------------------------------------+-----------+\n'
        echo ""
    fi
fi

# Statistics
working_count=0
failed_count=0
ipv4_working=0
ipv6_working=0

if [ -f "$RESULTS_FILE" ]; then
    working_count=$(wc -l < $RESULTS_FILE 2>/dev/null || echo "0")
    # Count IPv4 and IPv6 separately
    while IFS='|' read -r dns_name avg ip; do
        if is_ipv6_dns "$dns_name"; then
            ipv6_working=$((ipv6_working + 1))
        else
            ipv4_working=$((ipv4_working + 1))
        fi
    done < $RESULTS_FILE
fi
if [ -f "$FAILED_FILE" ]; then
    failed_count=$(wc -l < $FAILED_FILE 2>/dev/null || echo "0")
fi
total_tested=$((working_count + failed_count))

printf '%bStatistics:%s\n' "${GREEN}" "${NC}"
printf '  Total Tested: %s\n' "$total_tested"
printf '  Working: %s%s%s (IPv4: %s, IPv6: %s)\n' "${GREEN}" "$working_count" "${NC}" "$ipv4_working" "$ipv6_working"
printf '  Failed: %s%s%s\n' "${RED}" "$failed_count" "${NC}"
echo ""

# Show the best DNS server overall
if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    best_dns=$(sort -t'|' -k2 -n $RESULTS_FILE | head -1)
    if [ -n "$best_dns" ]; then
        name=$(echo "$best_dns" | cut -d'|' -f1)
        avg=$(echo "$best_dns" | cut -d'|' -f2)
        ip=$(echo "$best_dns" | cut -d'|' -f3)
        printf '%b========================================================================%b\n' "${BLUE}" "${NC}"
        printf '%b[BEST] BEST DNS SERVER OVERALL: %s%b\n' "${GREEN}" "$name" "${NC}"
        printf '       IP Address: %s\n' "$ip"
        printf '       Average Response Time: %b%s ms%b\n' "${GREEN}" "$avg" "${NC}"
        printf '%b========================================================================%b\n' "${BLUE}" "${NC}"
        echo ""
    fi
    
    # Best IPv4
    best_ipv4=$(sort -t'|' -k2 -n $RESULTS_FILE | while IFS='|' read -r dns_name avg ip; do
        if ! is_ipv6_dns "$dns_name"; then
            echo "$dns_name|$avg|$ip"
            break
        fi
    done)
    if [ -n "$best_ipv4" ]; then
        name=$(echo "$best_ipv4" | cut -d'|' -f1)
        avg=$(echo "$best_ipv4" | cut -d'|' -f2)
        ip=$(echo "$best_ipv4" | cut -d'|' -f3)
        printf '%b[#1] BEST IPv4 DNS SERVER: %s%b\n' "${GREEN}" "$name" "${NC}"
        printf '     IP Address: %s\n' "$ip"
        printf '     Average Response Time: %b%s ms%b\n' "${GREEN}" "$avg" "${NC}"
        echo ""
    fi
    
    # Best IPv6
    if [ $IPV6_ENABLED -eq 1 ]; then
        best_ipv6=$(sort -t'|' -k2 -n $RESULTS_FILE | while IFS='|' read -r dns_name avg ip; do
            if is_ipv6_dns "$dns_name"; then
                echo "$dns_name|$avg|$ip"
                break
            fi
        done)
        if [ -n "$best_ipv6" ]; then
            name=$(echo "$best_ipv6" | cut -d'|' -f1)
            avg=$(echo "$best_ipv6" | cut -d'|' -f2)
            ip=$(echo "$best_ipv6" | cut -d'|' -f3)
            printf '%b[#1] BEST IPv6 DNS SERVER: %s%b\n' "${GREEN}" "$name" "${NC}"
            printf '     IP Address: %s\n' "$ip"
            printf '     Average Response Time: %b%s ms%b\n' "${GREEN}" "$avg" "${NC}"
            echo ""
        fi
    fi
fi

# Show failed DNS servers if any
if [ -f "$FAILED_FILE" ] && [ -s "$FAILED_FILE" ]; then
    echo ""
    printf '%bFailed/Unreachable DNS Servers:%s\n' "${RED}" "${NC}"
    printf '+--------------------------------------+-------------------------------------+\n'
    printf '| DNS Server                           | IP Address                          |\n'
    printf '+--------------------------------------+-------------------------------------+\n'
    while IFS='|' read -r dns_name dns_ip; do
        printf "| %-36s | %-35s |\n" "$dns_name" "$dns_ip"
    done < $FAILED_FILE
    printf '+--------------------------------------+-------------------------------------+\n'
fi

echo ""
printf '%bTest completed!%s\n' "${YELLOW}" "${NC}"
echo ""

# Configuration recommendation
printf '%b========================================================================%s\n' "${BLUE}" "${NC}"
printf '%bCONFIGURATION RECOMMENDATION FOR OPENWRT:%s\n' "${GREEN}" "${NC}"
echo ""

if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    # Get top 2 best performing DNS servers
    primary_line=$(sort -t'|' -k2 -n $RESULTS_FILE | head -1)
    secondary_line=$(sort -t'|' -k2 -n $RESULTS_FILE | head -2 | tail -1)

    if [ -n "$primary_line" ]; then
        primary_name=$(echo "$primary_line" | cut -d'|' -f1)
        primary_avg=$(echo "$primary_line" | cut -d'|' -f2)
        primary_ip=$(echo "$primary_line" | cut -d'|' -f3)
        printf 'For optimal performance, configure your DNS as:\n'
        printf '  Primary DNS:   %b%s%b (%s - %sms)\n' "${GREEN}" "$primary_ip" "${NC}" "$primary_name" "$primary_avg"

        if [ -n "$secondary_line" ] && [ "$secondary_line" != "$primary_line" ]; then
            secondary_name=$(echo "$secondary_line" | cut -d'|' -f1)
            secondary_avg=$(echo "$secondary_line" | cut -d'|' -f2)
            secondary_ip=$(echo "$secondary_line" | cut -d'|' -f3)
            printf '  Secondary DNS: %b%s%b (%s - %sms)\n' "${GREEN}" "$secondary_ip" "${NC}" "$secondary_name" "$secondary_avg"
        fi
    fi
fi

printf '%b========================================================================%s\n' "${BLUE}" "${NC}"

# DNS-PING CORRELATION TEST
echo ""
echo ""
printf '%b========================================================================%s\n' "${BLUE}" "${NC}"
printf '%b                    DNS-PING CORRELATION ANALYSIS%s\n' "${GREEN}" "${NC}"
printf '%b========================================================================%s\n' "${BLUE}" "${NC}"
echo ""

if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    printf '%bTesting ping latency for working DNS servers and calculating correlation score...%s\n' "${YELLOW}" "${NC}"
    echo ""

    MAX_PING_PARALLEL=20

    # Create temp directory for ping results
    PING_TEMP_DIR="/tmp/ping_temp_$$"
    mkdir -p "$PING_TEMP_DIR"
    trap 'rm -rf "$DNS_TEMP_DIR" "$PING_TEMP_DIR"' EXIT

    # Export for subshells
    export PING_TEMP_DIR

    # Progress for correlation test
    current=0
    tested_count=$(wc -l < $RESULTS_FILE 2>/dev/null || echo "0")
    ping_job_count=0

    printf 'Testing ping latency for %s working DNS servers...\n' "$tested_count"
    echo ""
    printf '%bLaunching parallel ping tests (max %s concurrent)...%s\n' "${YELLOW}" "$MAX_PING_PARALLEL" "${NC}"

    # Test ping for each working DNS server
    while IFS='|' read -r dns_name dns_time ip; do
        current=$((current + 1))

        # Create temp file for this ping result - use MD5 hash for safe filename
        ping_temp_file="$PING_TEMP_DIR/$(echo "$dns_name" | md5sum | cut -d' ' -f1).txt"

        # Launch ping test in background
        {
            printf "[%3d/%3d] Pinging %-35s (%s) ... \n" "$current" "$tested_count" "$dns_name" "$ip"

            ping_time=$(test_ping "$ip")

            if [ "$ping_time" = "9999" ]; then
                printf "[%3d/%3d] %-35s (%s): %bFAILED%s\n" "$current" "$tested_count" "$dns_name" "$ip" "${RED}" "${NC}"
                # Skip failed ping servers - don't store in correlation results
            else
                printf "[%3d/%3d] %-35s (%s): ${GREEN}%4d ms${NC}\n" "$current" "$tested_count" "$dns_name" "$ip" "$ping_time"

                # Calculate correlation score (weighted average)
                # DNS query time is more important (70%) than ping (30%)
                correlation_score=$(( (dns_time * 70 + ping_time * 30) / 100 ))

                # Save results to temp file
                echo "$correlation_score|$dns_name|$dns_time|$ping_time|$ip" > "$ping_temp_file"
            fi
        } &

        ping_job_count=$((ping_job_count + 1))

        # Limit parallel jobs (ash doesn't have wait -n, so use job count)
        if [ $ping_job_count -ge $MAX_PING_PARALLEL ]; then
            wait
            ping_job_count=0
        fi
    done < $RESULTS_FILE

    # Wait for all remaining ping jobs
    wait

    printf '\n%bAll ping tests completed!%s\n' "${GREEN}" "${NC}"
    echo ""

    # Collect results from temp files
    echo "Processing ping test results..."
    # Use find to locate all txt files in ping temp directory
    if [ -d "$PING_TEMP_DIR" ]; then
        find "$PING_TEMP_DIR" -name "*.txt" -type f 2>/dev/null | while read -r ping_temp_file; do
            if [ -f "$ping_temp_file" ]; then
                cat "$ping_temp_file" >> $CORRELATION_FILE
            fi
        done
    fi
    
    echo ""
    
    # Display IPv4 Correlation Results
    printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
    printf '%b|                IPv4 DNS-PING CORRELATION RESULTS                             |%s\n' "${CYAN}" "${NC}"
    printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
    echo ""
    printf '%bIPv4 DNS-Ping Correlation (Best => Worst):%s\n' "${GREEN}" "${NC}"
    printf '+------+--------------------------------------+-------------------------------------+----------+----------+------------+--------------+\n'
    printf '| Rank | DNS Server                           | IP Address                          | DNS (ms) | Ping(ms) | Difference | Score        |\n'
    printf '+------+--------------------------------------+-------------------------------------+----------+----------+------------+--------------+\n'
    
    rank=1
    ipv4_corr_count=0
    sort -t'|' -k1 -n $CORRELATION_FILE 2>/dev/null | while IFS='|' read -r score dns_name dns_time ping_time ip; do
        if ! is_ipv6_dns "$dns_name"; then
            # Calculate difference
            if [ "$ping_time" = "9999" ]; then
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
            
            printf "| %-4d | %-36s | %-35s | %8s | %8s | ${diff_color}%10s${NC} | ${score_color}%12d${NC} |\n" \
                   "$rank" "$dns_name" "$ip" "$dns_time" "$ping_display" "$diff" "$score"
            
            rank=$((rank + 1))
            ipv4_corr_count=$((ipv4_corr_count + 1))
        fi
    done
    
    if [ $ipv4_corr_count -eq 0 ]; then
        printf '|      | No IPv4 DNS servers with ping data  |                                     |          |          |            |              |\n'
    fi
    
    printf '+------+--------------------------------------+-------------------------------------+----------+----------+------------+--------------+\n'
    echo ""
    
    # Display IPv6 Correlation Results
    if [ $IPV6_ENABLED -eq 1 ]; then
        printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
        printf '%b|                IPv6 DNS-PING CORRELATION RESULTS                             |%s\n' "${CYAN}" "${NC}"
        printf '%b+------------------------------------------------------------------------------+%s\n' "${CYAN}" "${NC}"
        echo ""
        printf '%bIPv6 DNS-Ping Correlation (Best => Worst):%s\n' "${GREEN}" "${NC}"
        printf '+------+--------------------------------------+-------------------------------------+----------+----------+------------+--------------+\n'
        printf '| Rank | DNS Server                           | IP Address                          | DNS (ms) | Ping(ms) | Difference | Score        |\n'
        printf '+------+--------------------------------------+-------------------------------------+----------+----------+------------+--------------+\n'
        
        rank=1
        ipv6_corr_count=0
        sort -t'|' -k1 -n $CORRELATION_FILE 2>/dev/null | while IFS='|' read -r score dns_name dns_time ping_time ip; do
            if is_ipv6_dns "$dns_name"; then
                # Calculate difference
                if [ "$ping_time" = "9999" ]; then
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
                
                printf "| %-4d | %-36s | %-35s | %8s | %8s | ${diff_color}%10s${NC} | ${score_color}%12d${NC} |\n" \
                       "$rank" "$dns_name" "$ip" "$dns_time" "$ping_display" "$diff" "$score"
                
                rank=$((rank + 1))
                ipv6_corr_count=$((ipv6_corr_count + 1))
            fi
        done
        
        if [ $ipv6_corr_count -eq 0 ]; then
            printf '|      | No IPv6 DNS servers with ping data  |                                     |          |          |            |              |\n'
        fi
        
        printf '+------+--------------------------------------+-------------------------------------+----------+----------+------------+--------------+\n'
        echo ""
    fi
    
    echo ""
    printf '%bScore Calculation:%s\n' "${GREEN}" "${NC}"
    printf '  Score = (DNS Query Time x 70%% + Ping Latency x 30%%)\n'
    printf '  Lower score = Better overall performance\n'
    echo ""
    
    # Find best correlations
    if [ -f "$CORRELATION_FILE" ] && [ -s "$CORRELATION_FILE" ]; then
        # Best IPv4
        best_ipv4_corr=$(sort -t'|' -k1 -n $CORRELATION_FILE 2>/dev/null | while IFS='|' read -r score dns_name dns_time ping_time ip; do
            if ! is_ipv6_dns "$dns_name"; then
                echo "$score|$dns_name|$dns_time|$ping_time|$ip"
                break
            fi
        done)
        if [ -n "$best_ipv4_corr" ]; then
            score=$(echo "$best_ipv4_corr" | cut -d'|' -f1)
            name=$(echo "$best_ipv4_corr" | cut -d'|' -f2)
            dns_time=$(echo "$best_ipv4_corr" | cut -d'|' -f3)
            ping_time=$(echo "$best_ipv4_corr" | cut -d'|' -f4)
            ip=$(echo "$best_ipv4_corr" | cut -d'|' -f5)
            printf '%b[#1] BEST IPv4 DNS SERVER (DNS+Network Performance):%b\n' "${GREEN}" "${NC}"
            printf '     Server: %s\n' "$name"
            printf '     IP: %s\n' "$ip"
            printf '     DNS Query: %b%sms%b, Ping: %b%sms%b, Score: %b%s%b\n' "${GREEN}" "${dns_time}" "${NC}" "${GREEN}" "${ping_time}" "${NC}" "${GREEN}" "${score}" "${NC}"
            echo ""
        fi
        
        # Best IPv6
        if [ $IPV6_ENABLED -eq 1 ]; then
            best_ipv6_corr=$(sort -t'|' -k1 -n $CORRELATION_FILE 2>/dev/null | while IFS='|' read -r score dns_name dns_time ping_time ip; do
                if is_ipv6_dns "$dns_name"; then
                    echo "$score|$dns_name|$dns_time|$ping_time|$ip"
                    break
                fi
            done)
            if [ -n "$best_ipv6_corr" ]; then
                score=$(echo "$best_ipv6_corr" | cut -d'|' -f1)
                name=$(echo "$best_ipv6_corr" | cut -d'|' -f2)
                dns_time=$(echo "$best_ipv6_corr" | cut -d'|' -f3)
                ping_time=$(echo "$best_ipv6_corr" | cut -d'|' -f4)
                ip=$(echo "$best_ipv6_corr" | cut -d'|' -f5)
                printf '%b[#1] BEST IPv6 DNS SERVER (DNS+Network Performance):%b\n' "${GREEN}" "${NC}"
                printf '     Server: %s\n' "$name"
                printf '     IP: %s\n' "$ip"
                printf '     DNS Query: %b%sms%b, Ping: %b%sms%b, Score: %b%s%b\n' "${GREEN}" "${dns_time}" "${NC}" "${GREEN}" "${ping_time}" "${NC}" "${GREEN}" "${score}" "${NC}"
                echo ""
            fi
        fi
    fi
fi

echo ""
printf '%bAnalysis complete!%s\n' "${YELLOW}" "${NC}"