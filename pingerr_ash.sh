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
# Tests multiple DNS providers and finds the fastest one

# Color codes for output (using printf format for ash compatibility)
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[1;33m')
BLUE=$(printf '\033[0;34m')
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

# DNS Servers to test - format: "Name|IP"
DNS_SERVERS="
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

# Create temp files for results
RESULTS_FILE="/tmp/dns_results_$$"
FAILED_FILE="/tmp/dns_failed_$$"
CORRELATION_FILE="/tmp/dns_correlation_$$"

# Clean up temp files on exit
trap 'rm -f "$RESULTS_FILE" "$FAILED_FILE" "$CORRELATION_FILE"' EXIT

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
    
    # Use dig to test DNS server
    if command -v dig >/dev/null 2>&1; then
        result=$(dig @"${dns_server}" "${domain}" +noall +stats +time=${timeout} 2>/dev/null | grep "Query time:" | awk '{print $4}')
    elif command -v nslookup >/dev/null 2>&1; then
        # Fallback to nslookup with time command
        local start
        start=$(date +%s%3N 2>/dev/null || date +%s)
        nslookup "${domain}" "${dns_server}" >/dev/null 2>&1
        local end
        end=$(date +%s%3N 2>/dev/null || date +%s)
        if nslookup "${domain}" "${dns_server}" >/dev/null 2>&1; then
            result=$((end - start))
        fi
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

# Function to test ping latency
test_ping() {
    local ip=$1
    local count=3
    local result=""
    
    # Try to ping with 3 packets, 1 second timeout
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

# Check for required commands
if ! command -v dig >/dev/null 2>&1 && ! command -v nslookup >/dev/null 2>&1; then
    printf '%bError: Neither %s nor %s found. Please install dnsutils/bind-tools.%s\n' "${RED}" "'dig'" "'nslookup'" "${NC}"
    echo "On OpenWRT: opkg install bind-dig"
    echo "On Debian/Ubuntu: apt-get install dnsutils"
    echo "On RHEL/CentOS: yum install bind-utils"
    exit 1
fi

# Count total DNS servers
DNS_COUNT=$(count_dns_servers)

# Header
total_tests=$((DNS_COUNT * TEST_COUNT))
printf '%b════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
printf '%b      DNS Speed Test - Testing %s DNS Servers%s\n' "${GREEN}" "${DNS_COUNT}" "${NC}"
printf '%b════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
echo ""
printf 'Total DNS Servers: %s\n' "${DNS_COUNT}"
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

printf '%bLaunching parallel DNS tests (max %s concurrent)...%s\n' "${YELLOW}" "$MAX_DNS_PARALLEL" "${NC}"
echo ""

# Process each DNS server
job_count=0
echo "$DNS_SERVERS" | grep -v "^$" | while IFS='|' read -r dns_name dns_ip; do
    current=$((current + 1))

    # Create temp file for this DNS result
    temp_file="$DNS_TEMP_DIR/$(echo "$dns_name" | tr '/' '_').txt"

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
for temp_file in "$DNS_TEMP_DIR"/*.txt; do
    if [ -f "$temp_file" ]; then
        read -r status name data1 data2 < "$temp_file"
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

echo ""
printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
printf '%b                                    COMPLETE RESULTS (BEST → WORST)%s\n' "${GREEN}" "${NC}"
printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
echo ""

# Sort and display ALL results
if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    printf '%bAll DNS Servers Ranked by Speed:%s\n' "${GREEN}" "${NC}"
    printf '┌──────┬──────────────────────────────────────┬───────────────────────┬───────────┐\n'
    printf '│ Rank │ DNS Server                           │ IP Address            │ Avg Time  │\n'
    printf '├──────┼──────────────────────────────────────┼───────────────────────┼───────────┤\n'
    
    rank=1
    sort -t'|' -k2 -n $RESULTS_FILE | while IFS='|' read -r dns_name avg ip; do
        # Color code based on speed
        if [ "$avg" -lt 50 ]; then
            time_color="${GREEN}"  # Excellent
        elif [ "$avg" -lt 100 ]; then
            time_color="${YELLOW}" # Good
        else
            time_color="${RED}"    # Slow
        fi
        
        printf "│ %-4d │ %-36s │ %-21s │ ${time_color}%7d ms${NC} │\n" "$rank" "$dns_name" "$ip" "$avg"
        rank=$((rank + 1))
    done
    
    printf '└──────┴──────────────────────────────────────┴───────────────────────┴───────────┘\n'
    echo ""
fi

# Statistics
working_count=0
failed_count=0
if [ -f "$RESULTS_FILE" ]; then
    working_count=$(wc -l < $RESULTS_FILE)
fi
if [ -f "$FAILED_FILE" ]; then
    failed_count=$(wc -l < $FAILED_FILE)
fi
total_tested=$((working_count + failed_count))

printf '%bStatistics:%s\n' "${GREEN}" "${NC}"
printf '  Total Tested: %s\n' "$total_tested"
printf '  Working: %s%s%s\n' "${GREEN}" "$working_count" "${NC}"
printf '  Failed: %s%s%s\n' "${RED}" "$failed_count" "${NC}"
echo ""

# Show the best DNS server
if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    best_dns=$(sort -t'|' -k2 -n $RESULTS_FILE | head -1)
    if [ -n "$best_dns" ]; then
        name=$(echo "$best_dns" | cut -d'|' -f1)
        avg=$(echo "$best_dns" | cut -d'|' -f2)
        ip=$(echo "$best_dns" | cut -d'|' -f3)
        printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%b\n' "${BLUE}" "${NC}"
        printf '%b🏆 BEST DNS SERVER: %s%b\n' "${GREEN}" "$name" "${NC}"
        printf '   IP Address: %s\n' "$ip"
        printf '   Average Response Time: %b%s ms%b\n' "${GREEN}" "$avg" "${NC}"
        printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%b\n' "${BLUE}" "${NC}"
    fi
fi

# Show failed DNS servers if any
if [ -f "$FAILED_FILE" ] && [ -s "$FAILED_FILE" ]; then
    echo ""
    printf '%bFailed/Unreachable DNS Servers:%s\n' "${RED}" "${NC}"
    printf '┌──────────────────────────────────────┬───────────────────────┐\n'
    printf '│ DNS Server                           │ IP Address            │\n'
    printf '├──────────────────────────────────────┼───────────────────────┤\n'
    while IFS='|' read -r dns_name dns_ip; do
        printf "│ %-36s │ %-21s │\n" "$dns_name" "$dns_ip"
    done < $FAILED_FILE
    printf '└──────────────────────────────────────┴───────────────────────┘\n'
fi

echo ""
printf '%bTest completed!%s\n' "${YELLOW}" "${NC}"
echo ""

# Configuration recommendation
printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
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
        printf '  Primary DNS:   %b%s%b (%s - %sms)\n' "${GREEN}" "$primary_ip" "${NC}" "$primary_name" "$primary_avg"

        if [ -n "$secondary_line" ] && [ "$secondary_line" != "$primary_line" ]; then
            secondary_name=$(echo "$secondary_line" | cut -d'|' -f1)
            secondary_avg=$(echo "$secondary_line" | cut -d'|' -f2)
            secondary_ip=$(echo "$secondary_line" | cut -d'|' -f3)
            printf '  Secondary DNS: %b%s%b (%s - %sms)\n' "${GREEN}" "$secondary_ip" "${NC}" "$secondary_name" "$secondary_avg"
        fi
    fi
fi

printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"

# DNS-PING CORRELATION TEST
echo ""
echo ""
printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
printf '%b                                DNS-PING CORRELATION ANALYSIS%s\n' "${GREEN}" "${NC}"
printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
echo ""

if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    printf '%bTesting ping latency for working DNS servers and calculating correlation score...%s\n' "${YELLOW}" "${NC}"
    echo ""

    MAX_PING_PARALLEL=20

    # Create temp directory for ping results
    PING_TEMP_DIR="/tmp/ping_temp_$$"
    mkdir -p "$PING_TEMP_DIR"
    trap 'rm -rf "$DNS_TEMP_DIR" "$PING_TEMP_DIR"' EXIT

    # Progress for correlation test
    current=0
    tested_count=$(wc -l < $RESULTS_FILE)
    ping_job_count=0

    printf 'Testing ping latency for %s working DNS servers...\n' "$tested_count"
    echo ""
    printf '%bLaunching parallel ping tests (max %s concurrent)...%s\n' "${YELLOW}" "$MAX_PING_PARALLEL" "${NC}"

    # Test ping for each working DNS server
    while IFS='|' read -r dns_name dns_time ip; do
        current=$((current + 1))

        # Create temp file for this ping result
        ping_temp_file="$PING_TEMP_DIR/$(echo "$dns_name" | tr '/' '_').txt"

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
    for ping_temp_file in "$PING_TEMP_DIR"/*.txt; do
        if [ -f "$ping_temp_file" ]; then
            cat "$ping_temp_file" >> $CORRELATION_FILE
        fi
    done
    
    echo ""
    printf '%bDNS-Ping Correlation Results (Best → Worst):%s\n' "${GREEN}" "${NC}"
    printf '┌──────┬──────────────────────────────────────┬───────────────────────┬──────────┬──────────┬────────────┬──────────────┐\n'
    printf '│ Rank │ DNS Server                           │ IP Address            │ DNS (ms) │ Ping(ms) │ Difference │ Score        │\n'
    printf '├──────┼──────────────────────────────────────┼───────────────────────┼──────────┼──────────┼────────────┼──────────────┤\n'
    
    rank=1
    sort -t'|' -k1 -n $CORRELATION_FILE | while IFS='|' read -r score dns_name dns_time ping_time ip; do
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
        
        printf "│ %-4d │ %-36s │ %-21s │ %8s │ %8s │ ${diff_color}%10s${NC} │ ${score_color}%12d${NC} │\n" \
               "$rank" "$dns_name" "$ip" "$dns_time" "$ping_display" "$diff" "$score"
        
        rank=$((rank + 1))
    done
    
    printf '└──────┴──────────────────────────────────────┴───────────────────────┴──────────┴──────────┴────────────┴──────────────┘\n'
    
    echo ""
    printf '%bScore Calculation:%s\n' "${GREEN}" "${NC}"
    printf '  Score = (DNS Query Time × 70%% + Ping Latency × 30%%)\n'
    printf '  Lower score = Better overall performance\n'
    echo ""
    
    # Find best correlation
    if [ -f "$CORRELATION_FILE" ] && [ -s "$CORRELATION_FILE" ]; then
        best_correlation=$(sort -t'|' -k1 -n $CORRELATION_FILE | head -1)
        if [ -n "$best_correlation" ]; then
            score=$(echo "$best_correlation" | cut -d'|' -f1)
            name=$(echo "$best_correlation" | cut -d'|' -f2)
            dns_time=$(echo "$best_correlation" | cut -d'|' -f3)
            ping_time=$(echo "$best_correlation" | cut -d'|' -f4)
            ip=$(echo "$best_correlation" | cut -d'|' -f5)
            printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%b\n' "${BLUE}" "${NC}"
            printf '%b🏆 BEST OVERALL DNS SERVER (DNS+Network Performance):%b\n' "${GREEN}" "${NC}"
            printf '   Server: %s\n' "$name"
            printf '   IP: %s\n' "$ip"
            printf '   DNS Query: %b%sms%b\n' "${GREEN}" "${dns_time}" "${NC}"
            if [ "$ping_time" != "9999" ]; then
                printf '   Ping Latency: %b%sms%b\n' "${GREEN}" "${ping_time}" "${NC}"
            else
                printf '   Ping Latency: %bFAILED%b\n' "${RED}" "${NC}"
            fi
            printf '   Combined Score: %b%s%b\n' "${GREEN}" "${score}" "${NC}"
            printf '%b════════════════════════════════════════════════════════════════════════════════════════════════════%b\n' "${BLUE}" "${NC}"
        fi
    fi
fi

echo ""
printf '%bAnalysis complete!%s\n' "${YELLOW}" "${NC}"

