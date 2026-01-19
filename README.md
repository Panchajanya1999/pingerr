# pingerr

A comprehensive DNS benchmarking tool that tests 50+ public DNS servers to find the fastest and most reliable DNS resolver for your network.

## Features

- **Tests 50+ DNS Servers**: Including Google, Cloudflare, Quad9, OpenDNS, AdGuard, and many more
- **Cache-Aware Testing**: Warmup queries ensure accurate cached response time measurements
- **Multiple Test Iterations**: Performs 5 tests per server (configurable via `-n` flag)
- **DNS-Ping Correlation Analysis**: Measures both DNS query time and network latency
- **Smart Scoring System**: Weighted scoring (70% DNS, 30% ping) for optimal server selection
- **Color-Coded Results**: Visual indicators for performance (Green = Excellent, Yellow = Good, Red = Slow)
- **Configuration Recommendations**: Provides ready-to-use primary and secondary DNS suggestions

## How It Works

The script uses a **cache-aware benchmarking** approach:

1. **Warmup Query**: Sends an initial DNS query to prime the server's cache
2. **Measurement Queries**: Performs 5 subsequent queries to measure cached response time
3. **Median Calculation**: Uses the median of all measurements for robust results

This approach measures the actual network latency to each DNS server, rather than recursive resolution time, giving results that correlate closely with ping latency.

By default, `google.com` is used as the test domain, but you can customize this with the `-d` flag.

## Videos
### Demo Videos

#### Archlinux


https://github.com/user-attachments/assets/03f3c379-31b7-4e70-a2c6-28a5af8f27a1




#### OpenWRT


https://github.com/user-attachments/assets/04be614f-e4ae-4790-a437-95001589dd3e




> **Note:** Embedded videos may not play on GitHub.com due to platform limitations. If so, [click here for Archlinux](https://storage.panchajanya.dev/Screencasts/archlinux.mp4) or [OpenWRT](https://storage.panchajanya.dev/Screencasts/openwrt.mp4).

## Installation & Usage

### For Regular Linux/Mac Users (Bash)

Run directly from the internet:
```bash
curl -sSL https://raw.githubusercontent.com/Panchajanya1999/pingerr/refs/heads/master/pingerr.sh | bash
```

Or download and run:
```bash
# Download the script
curl -o https://raw.githubusercontent.com/Panchajanya1999/pingerr/refs/heads/master/pingerr.sh

# Make it executable
chmod +x pingerr.sh

# Run the test
./pingerr.sh
```

### For OpenWRT Users (Ash Shell)

Run directly from the internet:
```bash
wget -qO- https://raw.githubusercontent.com/Panchajanya1999/pingerr/refs/heads/master/pingerr_ash.sh | ash
```

Or download and run:
```bash
# Download the script
wget -O /tmp/pingerr_ash.sh https://raw.githubusercontent.com/Panchajanya1999/pingerr/refs/heads/master/pingerr_ash.sh

# Make it executable
chmod +x /tmp/pingerr_ash.sh

# Run the test
/tmp/pingerr_ash.sh
```

## Command Line Options

```
Options:
  -4, --ipv4-only     Test only IPv4 DNS servers
  -6, --ipv6-only     Test only IPv6 DNS servers (requires IPv6 connectivity)
  -n, --count N       Number of tests per server (default: 5)
  -d, --domain NAME   Domain/IP to use for DNS queries (default: google.com)
  -q, --quick         Quick mode (3 tests per server)
  --no-ping           Skip ping correlation test
  --no-color          Disable colored output
  -h, --help          Show help message
  -v, --version       Show version
```

### Examples

```bash
# Run full test (IPv4 + IPv6 if available)
./pingerr.sh

# Test only IPv4 servers
./pingerr.sh -4

# Quick test with fewer iterations
./pingerr.sh -q

# Use a custom domain for DNS queries
./pingerr.sh -d github.com

# Use an IP address for consistent measurements
./pingerr.sh -d 1.1.1.1

# Skip ping correlation analysis
./pingerr.sh --no-ping

# Run 10 tests per server for more accuracy
./pingerr.sh -n 10
```

## Prerequisites

### For Regular Systems
- **Required**: `dig` or `nslookup` command
- **Optional**: `ping` for correlation analysis

Install prerequisites:
```bash
# Debian/Ubuntu
sudo apt-get install dnsutils

# RHEL/CentOS/Fedora
sudo yum install bind-utils

# macOS (usually pre-installed)
# If not: brew install bind
```

### For OpenWRT
```bash
# Update package list
opkg update

# Install dig (recommended for better accuracy)
opkg install bind-dig

# Or install drill as alternative
opkg install drill
```

## Understanding the Results

### DNS Speed Rankings
The script provides a complete ranking of all tested DNS servers:
```
┌──────┬──────────────────────────────────────┬───────────────────────┬───────────┐
│ Rank │ DNS Server                           │ IP Address            │ Median    │
├──────┼──────────────────────────────────────┼───────────────────────┼───────────┤
│ 1    │ Cloudflare-Primary                   │ 1.1.1.1               │   12 ms   │
│ 2    │ Google-Primary                       │ 8.8.8.8               │   15 ms   │
```

### Performance Indicators
- 🟢 **Green** (< 50ms): Excellent performance
- 🟡 **Yellow** (50-100ms): Good performance
- 🔴 **Red** (> 100ms): Slow performance

### Correlation Analysis
The script performs a DNS-Ping correlation test to find servers that are both:
- Fast at DNS resolution
- Have low network latency

**Score Calculation**: `(DNS Query Time × 70% + Ping Latency × 30%)`

## Configuration Examples

### OpenWRT Configuration
After running the test, apply the recommended DNS servers:

```bash
# Via UCI commands
uci set network.wan.dns="1.1.1.1 8.8.8.8"
uci commit network
/etc/init.d/network restart
```

### Linux (systemd-resolved)
```bash
# Edit resolved.conf
sudo nano /etc/systemd/resolved.conf

# Add recommended DNS servers
DNS=1.1.1.1 8.8.8.8
FallbackDNS=9.9.9.9

# Restart service
sudo systemctl restart systemd-resolved
```

### macOS
```bash
# Via System Preferences
System Preferences > Network > Advanced > DNS
# Add the recommended IP addresses
```

## Sample Output

```
════════════════════════════════════════════════════════════════════
      DNS Speed Test - Testing 60+ DNS Servers
════════════════════════════════════════════════════════════════════

[1/60] Testing Cloudflare-Primary (1.1.1.1) ... 12 ms
[2/60] Testing Google-Primary (8.8.8.8) ... 15 ms
...

🏆 BEST DNS SERVER: Cloudflare-Primary
   IP Address: 1.1.1.1
   Median Response Time: 12 ms

CONFIGURATION RECOMMENDATION:
  Primary DNS:   1.1.1.1 (Cloudflare-Primary - 12ms)
  Secondary DNS: 8.8.8.8 (Google-Primary - 15ms)
```

## Advanced Usage

### Modify DNS Server List

Edit the script to add or remove DNS servers from the `DNS_NAMES_IPV4`/`DNS_IPS_IPV4` arrays (or `DNS_SERVERS_IPV4` for ash version).

### IPv6 Testing

The script automatically detects IPv6 connectivity. Use `-6` to test only IPv6 servers, or `-4` to skip IPv6 entirely.

## Troubleshooting

### "dig: command not found"
Install the DNS utilities package for your system (see Prerequisites).

### No results or all servers failing
- Check your internet connection
- Verify firewall isn't blocking DNS port 53
- Try running with `nslookup` instead of `dig`

### Permission denied
Make sure the script has execute permissions:
```bash
chmod +x pingerr.sh  # or pingerr_ash.sh for OpenWRT
```

### OpenWRT specific issues
- Ensure you have enough free RAM (script uses temporary files)
- If `/tmp` is full, clear some space: `rm /tmp/*`

## Performance Tips

1. **Run multiple times**: Network conditions vary; run 2-3 times for consistent results
2. **Test at different times**: DNS performance can vary by time of day
3. **Consider geography**: Servers physically closer typically perform better
4. **Check ISP restrictions**: Some ISPs block or redirect certain DNS servers

## DNS Server Categories

The script tests various categories of DNS servers:
- **Standard**: Google, Cloudflare, Quad9
- **Privacy-focused**: Mullvad, DNS0.EU, LibreDNS
- **Family-safe**: CleanBrowsing-Family, AdGuard-Family, OpenDNS-Family
- **Ad-blocking**: AdGuard, NextDNS, ControlD
- **Regional**: AliDNS (Asia), Yandex (Russia), DNS.SB

## License
This script is provided as-is for network diagnostics and optimization purposes.

