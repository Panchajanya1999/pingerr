# pingerr

A comprehensive DNS benchmarking tool that tests 60+ public DNS servers to find the fastest and most reliable DNS resolver for your network.

## Features

- **Tests 60+ DNS Servers**: Including Google, Cloudflare, Quad9, OpenDNS, AdGuard, and many more
- **Multiple Test Iterations**: Performs 5 tests per server using different popular domains
- **DNS-Ping Correlation Analysis**: Measures both DNS query time and network latency
- **Smart Scoring System**: Weighted scoring (70% DNS, 30% ping) for optimal server selection
- **Color-Coded Results**: Visual indicators for performance (Green = Excellent, Yellow = Good, Red = Slow)
- **Configuration Recommendations**: Provides ready-to-use primary and secondary DNS suggestions

## What It Tests

The script evaluates DNS servers across 15 popular domains including:
- google.com, youtube.com, facebook.com
- instagram.com, chatgpt.com, x.com
- whatsapp.com, reddit.com, wikipedia.org
- amazon.com, tiktok.com, cloudflare.com
- github.com, netflix.com, pinterest.com

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
│ Rank │ DNS Server                           │ IP Address            │ Avg Time  │
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
   Average Response Time: 12 ms

CONFIGURATION RECOMMENDATION:
  Primary DNS:   1.1.1.1 (Cloudflare-Primary - 12ms)
  Secondary DNS: 8.8.8.8 (Google-Primary - 15ms)
```

# Advanced Options

### Modify Test Parameters

Edit the script to adjust:
- `TEST_COUNT`: Number of tests per server (default: 5)
- `TEST_DOMAINS`: Domains to test against
- `DNS_SERVERS`: Add or remove DNS servers

### Run Specific Tests Only

For quick tests, you can modify the DNS_SERVERS list in the script to include only servers you're interested in.

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

