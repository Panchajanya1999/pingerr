#!/usr/bin/env python3

""""
Author: @Alb4don
Version: 1.0
"""

import sys
import os
import socket
import time
import argparse
import subprocess
import platform
import concurrent.futures
import statistics
import csv
import json
import logging
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
from threading import Lock
import tempfile
import ipaddress
import re


VERSION = "1.0"
BANNER = """
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║    ██████╗ ██╗███╗   ██╗ ██████╗ ███████╗██████╗ ██████╗                   ║
║    ██╔══██╗██║████╗  ██║██╔════╝ ██╔════╝██╔══██╗██╔══██╗                  ║
║    ██████╔╝██║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝██████╔╝                  ║
║    ██╔═══╝ ██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗██╔══██╗                  ║
║    ██║     ██║██║ ╚████║╚██████╔╝███████╗██║  ██║██║  ██║                  ║
║    ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝                  ║
║                                                                            ║
║                                                                            ║
║                                                                            ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
"""


class Colors:
    
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    GRAY = '\033[0;37m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable_colors():
        
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GRAY = ''
        Colors.BOLD = ''
        Colors.RESET = ''


TEST_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "chatgpt.com",
    "x.com",
    "whatsapp.com",
    "reddit.com",
    "wikipedia.org",
    "amazon.com",
    "tiktok.com",
    "pinterest.com",
    "cloudflare.com",
    "github.com",
    "netflix.com"
]


DNS_SERVERS_IPV4 = {
    "Google-Primary": "8.8.8.8",
    "Google-Secondary": "8.8.4.4",
    "Cloudflare-Primary": "1.1.1.1",
    "Cloudflare-Secondary": "1.0.0.1",
    "Cloudflare-Family-Primary": "1.1.1.3",
    "Cloudflare-Family-Secondary": "1.0.0.3",
    "Quad9-Primary": "9.9.9.9",
    "Quad9-Secondary": "149.112.112.112",
    "Quad9-Secured": "9.9.9.11",
    "OpenDNS-Primary": "208.67.222.222",
    "OpenDNS-Secondary": "208.67.220.220",
    "OpenDNS-Family-Primary": "208.67.222.123",
    "OpenDNS-Family-Secondary": "208.67.220.123",
    "DNS.SB-Primary": "185.222.222.222",
    "DNS.SB-Secondary": "45.11.45.11",
    "NextDNS-Primary": "45.90.28.39",
    "NextDNS-Secondary": "45.90.30.39",
    "AdGuard-Primary": "94.140.14.14",
    "AdGuard-Secondary": "94.140.15.15",
    "AdGuard-Family-Primary": "94.140.14.15",
    "AdGuard-Family-Secondary": "94.140.15.16",
    "CleanBrowsing-Primary": "185.228.168.9",
    "CleanBrowsing-Secondary": "185.228.169.9",
    "CleanBrowsing-Family": "185.228.168.168",
    "ControlD-Primary": "76.76.2.0",
    "ControlD-Secondary": "76.76.10.0",
    "ControlD-Malware": "76.76.2.1",
    "Mullvad-Primary": "194.242.2.2",
    "Mullvad-Secondary": "194.242.2.3",
    "DNS0.EU-Primary": "193.110.81.0",
    "DNS0.EU-Secondary": "185.253.5.0",
    "Comodo-Primary": "8.26.56.26",
    "Comodo-Secondary": "8.20.247.20",
    "Verisign-Primary": "64.6.64.6",
    "Verisign-Secondary": "64.6.65.6",
}

DNS_SERVERS_IPV6 = {
    "Google-Primary-v6": "2001:4860:4860::8888",
    "Google-Secondary-v6": "2001:4860:4860::8844",
    "Cloudflare-Primary-v6": "2606:4700:4700::1111",
    "Cloudflare-Secondary-v6": "2606:4700:4700::1001",
    "Cloudflare-Family-Primary-v6": "2606:4700:4700::1113",
    "Cloudflare-Family-Secondary-v6": "2606:4700:4700::1003",
    "Quad9-Primary-v6": "2620:fe::fe",
    "Quad9-Secondary-v6": "2620:fe::9",
    "Quad9-Secured-v6": "2620:fe::11",
    "OpenDNS-Primary-v6": "2620:119:35::35",
    "OpenDNS-Secondary-v6": "2620:119:53::53",
    "OpenDNS-Family-v6": "2620:119:35::123",
    "AdGuard-Primary-v6": "2a10:50c0::ad1:ff",
    "AdGuard-Secondary-v6": "2a10:50c0::ad2:ff",
    "AdGuard-Family-Primary-v6": "2a10:50c0::bad1:ff",
    "AdGuard-Family-Secondary-v6": "2a10:50c0::bad2:ff",
    "DNS.SB-Primary-v6": "2a09::",
    "DNS.SB-Secondary-v6": "2a11::",
}


@dataclass
class DNSTestResult:
    server_name: str
    server_ip: str
    average_time: float
    min_time: float
    max_time: float
    success_count: int
    total_count: int
    is_ipv6: bool
    
    @property
    def success_rate(self) -> float:
        if self.total_count == 0:
            return 0.0
        return (self.success_count / self.total_count) * 100

@dataclass
class PingTestResult:
    server_name: str
    server_ip: str
    average_latency: float
    min_latency: float
    max_latency: float
    packet_loss: float
    
@dataclass
class CorrelationResult:
    server_name: str
    server_ip: str
    dns_time: float
    ping_time: float
    correlation_score: float
    is_ipv6: bool
    
    def __post_init__(self):
        self.correlation_score = (self.dns_time * 0.7) + (self.ping_time * 0.3)

class InputValidator:
    IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    
    @staticmethod
    def validate_ipv4(ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def validate_ipv6(ip: str) -> bool:
        try:
            addr = ipaddress.IPv6Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        return InputValidator.validate_ipv4(ip) or InputValidator.validate_ipv6(ip)
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        if not domain or len(domain) > 253:
            return False
        if domain[-1] == ".":
            domain = domain[:-1]
        return bool(InputValidator.DOMAIN_PATTERN.match(domain))
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        filename = os.path.basename(filename)
        filename = re.sub(r'[^\w\-_\. ]', '', filename)
        return filename


class SecureLogger:
    def __init__(self, log_file: Optional[str] = None, verbose: bool = False):
        self.verbose = verbose
        self.lock = Lock()
        
        if log_file is None:
            log_dir = tempfile.gettempdir()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.log_file = os.path.join(log_dir, f'pingerr_{timestamp}.log')
        else:
            self.log_file = log_file
        
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
            ]
        )
        
        self.logger = logging.getLogger('pingerr')
    
    def info(self, message: str):
        with self.lock:
            self.logger.info(message)
            if self.verbose:
                print(f"{Colors.CYAN}[INFO]{Colors.RESET} {message}")
    
    def success(self, message: str):
        with self.lock:
            self.logger.info(f"SUCCESS: {message}")
            if self.verbose:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} {message}")
    
    def warning(self, message: str):
        with self.lock:
            self.logger.warning(message)
            if self.verbose:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} {message}")
    
    def error(self, message: str):
        with self.lock:
            self.logger.error(message)
            if self.verbose:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} {message}")
    
    def debug(self, message: str):
        with self.lock:
            self.logger.debug(message)
            if self.verbose:
                print(f"{Colors.GRAY}[DEBUG]{Colors.RESET} {message}")

class SystemChecker:
    def __init__(self, logger: SecureLogger):
        self.logger = logger
        self.os_type = platform.system()
        self.python_version = sys.version_info
    
    def check_prerequisites(self) -> bool:
        print(f"\n{Colors.CYAN}[*] Checking system requirements...{Colors.RESET}")
        self.logger.info("Checking system prerequisites")
        
        all_checks_passed = True
        
        if self.python_version < (3, 8):
            print(f"{Colors.RED}[!] Error: Python 3.8+ is required{Colors.RESET}")
            self.logger.error(f"Insufficient Python version: {sys.version}")
            return False
        print(f"{Colors.GREEN}[✓] Python version: {sys.version.split()[0]}{Colors.RESET}")
        
        print(f"{Colors.GREEN}[✓] Operating System: {self.os_type}{Colors.RESET}")
        self.logger.info(f"Operating System: {self.os_type}")
        
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=2)
            print(f"{Colors.GREEN}[✓] Network connectivity confirmed{Colors.RESET}")
            self.logger.success("Network connectivity test passed")
        except (socket.error, socket.timeout) as e:
            print(f"{Colors.YELLOW}[!] Warning: Network connectivity issue detected{Colors.RESET}")
            self.logger.warning(f"Network connectivity test failed: {e}")
            all_checks_passed = False
        
        if self.os_type == "Windows":
            print(f"{Colors.GREEN}[✓] Windows DNS tools available{Colors.RESET}")
        else:
            has_dig = self._check_command("dig")
            has_nslookup = self._check_command("nslookup")
            if has_dig or has_nslookup:
                tool = "dig" if has_dig else "nslookup"
                print(f"{Colors.GREEN}[✓] DNS tool available: {tool}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!] Warning: Neither 'dig' nor 'nslookup' found{Colors.RESET}")
                self.logger.warning("DNS query tools not found")
        
        print()
        return all_checks_passed
    
    def _check_command(self, command: str) -> bool:
        try:
            subprocess.run([command, "--version"], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL,
                         timeout=2)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def check_ipv6_support(self) -> bool:
        print(f"{Colors.CYAN}[*] Checking IPv6 connectivity...{Colors.RESET}")
        self.logger.info("Testing IPv6 connectivity")
        
        try:

            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(("2001:4860:4860::8888", 53))
            sock.close()
            print(f"{Colors.GREEN}[✓] IPv6 connectivity is working!{Colors.RESET}\n")
            self.logger.success("IPv6 connectivity test successful")
            return True
        except (socket.error, socket.timeout, OSError) as e:
            print(f"{Colors.YELLOW}[!] IPv6 connectivity not available{Colors.RESET}")
            self.logger.warning(f"IPv6 connectivity test failed: {e}\n")
            return False


class DNSTester:
    
    def __init__(self, logger: SecureLogger, timeout: int = 2):
        self.logger = logger
        self.timeout = timeout
        self.os_type = platform.system()
    
    def test_dns_server(self, server_name: str, server_ip: str, 
                       test_count: int = 5) -> Optional[DNSTestResult]:
        if not InputValidator.validate_ip_address(server_ip):
            self.logger.error(f"Invalid DNS server IP: {server_ip}")
            return None
        
        is_ipv6 = InputValidator.validate_ipv6(server_ip)
        times = []
        success_count = 0
        
        for i in range(test_count):
            domain = TEST_DOMAINS[i % len(TEST_DOMAINS)]

            if not InputValidator.validate_domain(domain):
                self.logger.warning(f"Invalid domain: {domain}")
                continue
            
            response_time = self._query_dns(server_ip, domain, is_ipv6)
            
            if response_time is not None and response_time > 0:
                times.append(response_time)
                success_count += 1
        
        if not times:
            return None
        
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        
        return DNSTestResult(
            server_name=server_name,
            server_ip=server_ip,
            average_time=round(avg_time, 2),
            min_time=round(min_time, 2),
            max_time=round(max_time, 2),
            success_count=success_count,
            total_count=test_count,
            is_ipv6=is_ipv6
        )
    
    def _query_dns(self, dns_server: str, domain: str, is_ipv6: bool) -> Optional[float]:
        try:
            start_time = time.time()
            
            family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            
            result = self._direct_dns_query(dns_server, domain, family)
            
            elapsed_time = (time.time() - start_time) * 1000 
            
            if result:
                return elapsed_time
            return None
            
        except Exception as e:
            self.logger.debug(f"DNS query failed for {dns_server} to {domain}: {e}")
            return None
    
    def _direct_dns_query(self, dns_server: str, domain: str, family: int) -> bool:
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            transaction_id = os.urandom(2)
            flags = b'\x01\x00'  
            questions = b'\x00\x01'  
            answer_rrs = b'\x00\x00'
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'
            
            qname = b''
            for part in domain.split('.'):
                qname += bytes([len(part)]) + part.encode('ascii')
            qname += b'\x00'  
            
            qtype = b'\x00\x01'  
            qclass = b'\x00\x01'  
            
            query = (transaction_id + flags + questions + answer_rrs + 
                    authority_rrs + additional_rrs + qname + qtype + qclass)
            
            sock.sendto(query, (dns_server, 53))
            data, _ = sock.recvfrom(512)
            sock.close()
            return len(data) > 12  
            
        except Exception as e:
            self.logger.debug(f"Direct DNS query failed: {e}")
            return False


class PingTester:
    
    def __init__(self, logger: SecureLogger):
        self.logger = logger
        self.os_type = platform.system()
    
    def test_ping(self, server_name: str, server_ip: str, count: int = 3) -> Optional[PingTestResult]:
        if not InputValidator.validate_ip_address(server_ip):
            self.logger.error(f"Invalid IP address for ping: {server_ip}")
            return None
        
        is_ipv6 = InputValidator.validate_ipv6(server_ip)
        
        try:
            if self.os_type == "Windows":
                ping_cmd = ["ping", "-n", str(count), "-w", "1000"]
                if is_ipv6:
                    ping_cmd = ["ping", "-6", "-n", str(count), "-w", "1000"]
            else: 
                ping_cmd = ["ping", "-c", str(count), "-W", "1"]
                if is_ipv6:
                    ping_cmd = ["ping6", "-c", str(count), "-W", "1"]
            
            ping_cmd.append(server_ip)
            
            result = subprocess.run(
                ping_cmd,
                capture_output=True,
                text=True,
                timeout=count * 2 + 2, 
                check=False
            )
            
            if result.returncode == 0:
                times = self._parse_ping_output(result.stdout)
                if times:
                    avg_latency = statistics.mean(times)
                    min_latency = min(times)
                    max_latency = max(times)
                    packet_loss = ((count - len(times)) / count) * 100
                    
                    return PingTestResult(
                        server_name=server_name,
                        server_ip=server_ip,
                        average_latency=round(avg_latency, 2),
                        min_latency=round(min_latency, 2),
                        max_latency=round(max_latency, 2),
                        packet_loss=round(packet_loss, 2)
                    )
            
            return None
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Ping timeout for {server_ip}")
            return None
        except Exception as e:
            self.logger.debug(f"Ping failed for {server_ip}: {e}")
            return None
    
    def _parse_ping_output(self, output: str) -> List[float]:
        """Parse ping output to extract response times"""
        times = []
        
        patterns = [
            r'time[=<](\d+\.?\d*)\s*ms',  
            r'time=(\d+\.?\d*)\s*ms',      
            r'(\d+\.?\d*)\s*ms', 
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                times = [float(m) for m in matches]
                break
        
        return times

class ParallelTester:
    
    def __init__(self, logger: SecureLogger, max_workers: int = 10):
        self.logger = logger
        self.max_workers = max_workers
        self.dns_tester = DNSTester(logger)
        self.ping_tester = PingTester(logger)
    
    def test_all_dns_servers(self, dns_servers: Dict[str, str], 
                            test_count: int = 5) -> Dict[str, DNSTestResult]:
        print(f"\n{Colors.CYAN}[*] Starting parallel DNS tests (Max: {self.max_workers} concurrent)...{Colors.RESET}\n")
        self.logger.info(f"Initiating parallel DNS testing with {len(dns_servers)} servers")
        
        results = {}
        total = len(dns_servers)
        current = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_server = {
                executor.submit(self.dns_tester.test_dns_server, name, ip, test_count): (name, ip)
                for name, ip in dns_servers.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_server):
                current += 1
                name, ip = future_to_server[future]
                
                try:
                    result = future.result(timeout=test_count * 3)
                    if result:
                        results[name] = result
                        print(f"  [{current:3d}/{total:3d}] {name:40} ({ip:40}) : {Colors.GREEN}{result.average_time:7.2f} ms{Colors.RESET}")
                    else:
                        print(f"  [{current:3d}/{total:3d}] {name:40} ({ip:40}) : {Colors.RED}FAILED{Colors.RESET}")
                except Exception as e:
                    print(f"  [{current:3d}/{total:3d}] {name:40} ({ip:40}) : {Colors.RED}ERROR{Colors.RESET}")
                    self.logger.error(f"DNS test error for {name}: {e}")
        
        print(f"\n{Colors.GREEN}[✓] All DNS tests completed!{Colors.RESET}\n")
        self.logger.success(f"DNS testing completed. Results: {len(results)} working servers")
        
        return results
    
    def test_all_ping(self, dns_results: Dict[str, DNSTestResult]) -> Dict[str, PingTestResult]:
        
        print(f"\n{Colors.CYAN}[*] Starting ping correlation analysis...{Colors.RESET}\n")
        self.logger.info("Initiating ping correlation tests")
        
        results = {}
        total = len(dns_results)
        current = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers * 2) as executor:
            future_to_server = {
                executor.submit(self.ping_tester.test_ping, name, result.server_ip): name
                for name, result in dns_results.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_server):
                current += 1
                name = future_to_server[future]
                
                try:
                    result = future.result(timeout=10)
                    if result:
                        results[name] = result
                        print(f"  [{current:3d}/{total:3d}] {name:40} : Ping {Colors.GREEN}{result.average_latency:7.2f} ms{Colors.RESET}")
                    else:
                        print(f"  [{current:3d}/{total:3d}] {name:40} : Ping {Colors.YELLOW}FAILED{Colors.RESET}")
                except Exception as e:
                    print(f"  [{current:3d}/{total:3d}] {name:40} : Ping {Colors.YELLOW}ERROR{Colors.RESET}")
                    self.logger.error(f"Ping test error for {name}: {e}")
        
        print(f"\n{Colors.GREEN}[✓] Ping correlation tests completed!{Colors.RESET}\n")
        self.logger.success("Ping correlation testing completed")
        
        return results

class ResultsDisplay:
    
    @staticmethod
    def show_banner():
        print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
        print(f"  {Colors.GRAY}Version: {VERSION} | Platform: {platform.system()}")
        print()
    
    @staticmethod
    def show_dns_results(results: Dict[str, DNSTestResult], title: str):
        if not results:
            return
        
        sorted_results = sorted(results.items(), key=lambda x: x[1].average_time)
        
        print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║  {title:79}║{Colors.RESET}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
        
        print("┌──────┬──────────────────────────────────────┬─────────────────────────────────────┬───────────┐")
        print("│ Rank │ DNS Server                           │ IP Address                          │ Avg Time  │")
        print("├──────┼──────────────────────────────────────┼─────────────────────────────────────┼───────────┤")
        
        for rank, (name, result) in enumerate(sorted_results, 1):
            if result.average_time < 50:
                color = Colors.GREEN
            elif result.average_time < 100:
                color = Colors.YELLOW
            else:
                color = Colors.RED
            
            print(f"│ {rank:4} │ {name:36} │ {result.server_ip:35} │ {color}{result.average_time:7.2f} ms{Colors.RESET} │")
        
        print("└──────┴──────────────────────────────────────┴─────────────────────────────────────┴───────────┘")
    
    @staticmethod
    def show_correlation_results(results: Dict[str, CorrelationResult], title: str):
        if not results:
            return
        sorted_results = sorted(results.items(), key=lambda x: x[1].correlation_score)
        
        print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║  {title:79}║{Colors.RESET}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
        
        print("┌──────┬──────────────────────────────────────┬──────────┬──────────┬────────────┬──────────────┐")
        print("│ Rank │ DNS Server                           │ DNS (ms) │ Ping(ms) │ Difference │ Score        │")
        print("├──────┼──────────────────────────────────────┼──────────┼──────────┼────────────┼──────────────┤")
        
        for rank, (name, result) in enumerate(sorted_results, 1):
            diff = result.ping_time - result.dns_time
            if result.correlation_score < 50:
                score_color = Colors.GREEN
            elif result.correlation_score < 100:
                score_color = Colors.YELLOW
            else:
                score_color = Colors.RED
            
            if diff < 50:
                diff_color = Colors.GREEN
            elif diff < 150:
                diff_color = Colors.YELLOW
            else:
                diff_color = Colors.RED
            
            print(f"│ {rank:4} │ {name:36} │ {result.dns_time:8.2f} │ {result.ping_time:8.2f} │ "
                  f"{diff_color}{diff:10.2f}{Colors.RESET} │ {score_color}{result.correlation_score:12.2f}{Colors.RESET} │")
        
        print("└──────┴──────────────────────────────────────┴──────────┴──────────┴────────────┴──────────────┘")
    
    @staticmethod
    def show_statistics(dns_results: Dict[str, DNSTestResult], total_tested: int, ipv6_enabled: bool):
        ipv4_count = sum(1 for r in dns_results.values() if not r.is_ipv6)
        ipv6_count = sum(1 for r in dns_results.values() if r.is_ipv6)
        
        print(f"\n{Colors.GREEN}Statistics:{Colors.RESET}")
        print(f"  Total Tested: {total_tested}")
        print(f"  Working: {Colors.GREEN}{len(dns_results)}{Colors.RESET} (IPv4: {ipv4_count}, IPv6: {ipv6_count})")
        print(f"  Failed: {Colors.RED}{total_tested - len(dns_results)}{Colors.RESET}")
        print()
    
    @staticmethod
    def show_best_servers(dns_results: Dict[str, DNSTestResult], 
                         correlation_results: Dict[str, CorrelationResult]):
        if not dns_results:
            return
        
        best_dns = min(dns_results.items(), key=lambda x: x[1].average_time)
        
        print("═" * 95)
        print(f"{Colors.GREEN}🏆 BEST DNS SERVER OVERALL: {best_dns[0]}{Colors.RESET}")
        print(f"   IP Address: {best_dns[1].server_ip}")
        print(f"   Average Response Time: {Colors.GREEN}{best_dns[1].average_time:.2f} ms{Colors.RESET}")
        print("═" * 95)
        print()
        
        if correlation_results:
            best_corr = min(correlation_results.items(), key=lambda x: x[1].correlation_score)
            print(f"{Colors.GREEN}🏅 BEST OVERALL PERFORMANCE (DNS + Network):{Colors.RESET} {best_corr[0]}")
            print(f"   IP: {best_corr[1].server_ip}")
            print(f"   DNS Query: {Colors.GREEN}{best_corr[1].dns_time:.2f}ms{Colors.RESET}, "
                  f"Ping: {Colors.GREEN}{best_corr[1].ping_time:.2f}ms{Colors.RESET}, "
                  f"Score: {Colors.GREEN}{best_corr[1].correlation_score:.2f}{Colors.RESET}")
            print()
    
    @staticmethod
    def show_configuration_guide(results: Dict[str, DNSTestResult]):
        if len(results) < 2:
            return
        
        sorted_results = sorted(results.items(), key=lambda x: x[1].average_time)
        primary = sorted_results[0]
        secondary = sorted_results[1]
        
        print("\n" + "═" * 95)
        print(f"{Colors.BLUE}                    CONFIGURATION RECOMMENDATION{Colors.RESET}")
        print("═" * 95)
        print()
        print(f"{Colors.GREEN}RECOMMENDED DNS CONFIGURATION:{Colors.RESET}")
        print(f"  Primary DNS:   {Colors.CYAN}{primary[1].server_ip:15}{Colors.RESET} ({primary[0]} - {primary[1].average_time:.2f}ms)")
        print(f"  Secondary DNS: {Colors.CYAN}{secondary[1].server_ip:15}{Colors.RESET} ({secondary[0]} - {secondary[1].average_time:.2f}ms)")
        print()

class ResultsExporter:
    @staticmethod
    def export_to_csv(dns_results: Dict[str, DNSTestResult], 
                     correlation_results: Dict[str, CorrelationResult],
                     filename: str, logger: SecureLogger):
        try:
            filename = InputValidator.sanitize_filename(filename)
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['DNSServer', 'IPAddress', 'DNSResponseTime', 
                            'PingLatency', 'CorrelationScore', 'IsIPv6', 'Timestamp']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                for name, dns_result in dns_results.items():
                    ping_latency = 'N/A'
                    corr_score = 'N/A'
                    
                    if name in correlation_results:
                        ping_latency = f"{correlation_results[name].ping_time:.2f}"
                        corr_score = f"{correlation_results[name].correlation_score:.2f}"
                    
                    writer.writerow({
                        'DNSServer': name,
                        'IPAddress': dns_result.server_ip,
                        'DNSResponseTime': f"{dns_result.average_time:.2f}",
                        'PingLatency': ping_latency,
                        'CorrelationScore': corr_score,
                        'IsIPv6': str(dns_result.is_ipv6),
                        'Timestamp': timestamp
                    })
            
            print(f"\n{Colors.GREEN}[✓] Results exported to: {filename}{Colors.RESET}")
            logger.success(f"Results exported successfully to {filename}")
            
        except Exception as e:
            print(f"\n{Colors.RED}[!] Failed to export results: {e}{Colors.RESET}")
            logger.error(f"Export failed: {e}")
    
    @staticmethod
    def export_to_json(dns_results: Dict[str, DNSTestResult],
                      correlation_results: Dict[str, CorrelationResult],
                      filename: str, logger: SecureLogger):
        try:
            filename = InputValidator.sanitize_filename(filename)
            
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'platform': platform.system(),
                'dns_results': {},
                'correlation_results': {}
            }
            
            for name, result in dns_results.items():
                export_data['dns_results'][name] = asdict(result)
            
            for name, result in correlation_results.items():
                export_data['correlation_results'][name] = asdict(result)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"\n{Colors.GREEN}[✓] Results exported to: {filename}{Colors.RESET}")
            logger.success(f"Results exported successfully to {filename}")
            
        except Exception as e:
            print(f"\n{Colors.RED}[!] Failed to export results: {e}{Colors.RESET}")
            logger.error(f"Export failed: {e}")


class PingerrApp:
    
    def __init__(self, args):
        self.args = args
        self.logger = SecureLogger(
            log_file=args.log_file,
            verbose=args.verbose
        )
        
        if not sys.stdout.isatty() or platform.system() == 'Windows':
            if platform.system() == 'Windows':
                try:
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                except:
                    Colors.disable_colors()
            else:
                Colors.disable_colors()
        
        self.system_checker = SystemChecker(self.logger)
        self.parallel_tester = ParallelTester(self.logger, args.max_parallel)
    
    def run(self):
        try:
            ResultsDisplay.show_banner()

            print("═" * 95)
            print()
            print(f"  {Colors.CYAN}Test Configuration:{Colors.RESET}")
            print(f"    • Tests per server: {self.args.test_count}")
            print(f"    • Max parallel tests: {self.args.max_parallel}")
            print(f"    • Timeout: {self.args.timeout} seconds")
            print(f"    • IPv6: {'Disabled' if self.args.skip_ipv6 else 'Enabled (if available)'}")
            print(f"    • Log file: {self.logger.log_file}")
            print()
            print("═" * 95)
            
            if not self.system_checker.check_prerequisites():
                print(f"{Colors.RED}[!] System checks failed. Exiting.{Colors.RESET}")
                return 1
            
            ipv6_enabled = False if self.args.skip_ipv6 else self.system_checker.check_ipv6_support()
            
            all_servers = DNS_SERVERS_IPV4.copy()
            if ipv6_enabled:
                print(f"{Colors.GREEN}[i] Including IPv6 DNS servers in tests{Colors.RESET}\n")
                all_servers.update(DNS_SERVERS_IPV6)
            
            print(f"{Colors.CYAN}[*] Total DNS servers to test: {len(all_servers)}{Colors.RESET}")
            print(f"    • IPv4 servers: {len(DNS_SERVERS_IPV4)}")
            if ipv6_enabled:
                print(f"    • IPv6 servers: {len(DNS_SERVERS_IPV6)}")
            print(f"    • Test domains: {len(TEST_DOMAINS)}")
            
            dns_results = self.parallel_tester.test_all_dns_servers(
                all_servers,
                self.args.test_count
            )
            
            ipv4_results = {k: v for k, v in dns_results.items() if not v.is_ipv6}
            ipv6_results = {k: v for k, v in dns_results.items() if v.is_ipv6}
            
            if ipv4_results:
                ResultsDisplay.show_dns_results(ipv4_results, "IPv4 DNS SERVERS - RANKED BY SPEED")
            
            if ipv6_results:
                ResultsDisplay.show_dns_results(ipv6_results, "IPv6 DNS SERVERS - RANKED BY SPEED")
            
            ResultsDisplay.show_statistics(dns_results, len(all_servers), ipv6_enabled)
            
            ping_results = self.parallel_tester.test_all_ping(dns_results)
            
            correlation_results = {}
            for name, dns_result in dns_results.items():
                if name in ping_results:
                    correlation_results[name] = CorrelationResult(
                        server_name=name,
                        server_ip=dns_result.server_ip,
                        dns_time=dns_result.average_time,
                        ping_time=ping_results[name].average_latency,
                        correlation_score=0, 
                        is_ipv6=dns_result.is_ipv6
                    )
            
            ipv4_corr = {k: v for k, v in correlation_results.items() if not v.is_ipv6}
            ipv6_corr = {k: v for k, v in correlation_results.items() if v.is_ipv6}
            
            if ipv4_corr:
                ResultsDisplay.show_correlation_results(ipv4_corr, "IPv4 DNS-PING CORRELATION RESULTS")
            
            if ipv6_corr:
                ResultsDisplay.show_correlation_results(ipv6_corr, "IPv6 DNS-PING CORRELATION RESULTS")
            
            print(f"\n{Colors.GRAY}[i] Score Calculation: (DNS Query Time × 70% + Ping Latency × 30%){Colors.RESET}")
            print(f"{Colors.GRAY}[i] Lower score = Better overall performance{Colors.RESET}\n")
            
            ResultsDisplay.show_best_servers(dns_results, correlation_results)
            
            ResultsDisplay.show_configuration_guide(dns_results)
            
            if self.args.export_csv:
                ResultsExporter.export_to_csv(
                    dns_results,
                    correlation_results,
                    self.args.export_csv,
                    self.logger
                )
            
            if self.args.export_json:
                ResultsExporter.export_to_json(
                    dns_results,
                    correlation_results,
                    self.args.export_json,
                    self.logger
                )
            
            print("\n" + "═" * 95)
            print(f"{Colors.GREEN}[✓] Testing complete! Thank you for using Pingerr.{Colors.RESET}")
            print("═" * 95)
            print()
            print(f"{Colors.GRAY}[i] Log file saved: {self.logger.log_file}{Colors.RESET}")
            print()
            
            self.logger.success("Pingerr test session completed successfully")
            return 0
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Test interrupted by user{Colors.RESET}")
            self.logger.warning("Test interrupted by user (Ctrl+C)")
            return 130
        except Exception as e:
            print(f"\n{Colors.RED}[!] FATAL ERROR: {e}{Colors.RESET}")
            self.logger.error(f"Fatal error occurred: {e}")
            import traceback
            traceback.print_exc()
            return 1


def main():
    parser = argparse.ArgumentParser(
        description='Pingerr - DNS Speed Test Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""

Examples:
  %(prog)s                              # Basic test with defaults
  %(prog)s -t 3 -p 20                   # Quick test (3 iterations, 20 parallel)
  %(prog)s --skip-ipv6                  # Skip IPv6 tests
  %(prog)s --export-csv results.csv     # Export to CSV
  %(prog)s -v --export-json out.json    # Verbose with JSON export
        """
    )
    
    parser.add_argument(
        '-t', '--test-count',
        type=int,
        default=5,
        metavar='N',
        help='Number of tests per DNS server (1-10, default: 5)'
    )
    
    parser.add_argument(
        '-p', '--max-parallel',
        type=int,
        default=10,
        metavar='N',
        help='Maximum parallel tests (1-50, default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=2,
        metavar='SEC',
        help='Timeout in seconds for DNS queries (1-10, default: 2)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging output'
    )
    
    parser.add_argument(
        '--skip-ipv6',
        action='store_true',
        help='Skip all IPv6 DNS servers'
    )
    
    parser.add_argument(
        '--export-csv',
        metavar='FILE',
        help='Export results to CSV file'
    )
    
    parser.add_argument(
        '--export-json',
        metavar='FILE',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '--log-file',
        metavar='FILE',
        help='Custom log file path (default: temp directory)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )
    
    args = parser.parse_args()
    
    if not (1 <= args.test_count <= 10):
        parser.error("test-count must be between 1 and 10")
    
    if not (1 <= args.max_parallel <= 50):
        parser.error("max-parallel must be between 1 and 50")
    
    if not (1 <= args.timeout <= 10):
        parser.error("timeout must be between 1 and 10")
    
    app = PingerrApp(args)
    sys.exit(app.run())

if __name__ == "__main__":
    main()
