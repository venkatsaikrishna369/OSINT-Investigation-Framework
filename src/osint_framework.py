# src/osint_framework_final.py

import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any
import whois
import dns.resolver
import ssl
import socket
import requests
from bs4 import BeautifulSoup
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import logging
import os
import sys
import csv
import re
import hashlib
import base64
from urllib.parse import urlparse, urljoin
import base64

# Fix for Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

class FinalOSINTFramework:
    def __init__(self, target: str):
        self.target = target
        self.session = None
        self.start_time = datetime.now()
        self.results = {
            'target': target,
            'collection_date': self.start_time.isoformat(),
            'data': {},
            'sources': [],
            'findings': [],
            'risk_assessment': {},
            'recommendations': [],
            'timeline': []
        }
        self.source_tracker = SourceTracker()
        self.output_dir = 'reports'
        os.makedirs(self.output_dir, exist_ok=True)
        
    async def run_full_investigation(self):
        """Execute complete OSINT investigation workflow"""
        print(f"[START] OSINT Investigation for {self.target}")
        print("=" * 70)
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Phase 1: Target Definition
            print("[Phase 1] Target Definition")
            self.define_target()
            
            # Phase 2: Domain Intelligence
            print("[Phase 2] Domain Intelligence")
            await self.collect_domain_intelligence()
            
            # Phase 3: DNS Intelligence
            print("[Phase 3] DNS Intelligence")
            await self.collect_dns_intelligence()
            
            # Phase 4: IP & ASN Intelligence
            print("[Phase 4] IP & ASN Intelligence")
            await self.collect_ip_intelligence()
            
            # Phase 5: SSL/TLS Intelligence
            print("[Phase 5] SSL/TLS Intelligence")
            await self.collect_ssl_intelligence()
            
            # Phase 6: Security Headers
            print("[Phase 6] Security Headers Analysis")
            await self.collect_headers()
            
            # Phase 7: Technology Intelligence
            print("[Phase 7] Technology Fingerprinting")
            await self.collect_technologies()
            
            # Phase 8: Subdomain Discovery
            print("[Phase 8] Subdomain Discovery")
            await self.collect_subdomains()
            
            # Phase 9: Web Content Analysis
            print("[Phase 9] Web Content Analysis")
            await self.analyze_web_content()
            
            # Phase 10: robots.txt & Sitemap
            print("[Phase 10] robots.txt & Sitemap")
            await self.analyze_robots_sitemap()
            
            # Phase 11: Additional OSINT
            print("[Phase 11] Additional OSINT")
            await self.additional_osint()
            
            # Phase 12: Intelligence Correlation
            print("[Phase 12] Intelligence Correlation")
            self.correlate_intelligence()
            
            # Phase 13: Risk Assessment
            print("[Phase 13] Risk Assessment")
            self.assess_risks()
            
            # Phase 14: Timeline Generation
            print("[Phase 14] Intelligence Timeline")
            self.generate_timeline()
            
            # Phase 15: Report Generation
            print("[Phase 15] Report Generation")
            await self.generate_report()
            
            print("\n[COMPLETE] Investigation Complete!")
            print(f"Results saved to: {self.output_dir}/")
            print(f"HTML Report: {self.output_dir}/osint_report.html")
            print(f"PDF Report: {self.output_dir}/osint_report.pdf")
            print(f"JSON Data: {self.output_dir}/intelligence.json")

    async def collect_domain_intelligence(self):
        """Collect WHOIS and domain registration information"""
        try:
            domain_info = whois.whois(self.target)
            
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            data = {
                'registrar': str(domain_info.registrar) if domain_info.registrar else 'Unknown',
                'creation_date': str(creation_date) if creation_date else 'Unknown',
                'expiration_date': str(expiration_date) if expiration_date else 'Unknown',
                'updated_date': str(domain_info.updated_date) if domain_info.updated_date else 'Unknown',
                'nameservers': domain_info.name_servers if domain_info.name_servers else [],
                'domain_status': domain_info.status if domain_info.status else [],
                'domain_age_days': self.calculate_domain_age(creation_date),
                'days_until_expiry': self.calculate_days_until_expiry(expiration_date),
                'registrant': str(domain_info.registrant) if domain_info.registrant else 'Redacted/Private'
            }
            
            self.results['data']['domain'] = data
            self.source_tracker.add_source('SRC-001', 'WHOIS', 'domain_registration', 
                                         f'whois:{self.target}', 'High')
            print(f"  -> Domain registration collected (Age: {data['domain_age_days']} days)")
            
        except Exception as e:
            self.results['data']['domain'] = {'error': str(e), 'domain_age_days': 0}
            self.source_tracker.add_source('SRC-001', 'WHOIS', 'domain_registration', 
                                         f'whois:{self.target}', 'Low')
            print(f"  -> Domain collection error: {str(e)}")

    def calculate_domain_age(self, creation_date):
        """Calculate domain age in days"""
        if not creation_date:
            return 0
        try:
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            return (datetime.now() - creation_date).days
        except:
            return 0

    def calculate_days_until_expiry(self, expiration_date):
        """Calculate days until domain expiry"""
        if not expiration_date:
            return 0
        try:
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
            return (expiration_date - datetime.now()).days
        except:
            return 0

    async def collect_dns_intelligence(self):
        """Collect DNS records with additional record types"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'CNAME', 'SOA', 'SRV']
        dns_data = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(r) for r in answers]
                dns_data[record_type] = records
                self.source_tracker.add_source(f'SRC-DNS-{record_type}', 'DNS Resolver', 
                                             f'DNS {record_type}', f'dns:{self.target}', 'High')
            except Exception:
                dns_data[record_type] = []
        
        # Parse TXT records for SPF
        txt_records = dns_data.get('TXT', [])
        for record in txt_records:
            if 'v=spf1' in record:
                dns_data['SPF'] = record
        
        self.results['data']['dns'] = dns_data
        print(f"  -> DNS records collected: {len([k for k,v in dns_data.items() if v])} types")

    async def collect_ip_intelligence(self):
        """Collect IP intelligence with ASN and geolocation"""
        try:
            ip_addresses = dns.resolver.resolve(self.target, 'A')
            ip_data = {}
            
            for ip in ip_addresses:
                ip_str = str(ip)
                ip_info = await self.get_comprehensive_ip_info(ip_str)
                reverse_dns = await self.get_reverse_dns(ip_str)
                
                ip_data[ip_str] = {
                    'asn': ip_info.get('asn'),
                    'asn_org': ip_info.get('org'),
                    'isp': ip_info.get('isp'),
                    'country': ip_info.get('country'),
                    'country_code': ip_info.get('country_code'),
                    'region': ip_info.get('region'),
                    'city': ip_info.get('city'),
                    'postal': ip_info.get('postal'),
                    'timezone': ip_info.get('timezone'),
                    'latitude': ip_info.get('lat'),
                    'longitude': ip_info.get('lon'),
                    'network': ip_info.get('network'),
                    'reverse_dns': reverse_dns,
                    'hosting_type': self.detect_hosting_type(ip_info)
                }
                
            self.results['data']['ip'] = ip_data
            self.source_tracker.add_source('SRC-IP-001', 'IP Intelligence', 
                                         'IP Resolution', f'ip:{self.target}', 'High')
            print(f"  -> IP intelligence collected for {len(ip_data)} addresses")
            
        except Exception as e:
            self.results['data']['ip'] = {'error': str(e)}
            print(f"  -> IP collection error: {str(e)}")

    async def get_comprehensive_ip_info(self, ip):
        """Get comprehensive IP information"""
        info = {}
        try:
            async with self.session.get(f'http://ip-api.com/json/{ip}', timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    info.update({
                        'asn': data.get('as', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'postal': data.get('zip', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                        'network': data.get('isp', 'Unknown')
                    })
        except Exception:
            pass
        return info

    def detect_hosting_type(self, ip_info):
        """Detect hosting type based on ASN and organization"""
        org = ip_info.get('org', '').lower()
        asn = ip_info.get('asn', '').lower()
        
        if 'cloudflare' in org or 'cloudflare' in asn:
            return 'CDN (Cloudflare)'
        elif 'amazon' in org or 'aws' in org:
            return 'Cloud (AWS)'
        elif 'google' in org or 'cloud' in org:
            return 'Cloud (Google)'
        elif 'microsoft' in org or 'azure' in org:
            return 'Cloud (Azure)'
        elif 'digitalocean' in org:
            return 'Cloud (DigitalOcean)'
        else:
            return 'Traditional Hosting'

    async def get_reverse_dns(self, ip):
        """Get reverse DNS for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    async def collect_ssl_intelligence(self):
        """Collect SSL/TLS certificate intelligence"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    ssl_data = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subjectAltName': cert.get('subjectAltName', []),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'cipher_suite': cipher[0] if cipher else 'Unknown',
                        'cipher_protocol': cipher[1] if cipher else 'Unknown',
                        'cipher_key_bits': cipher[2] if cipher else 0,
                        'signature_algorithm': ssock.getpeercert().get('signatureAlgorithm', 'Unknown'),
                        'days_until_expiry': self.calculate_days_until_expiry(cert['notAfter'])
                    }
                    
                    self.results['data']['ssl'] = ssl_data
                    self.source_tracker.add_source('SRC-SSL-001', 'Certificate Transparency', 
                                                 'SSL Certificate', f'https://{self.target}', 'High')
                    print(f"  -> SSL certificate collected (Expires in {ssl_data['days_until_expiry']} days)")
                    
        except Exception as e:
            self.results['data']['ssl'] = {'error': str(e)}
            print(f"  -> SSL collection error: {str(e)}")

    async def collect_headers(self):
        """Collect security headers with analysis"""
        try:
            async with self.session.get(f'https://{self.target}', timeout=10) as response:
                headers = dict(response.headers)
                
                security_headers = {
                    'content-security-policy': {
                        'value': headers.get('content-security-policy', 'MISSING'),
                        'status': 'Present' if 'content-security-policy' in headers else 'Missing',
                        'score': 2 if 'content-security-policy' in headers else 0
                    },
                    'strict-transport-security': {
                        'value': headers.get('strict-transport-security', 'MISSING'),
                        'status': 'Present' if 'strict-transport-security' in headers else 'Missing',
                        'score': 2 if 'strict-transport-security' in headers else 0
                    },
                    'x-content-type-options': {
                        'value': headers.get('x-content-type-options', 'MISSING'),
                        'status': 'Present' if 'x-content-type-options' in headers else 'Missing',
                        'score': 1 if 'x-content-type-options' in headers else 0
                    },
                    'x-frame-options': {
                        'value': headers.get('x-frame-options', 'MISSING'),
                        'status': 'Present' if 'x-frame-options' in headers else 'Missing',
                        'score': 1 if 'x-frame-options' in headers else 0
                    },
                    'referrer-policy': {
                        'value': headers.get('referrer-policy', 'MISSING'),
                        'status': 'Present' if 'referrer-policy' in headers else 'Missing',
                        'score': 1 if 'referrer-policy' in headers else 0
                    },
                    'permissions-policy': {
                        'value': headers.get('permissions-policy', 'MISSING'),
                        'status': 'Present' if 'permissions-policy' in headers else 'Missing',
                        'score': 1 if 'permissions-policy' in headers else 0
                    },
                    'cache-control': {
                        'value': headers.get('cache-control', 'MISSING'),
                        'status': 'Present' if 'cache-control' in headers else 'Missing',
                        'score': 1 if 'cache-control' in headers else 0
                    },
                    'server': {
                        'value': headers.get('server', 'MISSING'),
                        'status': 'Present' if 'server' in headers else 'Missing',
                        'score': 0
                    },
                    'x-powered-by': {
                        'value': headers.get('x-powered-by', 'MISSING'),
                        'status': 'Present' if 'x-powered-by' in headers else 'Missing',
                        'score': -1 if 'x-powered-by' in headers else 0
                    },
                    'x-xss-protection': {
                        'value': headers.get('x-xss-protection', 'MISSING'),
                        'status': 'Present' if 'x-xss-protection' in headers else 'Missing',
                        'score': 1 if 'x-xss-protection' in headers else 0
                    }
                }
                
                total_score = sum(h['score'] for h in security_headers.values())
                max_score = 12
                security_score_percentage = int((total_score / max_score) * 100) if max_score > 0 else 0
                
                self.results['data']['headers'] = {
                    'raw': headers,
                    'security_headers': security_headers,
                    'security_score': total_score,
                    'security_score_percentage': security_score_percentage,
                    'headers_count': len(headers)
                }
                
                self.source_tracker.add_source('SRC-HDR-001', 'HTTP Headers', 
                                             'Security Headers', f'https://{self.target}', 'High')
                print(f"  -> Security headers collected (Score: {security_score_percentage}%)")
                
        except Exception as e:
            self.results['data']['headers'] = {'error': str(e)}
            print(f"  -> Headers collection error: {str(e)}")

    async def collect_technologies(self):
        """Technology fingerprinting"""
        technologies = {
            'web_server': [],
            'frontend_frameworks': [],
            'javascript_libraries': [],
            'css_frameworks': [],
            'analytics': [],
            'cdn': [],
            'hosting_platform': [],
            'cms': [],
            'ecommerce': [],
            'security_services': []
        }
        
        try:
            async with self.session.get(f'https://{self.target}', timeout=10) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Check meta tags
                meta_generator = soup.find('meta', {'name': 'generator'})
                if meta_generator:
                    generator = meta_generator.get('content', '')
                    if 'wordpress' in generator.lower():
                        technologies['cms'].append('WordPress')
                
                # Check for framework indicators
                if soup.find('script', {'src': re.compile(r'react|React|ReactDOM')}):
                    technologies['frontend_frameworks'].append('React')
                if soup.find('script', {'src': re.compile(r'angular|Angular')}):
                    technologies['frontend_frameworks'].append('Angular')
                if soup.find('script', {'src': re.compile(r'vue|Vue')}):
                    technologies['frontend_frameworks'].append('Vue.js')
                
                # Check for jQuery
                if soup.find('script', {'src': re.compile(r'jquery|jQuery')}):
                    technologies['javascript_libraries'].append('jQuery')
                
                # Check for Bootstrap
                if soup.find('link', {'href': re.compile(r'bootstrap|Bootstrap')}):
                    technologies['css_frameworks'].append('Bootstrap')
                if soup.find('link', {'href': re.compile(r'tailwind|Tailwind')}):
                    technologies['css_frameworks'].append('Tailwind CSS')
                
                # Check server headers
                if 'server' in response.headers:
                    server = response.headers['server']
                    technologies['web_server'].append(server)
                
                # Check for CDN
                if 'cloudflare' in str(response.headers).lower():
                    technologies['cdn'].append('Cloudflare')
                
                # Check for security services
                if 'cf-ray' in response.headers:
                    technologies['security_services'].append('Cloudflare')
                
                self.results['data']['technologies'] = technologies
                self.source_tracker.add_source('SRC-TECH-001', 'Technology Detection', 
                                             'Tech Stack', f'https://{self.target}', 'Medium')
                
                total_techs = sum(len(v) for v in technologies.values())
                print(f"  -> Technologies detected: {total_techs}")
                
        except Exception as e:
            self.results['data']['technologies'] = {'error': str(e)}
            print(f"  -> Technology detection error: {str(e)}")

    async def collect_subdomains(self):
        """Subdomain discovery using multiple sources"""
        subdomains = set()
        sources = {}
        
        # 1. Certificate Transparency logs
        try:
            async with self.session.get(f'https://crt.sh/?q=%25.{self.target}&output=json', timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    crt_subdomains = set()
                    for entry in data:
                        if 'name_value' in entry:
                            names = entry['name_value'].split('\n')
                            for name in names:
                                if self.target in name and name not in crt_subdomains:
                                    crt_subdomains.add(name)
                    subdomains.update(crt_subdomains)
                    sources['crt.sh'] = len(crt_subdomains)
        except Exception:
            sources['crt.sh'] = 0
        
        # 2. DNS brute force
        common_subdomains = ['www', 'mail', 'admin', 'api', 'cdn', 'dev', 'test', 'staging', 
                           'ftp', 'blog', 'shop', 'app', 'docs', 'support', 'help', 'status']
        
        dns_subdomains = set()
        for sub in common_subdomains:
            try:
                dns.resolver.resolve(f'{sub}.{self.target}', 'A')
                dns_subdomains.add(f'{sub}.{self.target}')
            except Exception:
                pass
        subdomains.update(dns_subdomains)
        sources['DNS Brute Force'] = len(dns_subdomains)
        
        self.results['data']['subdomains'] = {
            'discovered': list(subdomains),
            'count': len(subdomains),
            'sources': sources
        }
        
        self.source_tracker.add_source('SRC-SUB-001', 'Certificate Transparency', 
                                     'Subdomain Discovery', f'ct:{self.target}', 'High')
        print(f"  -> Subdomains discovered: {len(subdomains)} from {len(sources)} sources")

    async def analyze_web_content(self):
        """Analyze web content for additional intelligence"""
        try:
            async with self.session.get(f'https://{self.target}', timeout=10) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                page_info = {
                    'title': soup.title.string if soup.title else 'No title',
                    'meta_description': '',
                    'meta_keywords': '',
                    'links': {'internal': [], 'external': [], 'scripts': [], 'stylesheets': []},
                    'emails': [],
                    'social_links': []
                }
                
                # Extract meta tags
                for meta in soup.find_all('meta'):
                    if meta.get('name') == 'description':
                        page_info['meta_description'] = meta.get('content', '')
                    if meta.get('name') == 'keywords':
                        page_info['meta_keywords'] = meta.get('content', '')
                
                # Extract emails
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails = re.findall(email_pattern, html)
                if emails:
                    page_info['emails'] = list(set(emails))
                
                self.results['data']['web_content'] = page_info
                self.source_tracker.add_source('SRC-WEB-001', 'Web Content', 
                                             'Page Analysis', f'https://{self.target}', 'Medium')
                print(f"  -> Web content analyzed")
                
        except Exception as e:
            self.results['data']['web_content'] = {'error': str(e)}
            print(f"  -> Web content error: {str(e)}")

    async def analyze_robots_sitemap(self):
        """Analyze robots.txt and sitemap"""
        robots_data = {}
        sitemap_data = {}
        
        # Check robots.txt
        try:
            async with self.session.get(f'https://{self.target}/robots.txt', timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    robots_data = {
                        'exists': True,
                        'content': content,
                        'disallowed_paths': self.extract_disallowed_paths(content),
                        'sitemap': self.extract_sitemap_url(content)
                    }
                    self.source_tracker.add_source('SRC-ROB-001', 'robots.txt', 
                                                 'Robots Analysis', f'https://{self.target}/robots.txt', 'High')
                    print(f"  -> robots.txt found with {len(robots_data['disallowed_paths'])} disallowed paths")
                else:
                    robots_data = {'exists': False}
        except Exception as e:
            robots_data = {'exists': False, 'error': str(e)}
        
        # Check sitemap
        try:
            async with self.session.get(f'https://{self.target}/sitemap.xml', timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    sitemap_data = {
                        'exists': True,
                        'content': content,
                        'urls': self.extract_urls_from_sitemap(content),
                        'count': len(self.extract_urls_from_sitemap(content))
                    }
                    self.source_tracker.add_source('SRC-SIT-001', 'Sitemap', 
                                                 'Sitemap Analysis', f'https://{self.target}/sitemap.xml', 'High')
                    print(f"  -> sitemap.xml found with {sitemap_data['count']} URLs")
                else:
                    sitemap_data = {'exists': False}
        except Exception as e:
            sitemap_data = {'exists': False, 'error': str(e)}
        
        self.results['data']['robots'] = robots_data
        self.results['data']['sitemap'] = sitemap_data

    async def additional_osint(self):
        """Additional OSINT collection"""
        additional = {
            'public_files': []
        }
        
        # Check for common public files
        public_files = ['humans.txt', 'security.txt', '.well-known/security.txt']
        
        for file_path in public_files:
            try:
                async with self.session.get(f'https://{self.target}/{file_path}', timeout=5) as response:
                    if response.status == 200:
                        additional['public_files'].append({
                            'path': file_path,
                            'status': response.status
                        })
            except Exception:
                pass
        
        self.results['data']['additional_osint'] = additional
        print(f"  -> Additional OSINT collected ({len(additional['public_files'])} public files)")

    def correlate_intelligence(self):
        """Intelligence correlation"""
        correlation = {
            'infrastructure_map': {},
            'security_observations': []
        }
        
        # Build infrastructure relationships
        if 'ip' in self.results['data'] and 'dns' in self.results['data']:
            for ip, ip_data in self.results['data']['ip'].items():
                correlation['infrastructure_map'][ip] = {
                    'dns_records': self.results['data']['dns'].get('A', []),
                    'asn': ip_data.get('asn'),
                    'organization': ip_data.get('asn_org'),
                    'hosting_type': ip_data.get('hosting_type'),
                    'country': ip_data.get('country')
                }
        
        # Analyze security headers
        if 'headers' in self.results['data']:
            headers_data = self.results['data']['headers']
            if 'security_headers' in headers_data:
                for header, info in headers_data['security_headers'].items():
                    if info['status'] == 'Missing' and header not in ['server', 'x-powered-by']:
                        correlation['security_observations'].append({
                            'type': 'Missing Security Header',
                            'header': header,
                            'severity': 'Medium'
                        })
        
        # Analyze SSL certificate
        if 'ssl' in self.results['data'] and 'days_until_expiry' in self.results['data']['ssl']:
            days = self.results['data']['ssl']['days_until_expiry']
            if days < 30:
                correlation['security_observations'].append({
                    'type': 'Certificate Expiry',
                    'header': 'SSL Certificate',
                    'severity': 'High'
                })
        
        self.results['correlation'] = correlation
        print(f"  -> Intelligence correlated ({len(correlation['security_observations'])} observations)")

    def assess_risks(self):
        """Risk assessment with detailed scoring"""
        risk_score = 0
        findings = []
        detailed_risks = []
        
        # 1. SSL Certificate Risk
        if 'ssl' in self.results['data'] and 'days_until_expiry' in self.results['data']['ssl']:
            days = self.results['data']['ssl']['days_until_expiry']
            if days < 30:
                risk_score += 25
                findings.append(f'SSL Certificate expires in {days} days (HIGH)')
                detailed_risks.append({'category': 'SSL', 'risk': 'Certificate Expiry', 'severity': 'High'})
            elif days < 90:
                risk_score += 10
                findings.append(f'SSL Certificate expires in {days} days (MEDIUM)')
                detailed_risks.append({'category': 'SSL', 'risk': 'Certificate Expiry', 'severity': 'Medium'})
        
        # 2. Security Headers Risk
        if 'headers' in self.results['data']:
            headers_data = self.results['data']['headers']
            if 'security_headers' in headers_data:
                missing = [h for h, info in headers_data['security_headers'].items() 
                          if info['status'] == 'Missing' and h not in ['server', 'x-powered-by']]
                risk_score += len(missing) * 5
                for header in missing:
                    findings.append(f'Missing security header: {header}')
                    detailed_risks.append({'category': 'Headers', 'risk': f'Missing {header}', 'severity': 'Medium'})
        
        # 3. Subdomain Attack Surface
        if 'subdomains' in self.results['data']:
            sub_count = self.results['data']['subdomains'].get('count', 0)
            if sub_count > 10:
                risk_score += 15
                findings.append(f'Large attack surface: {sub_count} subdomains discovered')
                detailed_risks.append({'category': 'Subdomains', 'risk': 'Large Attack Surface', 'severity': 'Medium'})
            elif sub_count > 5:
                risk_score += 8
                findings.append(f'Significant attack surface: {sub_count} subdomains discovered')
                detailed_risks.append({'category': 'Subdomains', 'risk': 'Significant Attack Surface', 'severity': 'Low'})
        
        # 4. Sensitive Paths in robots.txt
        if 'robots' in self.results['data'] and self.results['data']['robots'].get('exists'):
            disallowed = self.results['data']['robots'].get('disallowed_paths', [])
            sensitive = ['admin', 'config', 'backup', 'private', 'internal', 'api']
            for path in disallowed:
                for s in sensitive:
                    if s in path.lower():
                        risk_score += 10
                        findings.append(f'Sensitive path exposed in robots.txt: {path}')
                        detailed_risks.append({'category': 'robots.txt', 'risk': 'Sensitive Path Exposure', 'severity': 'Medium'})
                        break
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        self.results['risk_assessment'] = {
            'score': min(risk_score, 100),
            'level': risk_level,
            'findings': findings,
            'detailed_risks': detailed_risks,
            'recommendations': self.generate_recommendations(detailed_risks)
        }
        self.results['findings'] = findings
        print(f"  -> Risk assessment: {risk_level} (Score: {min(risk_score, 100)})")

    def generate_recommendations(self, detailed_risks):
        """Generate recommendations"""
        recommendations = set()
        
        for risk in detailed_risks:
            if risk['category'] == 'SSL':
                recommendations.add('Implement automated SSL certificate renewal process')
                recommendations.add('Monitor certificate expiry with proactive alerts')
            elif risk['category'] == 'Headers':
                recommendations.add('Implement comprehensive security headers (CSP, HSTS, X-Frame-Options)')
                recommendations.add('Enable X-Content-Type-Options: nosniff header')
                recommendations.add('Enable Referrer-Policy header')
                recommendations.add('Enable Permissions-Policy header')
            elif risk['category'] == 'Subdomains':
                recommendations.add('Conduct regular subdomain discovery and monitoring')
                recommendations.add('Implement subdomain takeover prevention measures')
            elif risk['category'] == 'robots.txt':
                recommendations.add('Review and restrict sensitive paths in robots.txt')
                recommendations.add('Implement proper access controls for administrative paths')
        
        if not recommendations:
            recommendations.add('Conduct comprehensive security review of discovered assets')
            recommendations.add('Regularly perform passive OSINT monitoring')
        
        return list(recommendations)

    def generate_timeline(self):
        """Generate intelligence timeline"""
        timeline = []
        
        # Domain registration
        if 'domain' in self.results['data'] and 'creation_date' in self.results['data']['domain']:
            if self.results['data']['domain']['creation_date'] != 'Unknown':
                timeline.append({
                    'date': self.results['data']['domain']['creation_date'],
                    'event': 'Domain Registered',
                    'details': f'Domain {self.target} was registered'
                })
        
        # Certificate issuance
        if 'ssl' in self.results['data'] and 'not_before' in self.results['data']['ssl']:
            if self.results['data']['ssl']['not_before'] != 'Unknown':
                timeline.append({
                    'date': self.results['data']['ssl']['not_before'],
                    'event': 'SSL Certificate Issued',
                    'details': 'Current SSL certificate was issued'
                })
        
        # Sort timeline by date
        timeline.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        self.results['timeline'] = timeline
        print(f"  -> Timeline generated with {len(timeline)} events")

    async def generate_report(self):
        """Generate report with HTML and PDF download"""
        env = Environment(loader=FileSystemLoader('templates'))
        os.makedirs('templates', exist_ok=True)
        
        template_path = 'templates/report_template_final.html'
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(self.get_final_html_template())
        
        template = env.get_template('report_template_final.html')
        
        report_data = {
            'target': self.target,
            'collection_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'collection_duration': str(datetime.now() - self.start_time),
            'data': self.results['data'],
            'correlation': self.results.get('correlation', {}),
            'risk_assessment': self.results.get('risk_assessment', {}),
            'sources': self.source_tracker.get_sources(),
            'findings': self.results.get('findings', []),
            'recommendations': self.results.get('risk_assessment', {}).get('recommendations', []),
            'timeline': self.results.get('timeline', [])
        }
        
        html_content = template.render(**report_data)
        
        # Save HTML
        html_path = f'{self.output_dir}/osint_report.html'
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"  -> HTML report saved: {html_path}")
        
        # Generate PDF using JavaScript in the HTML
        # The PDF download will be handled client-side
        
        # Save JSON data
        json_path = f'{self.output_dir}/intelligence.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"  -> JSON data saved: {json_path}")
        
        # Save source registry
        self.source_tracker.export_csv()
        print(f"  -> Source registry saved")
        
        # Create a simple PDF using weasyprint if available, otherwise html2pdf.js will handle it
        try:
            import weasyprint
            pdf_path = f'{self.output_dir}/osint_report.pdf'
            weasyprint.HTML(string=html_content).write_pdf(pdf_path)
            print(f"  -> PDF report saved: {pdf_path}")
        except:
            print(f"  -> PDF will be generated via browser download button")

    def get_final_html_template(self):
        """Return final HTML template with PDF download button"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Intelligence Report - {{ target }}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js" integrity="sha512-GsLlZN/3F2ErC5ifS5QtgpiJtWd43JWSuIgh7mbzZ8zBps+dvLusV+eNQATqgA/HdeKFVgA5v3S/cIrLF7QnIg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; padding: 20px; color: #333; }
        .report { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 8px; }
        .header { 
            border-bottom: 4px solid #2c3e50; 
            padding-bottom: 20px; 
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        .header-content { flex: 1; }
        h1 { color: #2c3e50; font-size: 32px; }
        .subtitle { color: #7f8c8d; font-size: 16px; }
        .risk-indicator { 
            display: inline-block; 
            padding: 8px 20px; 
            border-radius: 20px; 
            font-weight: bold; 
            color: white; 
            margin-top: 10px; 
        }
        .risk-high { background: #e74c3c; }
        .risk-medium { background: #f39c12; }
        .risk-low { background: #3498db; }
        .dashboard { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 30px; 
            border-radius: 10px; 
            margin: 20px 0; 
        }
        .dashboard-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
            gap: 20px; 
            margin-top: 20px; 
        }
        .dashboard-item { text-align: center; }
        .dashboard-item h3 { font-weight: normal; opacity: 0.9; font-size: 14px; }
        .dashboard-item .value { font-size: 28px; font-weight: bold; margin: 5px 0; }
        .section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; background: white; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        tr:hover { background: #f5f5f5; }
        .badge { 
            display: inline-block; 
            padding: 3px 10px; 
            border-radius: 12px; 
            font-size: 12px; 
            font-weight: bold; 
            color: white; 
        }
        .badge-success { background: #27ae60; }
        .badge-danger { background: #e74c3c; }
        .badge-warning { background: #f39c12; }
        .badge-info { background: #3498db; }
        .footer { 
            margin-top: 40px; 
            padding-top: 20px; 
            border-top: 2px solid #ddd; 
            font-size: 12px; 
            color: #7f8c8d; 
            text-align: center; 
        }
        .finding { 
            border-left: 4px solid #e74c3c; 
            padding: 15px; 
            margin: 10px 0; 
            background: white; 
            border-radius: 4px; 
        }
        .finding.high { border-left-color: #e74c3c; }
        .finding.medium { border-left-color: #f39c12; }
        .finding.low { border-left-color: #3498db; }
        .timeline-item { 
            padding: 10px; 
            margin: 5px 0; 
            background: white; 
            border-radius: 4px; 
            border-left: 3px solid #3498db; 
        }
        .subdomain-tag { 
            display: inline-block; 
            background: #e8f4fd; 
            padding: 5px 15px; 
            border-radius: 20px; 
            margin: 3px; 
            font-size: 13px; 
        }
        .tech-tag { 
            display: inline-block; 
            background: #e8f8f0; 
            padding: 3px 12px; 
            border-radius: 15px; 
            margin: 2px; 
            font-size: 12px; 
            border: 1px solid #a8d8c8; 
        }
        .download-btn {
            background: #2c3e50;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            transition: background 0.3s;
            margin-bottom: 20px;
        }
        .download-btn:hover {
            background: #1a252f;
        }
        .download-btn svg {
            width: 20px;
            height: 20px;
            fill: currentColor;
        }
        @media print {
            .report { box-shadow: none; padding: 20px; }
            .dashboard { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .download-btn { display: none; }
        }
        .summary-box {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 15px 0;
        }
        .summary-box ul {
            list-style: none;
            padding: 0;
        }
        .summary-box li {
            padding: 8px 0;
            border-bottom: 1px solid #f5f5f5;
        }
        .summary-box li:last-child {
            border-bottom: none;
        }
    </style>
</head>
<body>
    <div class="report" id="report-content">
        <div class="header">
            <div class="header-content">
                <h1>OSINT Intelligence Report</h1>
                <div class="subtitle">{{ target }} | {{ collection_date }}</div>
                <div style="margin-top: 15px;">
                    <span class="risk-indicator risk-{{ risk_assessment.level.lower() }}">
                        Risk Level: {{ risk_assessment.level }}
                    </span>
                    <span style="margin-left: 20px; color: #7f8c8d;">
                        Score: {{ risk_assessment.score }}/100
                    </span>
                </div>
            </div>
            <button class="download-btn" onclick="downloadPDF()">
                <svg viewBox="0 0 20 20"><path d="M10 1a1 1 0 011 1v9.586l2.293-2.293a1 1 0 011.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L9 11.586V2a1 1 0 011-1zM3 16a1 1 0 011 1h12a1 1 0 011-1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2z"/></svg>
                Download PDF
            </button>
        </div>
        
        <div class="dashboard">
            <h2 style="color: white; text-align: center; margin: 0;">Intelligence Dashboard</h2>
            <div class="dashboard-grid">
                <div class="dashboard-item">
                    <h3>IP Addresses</h3>
                    <div class="value">{{ data.ip|length if data.ip else 0 }}</div>
                </div>
                <div class="dashboard-item">
                    <h3>DNS Records</h3>
                    <div class="value">{{ data.dns|length if data.dns else 0 }}</div>
                </div>
                <div class="dashboard-item">
                    <h3>Subdomains</h3>
                    <div class="value">{{ data.subdomains.count if data.subdomains else 0 }}</div>
                </div>
                <div class="dashboard-item">
                    <h3>Findings</h3>
                    <div class="value">{{ findings|length }}</div>
                </div>
                <div class="dashboard-item">
                    <h3>Timeline Events</h3>
                    <div class="value">{{ timeline|length }}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-box">
                <p style="margin-bottom: 10px;">This OSINT investigation analyzed <strong>{{ target }}</strong> across multiple dimensions:</p>
                <ul>
                    <li><strong>Domain Age:</strong> {{ data.domain.domain_age_days if data.domain else 'Unknown' }} days</li>
                    <li><strong>SSL Certificate:</strong> Expires in {{ data.ssl.days_until_expiry if data.ssl else 'Unknown' }} days</li>
                    <li><strong>Security Headers:</strong> {{ data.headers.security_score_percentage if data.headers else 0 }}% score</li>
                    <li><strong>Subdomains:</strong> {{ data.subdomains.count if data.subdomains else 0 }} discovered</li>
                    <li><strong>Risk Level:</strong> {{ risk_assessment.level }}</li>
                </ul>
            </div>
        </div>
        
        {% if timeline and timeline|length > 0 %}
        <div class="section">
            <h2>Intelligence Timeline</h2>
            {% for event in timeline %}
            <div class="timeline-item">
                <strong>{{ event.date }}</strong> - {{ event.event }}
                <br><span style="color: #7f8c8d;">{{ event.details }}</span>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <div class="section">
            <h2>Domain Intelligence</h2>
            {% if data.domain and data.domain.error is not defined %}
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Registrar</td><td>{{ data.domain.registrar or 'Unknown' }}</td></tr>
                <tr><td>Creation Date</td><td>{{ data.domain.creation_date or 'Unknown' }}</td></tr>
                <tr><td>Expiration Date</td><td>{{ data.domain.expiration_date or 'Unknown' }}</td></tr>
                <tr><td>Domain Age</td><td>{{ data.domain.domain_age_days }} days</td></tr>
                <tr><td>Days Until Expiry</td><td>{{ data.domain.days_until_expiry }} days</td></tr>
                <tr><td>Nameservers</td><td>{{ data.domain.nameservers|join(', ') if data.domain.nameservers else 'Unknown' }}</td></tr>
            </table>
            {% else %}
            <p>Domain information not available</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>DNS Intelligence</h2>
            {% if data.dns and data.dns.error is not defined %}
            <table>
                <tr><th>Record Type</th><th>Records</th></tr>
                {% for type, records in data.dns.items() %}
                <tr>
                    <td><strong>{{ type }}</strong></td>
                    <td>{{ records|join(', ') if records else 'No records found' }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <p>DNS information not available</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>IP & Infrastructure</h2>
            {% if data.ip and data.ip.error is not defined %}
            {% for ip, info in data.ip.items() %}
            <div style="margin: 10px 0; padding: 15px; background: white; border-radius: 4px; border-left: 3px solid #3498db;">
                <h3 style="margin: 0; color: #2c3e50;">IP: {{ ip }}</h3>
                <ul style="margin: 10px 0 0 20px; line-height: 1.6;">
                    <li><strong>ASN:</strong> {{ info.asn or 'N/A' }}</li>
                    <li><strong>Organization:</strong> {{ info.asn_org or 'N/A' }}</li>
                    <li><strong>Country:</strong> {{ info.country or 'N/A' }}</li>
                    <li><strong>ISP:</strong> {{ info.isp or 'N/A' }}</li>
                    <li><strong>Hosting Type:</strong> {{ info.hosting_type or 'N/A' }}</li>
                    <li><strong>Reverse DNS:</strong> {{ info.reverse_dns or 'N/A' }}</li>
                </ul>
            </div>
            {% endfor %}
            {% else %}
            <p>IP information not available</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>SSL/TLS Intelligence</h2>
            {% if data.ssl and data.ssl.error is not defined %}
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Subject</td><td>{{ data.ssl.subject|join(', ') if data.ssl.subject else 'N/A' }}</td></tr>
                <tr><td>Issuer</td><td>{{ data.ssl.issuer|join(', ') if data.ssl.issuer else 'N/A' }}</td></tr>
                <tr><td>Not Before</td><td>{{ data.ssl.not_before or 'N/A' }}</td></tr>
                <tr><td>Not After</td><td>{{ data.ssl.not_after or 'N/A' }}</td></tr>
                <tr><td>Days Until Expiry</td><td>{{ data.ssl.days_until_expiry }} days</td></tr>
                <tr><td>Cipher Suite</td><td>{{ data.ssl.cipher_suite or 'N/A' }}</td></tr>
                <tr><td>Subject Alternative Names</td><td>{{ data.ssl.subjectAltName|join(', ') if data.ssl.subjectAltName else 'N/A' }}</td></tr>
            </table>
            {% else %}
            <p>SSL/TLS information not available</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Security Headers</h2>
            {% if data.headers and data.headers.error is not defined %}
            <table>
                <tr><th>Header</th><th>Status</th></tr>
                {% for header, info in data.headers.security_headers.items() %}
                <tr>
                    <td><strong>{{ header|upper }}</strong></td>
                    <td>
                        {% if info.status == 'Missing' %}
                        <span class="badge badge-danger">Missing</span>
                        {% else %}
                        <span class="badge badge-success">Present</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
            <p style="margin-top: 10px;"><strong>Security Score:</strong> {{ data.headers.security_score_percentage }}%</p>
            {% else %}
            <p>Security headers information not available</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Technologies Detected</h2>
            {% if data.technologies and data.technologies.error is not defined %}
                {% for category, techs in data.technologies.items() %}
                    {% if techs is iterable and techs is not string and techs|length > 0 %}
                    <h3>{{ category|title }}</h3>
                    <div style="margin: 5px 0 15px 0;">
                        {% for tech in techs %}
                        <span class="tech-tag">{{ tech }}</span>
                        {% endfor %}
                    </div>
                    {% endif %}
                {% endfor %}
            {% else %}
            <p>No technologies detected</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Subdomains Discovered</h2>
            {% if data.subdomains and data.subdomains.discovered|length > 0 %}
            <div style="display: flex; flex-wrap: wrap; gap: 8px; padding: 10px 0;">
                {% for subdomain in data.subdomains.discovered %}
                <span class="subdomain-tag">{{ subdomain }}</span>
                {% endfor %}
            </div>
            <p><strong>Total:</strong> {{ data.subdomains.count }}</p>
            <p><strong>Sources:</strong> {{ data.subdomains.sources }}</p>
            {% else %}
            <p>No subdomains discovered</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>robots.txt Analysis</h2>
            {% if data.robots and data.robots.exists %}
            <p><span class="badge badge-success">robots.txt found</span></p>
            {% if data.robots.disallowed_paths %}
            <h3>Disallowed Paths:</h3>
            <ul>
                {% for path in data.robots.disallowed_paths %}
                <li><code>{{ path }}</code></li>
                {% endfor %}
            </ul>
            {% endif %}
            {% if data.robots.sitemap %}
            <p><strong>Sitemap:</strong> {{ data.robots.sitemap }}</p>
            {% endif %}
            {% else %}
            <p>robots.txt not found</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Security Observations</h2>
            {% if findings and findings|length > 0 %}
            {% for finding in findings %}
            <div class="finding{% if 'HIGH' in finding %} high{% elif 'MEDIUM' in finding %} medium{% else %} low{% endif %}">
                <p>{{ finding }}</p>
            </div>
            {% endfor %}
            {% else %}
            <p>No security observations found</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            {% if recommendations and recommendations|length > 0 %}
            <ul style="line-height: 2;">
                {% for recommendation in recommendations %}
                <li style="padding: 5px 0; border-bottom: 1px solid #eee;">{{ recommendation }}</li>
                {% endfor %}
            </ul>
            {% else %}
            <p>No specific recommendations at this time.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Source Documentation</h2>
            <table>
                <tr><th>ID</th><th>Source Type</th><th>Information</th><th>Confidence</th><th>Date</th></tr>
                {% for source in sources %}
                <tr>
                    <td><code>{{ source.id }}</code></td>
                    <td>{{ source.source_type }}</td>
                    <td>{{ source.information }}</td>
                    <td><span class="badge {% if source.confidence == 'High' %}badge-success{% elif source.confidence == 'Medium' %}badge-warning{% else %}badge-info{% endif %}">{{ source.confidence }}</span></td>
                    <td>{{ source.date[:10] if source.date else 'N/A' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        
        <div class="footer">
            <p>Report generated by OSINT Investigation Framework</p>
            <p>Generated: {{ collection_date }} | Duration: {{ collection_duration }}</p>
            <p>All information collected from publicly available sources | Classification: UNCLASSIFIED</p>
        </div>
    </div>

    <script>
        function downloadPDF() {
            const element = document.getElementById('report-content');
            const opt = {
                margin:       10,
                filename:     'osint_report.pdf',
                image:        { type: 'jpeg', quality: 0.98 },
                html2canvas:  { scale: 2, useCORS: true },
                jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
            };
            
            // Show loading state
            const btn = document.querySelector('.download-btn');
            btn.innerHTML = 'Generating PDF...';
            btn.disabled = true;
            
            html2pdf().set(opt).from(element).save().then(function() {
                btn.innerHTML = '<svg viewBox="0 0 20 20" style="width:20px;height:20px;fill:currentColor;"><path d="M10 1a1 1 0 011 1v9.586l2.293-2.293a1 1 0 011.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L9 11.586V2a1 1 0 011-1zM3 16a1 1 0 011 1h12a1 1 0 011-1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2z"/></svg> Download PDF';
                btn.disabled = false;
            });
        }
    </script>
</body>
</html>
        """

    def extract_disallowed_paths(self, content):
        """Extract disallowed paths from robots.txt"""
        paths = []
        for line in content.split('\n'):
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/' and not path.startswith('#'):
                    paths.append(path)
        return paths

    def extract_sitemap_url(self, content):
        """Extract sitemap URL from robots.txt"""
        for line in content.split('\n'):
            line = line.strip()
            if line.lower().startswith('sitemap:'):
                return line.split(':', 1)[1].strip()
        return None

    def extract_urls_from_sitemap(self, content):
        """Extract URLs from sitemap.xml"""
        urls = []
        for line in content.split('\n'):
            if '<loc>' in line:
                start = line.find('<loc>') + 5
                end = line.find('</loc>')
                if start > 0 and end > start:
                    urls.append(line[start:end])
        return urls

    def define_target(self):
        """Define investigation target and scope"""
        self.results['target_definition'] = {
            'target': self.target,
            'type': 'Website/Domain',
            'investigation_type': 'Passive OSINT',
            'scope': 'Publicly available information',
            'start_date': datetime.now().isoformat(),
            'investigator': 'Security Research Team'
        }

class SourceTracker:
    def __init__(self):
        self.sources = []
        
    def add_source(self, id, source_type, information, url, confidence):
        self.sources.append({
            'id': id,
            'source_type': source_type,
            'information': information,
            'url': url,
            'date': datetime.now().isoformat(),
            'confidence': confidence
        })
    
    def get_sources(self):
        return self.sources
    
    def export_csv(self):
        """Export sources to CSV format"""
        os.makedirs('sources', exist_ok=True)
        with open('sources/source_registry.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['id', 'source_type', 'information', 
                                                 'url', 'date', 'confidence'])
            writer.writeheader()
            writer.writerows(self.sources)

if __name__ == "__main__":
    import sys
    target = 'chicken-road2.app'
    if len(sys.argv) > 1:
        target = sys.argv[1]
    
    framework = FinalOSINTFramework(target)
    asyncio.run(framework.run_full_investigation())