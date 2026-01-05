"""
Universal Target Parser for Security Scanning Tools

This module provides intelligent target parsing and conversion to support
ALL possible target formats across different scanning tools:

Supported Formats:
- URLs: http://example.com, https://192.168.1.1:8080/path
- IPv4: 192.168.1.1, 10.0.0.0-255
- IPv6: 2001:db8::1, [2001:db8::1]:8080
- Hostnames: scanme.nmap.org, localhost, example.com
- CIDR: 192.168.1.0/24, 2001:db8::/32
- IP Ranges: 192.168.1.1-254, 10.0.0-255.1-254.1-254
- Ports: example.com:8080, 192.168.1.1:443

Tool-Specific Conversion:
- Nmap: Prefers hostname/IP (strips URLs)
- Nikto: Requires full URL (adds http:// if missing)
- Nuclei: Requires full URL (adds http:// if missing)
- OpenVAS: Accepts hostname/IP (strips URLs)
"""

import re
import ipaddress
from typing import Dict, Optional, Tuple, List
from urllib.parse import urlparse, urlunparse
from dataclasses import dataclass


@dataclass
class ParsedTarget:
    """Structured representation of a parsed target."""
    
    original: str           # Original input
    target_type: str        # "ipv4", "ipv6", "hostname", "url", "cidr", "range"
    hostname: Optional[str] # Extracted hostname/IP
    ip_address: Optional[str] # Extracted IP (if applicable)
    port: Optional[int]     # Extracted port number
    protocol: Optional[str] # http, https, etc.
    path: Optional[str]     # URL path
    cidr_suffix: Optional[str] # CIDR notation (e.g., "/24")
    range_spec: Optional[str]  # Range specification (e.g., "1-254")
    
    # Tool-specific formatted versions
    nmap_format: str        # Format suitable for Nmap
    nikto_format: str       # Format suitable for Nikto
    nuclei_format: str      # Format suitable for Nuclei
    openvas_format: str     # Format suitable for OpenVAS


class UniversalTargetParser:
    """Parse and convert targets to tool-specific formats."""
    
    # Regex patterns for various target formats
    PATTERNS = {
        # IPv4 patterns
        'ipv4_single': r'^(\d{1,3}\.){3}\d{1,3}$',
        'ipv4_cidr': r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',
        'ipv4_range': r'^(\d{1,3}\.){3}(\d{1,3})-(\d{1,3})$',
        'ipv4_port': r'^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$',
        
        # IPv6 patterns (simplified)
        'ipv6_single': r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$',
        'ipv6_cidr': r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/\d{1,3}$',
        'ipv6_bracket': r'^\[([0-9a-fA-F:]+)\](?::(\d{1,5}))?$',
        
        # Hostname patterns
        'hostname': r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
        'hostname_port': r'^([a-zA-Z0-9\-\.]+):(\d{1,5})$',
        
        # URL patterns
        'url_full': r'^(https?|ftp)://[^\s]+$',
    }
    
    @staticmethod
    def parse(target: str) -> ParsedTarget:
        """
        Parse target into structured format and generate tool-specific versions.
        
        Args:
            target: Any valid target format (URL, IP, hostname, CIDR, range, etc.)
            
        Returns:
            ParsedTarget object with all formats
            
        Raises:
            ValueError: If target is invalid or dangerous
        """
        original = target.strip()
        
        # Security check: block dangerous characters (but allow safe ones in URLs)
        dangerous_chars = [';', '|', '`', '$', '\n', '\r', '\x00', '{', '}']
        for char in dangerous_chars:
            if char in original:
                raise ValueError(f"Invalid character '{char}' in target")
        
        # Try to parse as URL first
        parsed_url = UniversalTargetParser._try_parse_url(original)
        if parsed_url:
            return parsed_url
        
        # Try IPv6 (must check before hostname due to colons)
        parsed_ipv6 = UniversalTargetParser._try_parse_ipv6(original)
        if parsed_ipv6:
            return parsed_ipv6
        
        # Try IPv4 with CIDR
        if '/' in original:
            parsed_cidr = UniversalTargetParser._try_parse_cidr(original)
            if parsed_cidr:
                return parsed_cidr
        
        # Try IPv4 with range
        if '-' in original and re.match(UniversalTargetParser.PATTERNS['ipv4_range'], original):
            return UniversalTargetParser._parse_ipv4_range(original)
        
        # Try IPv4 with port
        if ':' in original and re.match(UniversalTargetParser.PATTERNS['ipv4_port'], original):
            return UniversalTargetParser._parse_ipv4_port(original)
        
        # Try plain IPv4
        if re.match(UniversalTargetParser.PATTERNS['ipv4_single'], original):
            return UniversalTargetParser._parse_ipv4(original)
        
        # Try hostname with port
        if ':' in original and re.match(UniversalTargetParser.PATTERNS['hostname_port'], original):
            return UniversalTargetParser._parse_hostname_port(original)
        
        # Try plain hostname
        if re.match(UniversalTargetParser.PATTERNS['hostname'], original):
            return UniversalTargetParser._parse_hostname(original)
        
        raise ValueError(f"Invalid target format: {original}")
    
    @staticmethod
    def _try_parse_url(target: str) -> Optional[ParsedTarget]:
        """Try to parse as URL."""
        if not re.match(UniversalTargetParser.PATTERNS['url_full'], target.lower()):
            return None
        
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or parsed.netloc.split(':')[0]
            port = parsed.port
            protocol = parsed.scheme
            path = parsed.path or '/'
            
            # Reconstruct clean URL for Nikto/Nuclei
            clean_url = f"{protocol}://{hostname}"
            if port:
                clean_url += f":{port}"
            clean_url += path
            
            return ParsedTarget(
                original=target,
                target_type='url',
                hostname=hostname,
                ip_address=None,
                port=port,
                protocol=protocol,
                path=path,
                cidr_suffix=None,
                range_spec=None,
                nmap_format=hostname,  # Nmap: strip URL, use hostname
                nikto_format=clean_url,  # Nikto: keep full URL
                nuclei_format=clean_url,  # Nuclei: keep full URL
                openvas_format=hostname  # OpenVAS: strip URL, use hostname
            )
        except Exception:
            return None
    
    @staticmethod
    def _try_parse_ipv6(target: str) -> Optional[ParsedTarget]:
        """Try to parse as IPv6."""
        # Check for bracketed IPv6 with port
        bracket_match = re.match(UniversalTargetParser.PATTERNS['ipv6_bracket'], target)
        if bracket_match:
            ipv6, port = bracket_match.groups()
            port = int(port) if port else None
            
            return ParsedTarget(
                original=target,
                target_type='ipv6',
                hostname=ipv6,
                ip_address=ipv6,
                port=port,
                protocol=None,
                path=None,
                cidr_suffix=None,
                range_spec=None,
                nmap_format=ipv6,
                nikto_format=f"http://[{ipv6}]" + (f":{port}" if port else ""),
                nuclei_format=f"http://[{ipv6}]" + (f":{port}" if port else ""),
                openvas_format=ipv6
            )
        
        # Check for IPv6 CIDR
        if '/' in target and re.match(UniversalTargetParser.PATTERNS['ipv6_cidr'], target):
            try:
                network = ipaddress.IPv6Network(target, strict=False)
                return ParsedTarget(
                    original=target,
                    target_type='ipv6',
                    hostname=str(network.network_address),
                    ip_address=str(network.network_address),
                    port=None,
                    protocol=None,
                    path=None,
                    cidr_suffix=f"/{network.prefixlen}",
                    range_spec=None,
                    nmap_format=target,
                    nikto_format=f"http://[{network.network_address}]",
                    nuclei_format=f"http://[{network.network_address}]",
                    openvas_format=str(network.network_address)
                )
            except Exception:
                pass
        
        # Check for plain IPv6
        if re.match(UniversalTargetParser.PATTERNS['ipv6_single'], target):
            try:
                ipaddress.IPv6Address(target)
                return ParsedTarget(
                    original=target,
                    target_type='ipv6',
                    hostname=target,
                    ip_address=target,
                    port=None,
                    protocol=None,
                    path=None,
                    cidr_suffix=None,
                    range_spec=None,
                    nmap_format=target,
                    nikto_format=f"http://[{target}]",
                    nuclei_format=f"http://[{target}]",
                    openvas_format=target
                )
            except Exception:
                pass
        
        return None
    
    @staticmethod
    def _try_parse_cidr(target: str) -> Optional[ParsedTarget]:
        """Try to parse as CIDR notation."""
        try:
            # Try IPv4 CIDR
            network = ipaddress.IPv4Network(target, strict=False)
            return ParsedTarget(
                original=target,
                target_type='cidr',
                hostname=str(network.network_address),
                ip_address=str(network.network_address),
                port=None,
                protocol=None,
                path=None,
                cidr_suffix=f"/{network.prefixlen}",
                range_spec=None,
                nmap_format=target,  # Nmap supports CIDR
                nikto_format=f"http://{network.network_address}",
                nuclei_format=f"http://{network.network_address}",
                openvas_format=str(network.network_address)
            )
        except Exception:
            pass
        
        try:
            # Try IPv6 CIDR
            network = ipaddress.IPv6Network(target, strict=False)
            return ParsedTarget(
                original=target,
                target_type='cidr',
                hostname=str(network.network_address),
                ip_address=str(network.network_address),
                port=None,
                protocol=None,
                path=None,
                cidr_suffix=f"/{network.prefixlen}",
                range_spec=None,
                nmap_format=target,
                nikto_format=f"http://[{network.network_address}]",
                nuclei_format=f"http://[{network.network_address}]",
                openvas_format=str(network.network_address)
            )
        except Exception:
            pass
        
        return None
    
    @staticmethod
    def _parse_ipv4_range(target: str) -> ParsedTarget:
        """Parse IPv4 range (e.g., 192.168.1.1-254)."""
        base, range_end = target.rsplit('-', 1)
        
        return ParsedTarget(
            original=target,
            target_type='range',
            hostname=base,
            ip_address=base,
            port=None,
            protocol=None,
            path=None,
            cidr_suffix=None,
            range_spec=f"-{range_end}",
            nmap_format=target,  # Nmap supports ranges
            nikto_format=f"http://{base}",
            nuclei_format=f"http://{base}",
            openvas_format=base
        )
    
    @staticmethod
    def _parse_ipv4_port(target: str) -> ParsedTarget:
        """Parse IPv4 with port (e.g., 192.168.1.1:8080)."""
        ip, port_str = target.rsplit(':', 1)
        port = int(port_str)
        
        return ParsedTarget(
            original=target,
            target_type='ipv4',
            hostname=ip,
            ip_address=ip,
            port=port,
            protocol=None,
            path=None,
            cidr_suffix=None,
            range_spec=None,
            nmap_format=ip,  # Nmap uses -p flag for ports
            nikto_format=f"http://{ip}:{port}",
            nuclei_format=f"http://{ip}:{port}",
            openvas_format=ip
        )
    
    @staticmethod
    def _parse_ipv4(target: str) -> ParsedTarget:
        """Parse plain IPv4."""
        # Validate octets
        octets = target.split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            raise ValueError(f"Invalid IPv4 address: {target}")
        
        return ParsedTarget(
            original=target,
            target_type='ipv4',
            hostname=target,
            ip_address=target,
            port=None,
            protocol=None,
            path=None,
            cidr_suffix=None,
            range_spec=None,
            nmap_format=target,
            nikto_format=f"http://{target}",
            nuclei_format=f"http://{target}",
            openvas_format=target
        )
    
    @staticmethod
    def _parse_hostname_port(target: str) -> ParsedTarget:
        """Parse hostname with port (e.g., example.com:8080)."""
        hostname, port_str = target.rsplit(':', 1)
        port = int(port_str)
        
        return ParsedTarget(
            original=target,
            target_type='hostname',
            hostname=hostname,
            ip_address=None,
            port=port,
            protocol=None,
            path=None,
            cidr_suffix=None,
            range_spec=None,
            nmap_format=hostname,
            nikto_format=f"http://{hostname}:{port}",
            nuclei_format=f"http://{hostname}:{port}",
            openvas_format=hostname
        )
    
    @staticmethod
    def _parse_hostname(target: str) -> ParsedTarget:
        """Parse plain hostname."""
        return ParsedTarget(
            original=target,
            target_type='hostname',
            hostname=target,
            ip_address=None,
            port=None,
            protocol=None,
            path=None,
            cidr_suffix=None,
            range_spec=None,
            nmap_format=target,
            nikto_format=f"http://{target}",
            nuclei_format=f"http://{target}",
            openvas_format=target
        )
    
    @staticmethod
    def get_tool_format(target: str, tool_name: str) -> str:
        """
        Get the appropriate target format for a specific tool.
        
        Args:
            target: Original target input
            tool_name: Tool name (nmap, nikto, nuclei, openvas)
            
        Returns:
            Target formatted for the specific tool
            
        Example:
            >>> UniversalTargetParser.get_tool_format("http://scanme.nmap.org/", "nmap")
            'scanme.nmap.org'
            >>> UniversalTargetParser.get_tool_format("scanme.nmap.org", "nikto")
            'http://scanme.nmap.org'
        """
        parsed = UniversalTargetParser.parse(target)
        
        tool_formats = {
            'nmap': parsed.nmap_format,
            'nikto': parsed.nikto_format,
            'nuclei': parsed.nuclei_format,
            'openvas': parsed.openvas_format
        }
        
        return tool_formats.get(tool_name.lower(), parsed.nmap_format)
