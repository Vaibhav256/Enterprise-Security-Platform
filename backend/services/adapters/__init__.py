"""Adapters package initialization"""

from .base_adapter import BaseAdapter, ScanResult
from .nmap_adapter import NmapAdapter
from .openvas_adapter import OpenVASAdapter

__all__ = ["BaseAdapter", "ScanResult", "NmapAdapter", "OpenVASAdapter"]
