"""
API Gateway Routes Package

Exports all API namespaces for registration in the main app.
"""

# Import main scan routes from scan_routes module (sibling to this package)
from ..scan_routes import scans_ns, tools_ns, stats_ns

__all__ = ['scans_ns', 'tools_ns', 'stats_ns']
