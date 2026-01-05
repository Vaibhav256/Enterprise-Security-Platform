"""
Critical Vulnerability Alerts Service

Monitors for critical CVEs with available exploits and generates alerts.
Provides methods for checking and managing threat alerts.

Author: NTRO Security Team
Date: 2025-10-31
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from enum import Enum

# Handle database import gracefully
try:
    from config.database import DatabaseConfig
    from config.models import FeedEntry
    HAS_DB = True
except ImportError:
    HAS_DB = False

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Alert:
    """Represents a single alert for a critical vulnerability"""
    
    def __init__(self, cve_id: str, severity: str, cvss_score: float, 
                 title: str, exploit_count: int = 0, has_active_exploits: bool = False):
        self.cve_id = cve_id
        self.severity = severity
        self.cvss_score = cvss_score
        self.title = title
        self.exploit_count = exploit_count
        self.has_active_exploits = has_active_exploits
        self.created_at = datetime.utcnow()
        self.acknowledged = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'cve_id': self.cve_id,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'title': self.title,
            'exploit_count': self.exploit_count,
            'has_active_exploits': self.has_active_exploits,
            'created_at': self.created_at.isoformat(),
            'acknowledged': self.acknowledged
        }


class CriticalVulnerabilityAlertsService:
    """Service for managing critical vulnerability alerts"""
    
    # Alert thresholds
    CRITICAL_THRESHOLD = 9.0  # CVSS >= 9.0
    HIGH_THRESHOLD = 7.0      # CVSS >= 7.0
    
    def __init__(self):
        """Initialize alerts service"""
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: List[Dict[str, Any]] = []
        logger.info("✅ Critical Vulnerability Alerts Service initialized")
    
    def get_critical_alerts(self, days: int = 7, include_exploits: bool = True) -> List[Dict[str, Any]]:
        """
        Get critical CVEs from recent threat feeds.
        
        Args:
            days: Look back N days (default: 7)
            include_exploits: Only return CVEs with exploits (default: True)
        
        Returns:
            List of alert dictionaries
        """
        try:
            if not HAS_DB:
                logger.warning("Database not available in this context")
                return []
            
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            
            with Session(engine) as session:
                alerts = []
                
                # Query for critical/high CVEs from last N days
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                
                critical_cves = session.query(FeedEntry).filter(
                    FeedEntry.feed_source == 'nvd',
                    FeedEntry.severity.in_(['CRITICAL', 'HIGH']),
                    FeedEntry.cvss_score >= self.HIGH_THRESHOLD,
                    FeedEntry.published_date >= cutoff_date
                ).order_by(FeedEntry.cvss_score.desc()).all()
                
                for cve in critical_cves:
                    # Check for exploits
                    exploit_count = session.query(FeedEntry).filter(
                        FeedEntry.feed_source == 'exploitdb',
                        FeedEntry.entry_id.contains(cve.cve_id) if cve.cve_id else False
                    ).count()
                    
                    # Skip if no exploits and user requested only CVEs with exploits
                    if include_exploits and exploit_count == 0:
                        continue
                    
                    alert_dict = {
                        'cve_id': cve.cve_id,
                        'title': cve.title[:100] if cve.title else 'N/A',
                        'severity': cve.severity,
                        'cvss_score': cve.cvss_score,
                        'published_date': cve.published_date.isoformat() if cve.published_date else None,
                        'description': cve.description[:300] if cve.description else None,
                        'exploit_count': exploit_count,
                        'has_exploits': exploit_count > 0,
                        'risk_score': self._calculate_risk_score(cve.cvss_score, exploit_count),
                        'attack_vector': 'N/A'
                    }
                    alerts.append(alert_dict)
                
                engine.dispose()
                return alerts
            
        except Exception as e:
            logger.error(f"Error fetching critical alerts: {e}", exc_info=True)
            return []
    
    def get_exploit_availability(self, cve_id: str) -> Dict[str, Any]:
        """
        Check if public exploits are available for a CVE.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            Dictionary with exploit availability info
        """
        try:
            if not HAS_DB:
                return {'status': 'error', 'error': 'Database not available'}
            
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            session = Session(engine)
            
            # Get CVE info
            cve = session.query(FeedEntry).filter(
                FeedEntry.feed_source == 'nvd',
                FeedEntry.cve_id == cve_id
            ).first()
            
            if not cve:
                session.close()
                return {
                    'status': 'not_found',
                    'message': f'CVE {cve_id} not in database'
                }
            
            # Get exploits
            exploits = session.query(FeedEntry).filter(
                FeedEntry.feed_source == 'exploitdb',
                FeedEntry.entry_id.contains(cve_id)
            ).all()
            
            result = {
                'cve_id': cve_id,
                'cve_info': {
                    'title': cve.title,
                    'severity': cve.severity,
                    'cvss_score': cve.cvss_score,
                    'published_date': cve.published_date.isoformat() if cve.published_date else None
                },
                'exploit_available': len(exploits) > 0,
                'exploit_count': len(exploits),
                'exploits': [
                    {
                        'id': exploit.entry_id,
                        'title': exploit.title,
                        'type': exploit.metadata.get('type') if exploit.metadata else None,
                        'published_date': exploit.published_date.isoformat() if exploit.published_date else None,
                        'download_url': exploit.metadata.get('download_url') if exploit.metadata else None
                    }
                    for exploit in exploits
                ]
            }
            
            session.close()
            engine.dispose()
            return result
            
        except Exception as e:
            logger.error(f"Error checking exploit availability for {cve_id}: {e}", exc_info=True)
            return {'status': 'error', 'error': str(e)}
    
    def get_affected_systems(self, cve_id: str) -> List[Dict[str, str]]:
        """
        Get list of affected systems/products for a CVE.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            List of affected products
        """
        try:
            if not HAS_DB:
                return []
            
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            session = Session(engine)
            
            cve = session.query(FeedEntry).filter(
                FeedEntry.feed_source == 'nvd',
                FeedEntry.cve_id == cve_id
            ).first()
            
            if not cve or not cve.metadata:
                session.close()
                return []
            
            # Extract CPE (Common Product Enumeration) from metadata
            affected_products = []
            configurations = cve.metadata.get('configurations', [])
            
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpematch_list = node.get('cpeMatch', [])
                    for cpematch in cpematch_list:
                        cpe = cpematch.get('criteria', '')
                        if cpe:
                            # Extract product name from CPE URI
                            parts = cpe.split(':')
                            if len(parts) >= 5:
                                affected_products.append({
                                    'cpe': cpe,
                                    'product': parts[4],
                                    'version': parts[5] if len(parts) > 5 else '*'
                                })
            
            session.close()
            engine.dispose()
            
            # Remove duplicates
            unique_products = {}
            for product in affected_products:
                key = f"{product['product']}:{product['version']}"
                if key not in unique_products:
                    unique_products[key] = product
            
            return list(unique_products.values())
            
        except Exception as e:
            logger.error(f"Error getting affected systems for {cve_id}: {e}")
            return []
    
    def create_incident_report(self, cve_id: str) -> Dict[str, Any]:
        """
        Create a comprehensive incident report for a critical CVE.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary with incident report
        """
        try:
            # Get CVE and exploit info
            exploit_info = self.get_exploit_availability(cve_id)
            affected_systems = self.get_affected_systems(cve_id)
            
            report = {
                'report_id': f"INC-{cve_id}-{int(datetime.utcnow().timestamp())}",
                'created_at': datetime.utcnow().isoformat(),
                'cve_id': cve_id,
                'cve_info': exploit_info.get('cve_info', {}),
                'exploit_info': {
                    'available': exploit_info.get('exploit_available', False),
                    'count': exploit_info.get('exploit_count', 0),
                    'exploits': exploit_info.get('exploits', [])
                },
                'affected_products': affected_systems,
                'risk_assessment': self._assess_risk(exploit_info, len(affected_systems)),
                'recommendations': self._get_recommendations(cve_id, exploit_info)
            }
            
            logger.info(f"📋 Incident report created: {report['report_id']}")
            
            return report
            
        except Exception as e:
            logger.error(f"Error creating incident report: {e}", exc_info=True)
            return {'status': 'error', 'error': str(e)}
    
    def _calculate_risk_score(self, cvss_score: float, exploit_count: int) -> float:
        """Calculate risk score combining CVSS and exploit availability"""
        # Base score from CVSS
        risk = cvss_score
        
        # Increase risk if exploits are available
        if exploit_count > 0:
            risk += min(5.0, exploit_count * 0.5)  # Add up to 5 points for exploits
        
        # Cap at 10.0
        return min(10.0, risk)
    
    def _assess_risk(self, exploit_info: Dict, affected_count: int) -> str:
        """Assess overall risk level"""
        cvss = exploit_info.get('cve_info', {}).get('cvss_score', 0)
        has_exploits = exploit_info.get('exploit_available', False)
        
        if cvss >= 9.0 and has_exploits:
            return "🔴 CRITICAL - Immediate action required"
        elif cvss >= 9.0:
            return "🔴 CRITICAL - High priority"
        elif cvss >= 7.0 and has_exploits:
            return "🟠 HIGH - Urgent action needed"
        elif cvss >= 7.0:
            return "🟠 HIGH - Should be addressed soon"
        else:
            return "🟡 MEDIUM - Monitor and plan remediation"
    
    def _get_recommendations(self, cve_id: str, exploit_info: Dict) -> List[str]:
        """Get mitigation recommendations"""
        recommendations = [
            "Apply security patches from vendor if available",
            "Monitor affected systems for suspicious activity",
            "Review network segmentation and access controls"
        ]
        
        if exploit_info.get('exploit_available', False):
            recommendations.insert(0, "⚠️  PUBLIC EXPLOITS AVAILABLE - Prioritize patching")
            recommendations.append("Monitor network traffic for known exploit signatures")
        
        return recommendations
    
    def get_alerts_summary(self, days: int = 7) -> Dict[str, Any]:
        """
        Get summary of all critical alerts.
        
        Args:
            days: Look back N days
        
        Returns:
            Dictionary with alert summary statistics
        """
        try:
            if not HAS_DB:
                return {}
            
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            session = Session(engine)
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Count by severity
            critical_count = session.query(FeedEntry).filter(
                FeedEntry.feed_source == 'nvd',
                FeedEntry.severity == 'CRITICAL',
                FeedEntry.published_date >= cutoff_date
            ).count()
            
            high_count = session.query(FeedEntry).filter(
                FeedEntry.feed_source == 'nvd',
                FeedEntry.severity == 'HIGH',
                FeedEntry.published_date >= cutoff_date
            ).count()
            
            # CVEs with public exploits
            cves_with_exploits = session.query(
                FeedEntry.entry_id
            ).filter(
                FeedEntry.feed_source == 'exploitdb'
            ).distinct().count()
            
            session.close()
            engine.dispose()
            
            return {
                'period_days': days,
                'critical_cves': critical_count,
                'high_severity_cves': high_count,
                'cves_with_public_exploits': cves_with_exploits,
                'total_alerts': critical_count + high_count,
                'risk_level': 'CRITICAL' if critical_count > 0 else ('HIGH' if high_count > 0 else 'MEDIUM'),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting alerts summary: {e}")
            return {}
