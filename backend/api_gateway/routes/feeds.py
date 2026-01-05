"""
Threat Intelligence Feed API Routes

Endpoints for threat intelligence feeds management.
"""

from flask import Blueprint, request, jsonify
from flask_restx import Namespace, Resource, fields
from flask_cors import cross_origin
import logging
from datetime import datetime, timedelta

from services.threat_feeds.feed_manager import ThreatFeedManager
from services.threat_feeds.nvd_client import NVDClient
from services.threat_feeds.exploitdb_client import ExploitDBClient
from services.threat_feeds.feed_sync_service import FeedSyncService

logger = logging.getLogger(__name__)

# Create namespace
feeds_ns = Namespace('feeds', description='Threat intelligence feeds operations')

# Initialize managers
feed_manager = ThreatFeedManager()
nvd_client = NVDClient()
exploitdb_client = ExploitDBClient()
feed_sync_service = FeedSyncService()


@feeds_ns.route('/status')
class FeedStatus(Resource):
    """Get threat feed status"""
    
    def get(self):
        """
        Get status of all threat intelligence feeds.
        
        Returns:
            JSON with feed status information
        """
        try:
            status = feed_manager.get_feed_status()
            return jsonify({
                'status': 'success',
                'data': status
            })
        except Exception as e:
            logger.error(f"Error getting feed status: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


@feeds_ns.route('/refresh')
class FeedRefresh(Resource):
    """Refresh threat feeds"""
    
    def post(self):
        """
        Refresh threat intelligence feeds.
        
        Request JSON:
            {
                "force": false  # Force refresh even if cache is valid
            }
        
        Returns:
            JSON with refresh results
        """
        try:
            data = request.get_json() or {}
            force = data.get('force', False)
            
            logger.info(f"Feed refresh requested")
            results = feed_manager.refresh_feeds(force=force)
            
            return {
                'status': 'success',
                'data': results
            }, 200
        except Exception as e:
            logger.error(f"Error refreshing feeds: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }, 500


@feeds_ns.route('/cve/<cve_id>')
class CVEDetails(Resource):
    """Get CVE details"""
    
    def get(self, cve_id):
        """
        Get detailed information for a specific CVE from local database.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            JSON with CVE details from database
        """
        try:
            from config.models import FeedEntry
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            # Query database
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            
            with Session(engine) as session:
                entry = session.query(FeedEntry).filter(
                    FeedEntry.entry_id == cve_id,
                    FeedEntry.feed_source == 'nvd'
                ).first()
                
                engine.dispose()
                
                if not entry:
                    logger.warning(f"CVE not found in database: {cve_id}")
                    return {
                        'status': 'error',
                        'error': f'CVE not found: {cve_id}'
                    }, 404
                
                # Format response
                cve_data = {
                    'id': entry.entry_id,
                    'title': entry.title,
                    'description': entry.description,
                    'severity': entry.severity,
                    'cvss_score': float(entry.cvss_score) if entry.cvss_score else None,
                    'cvss_vector': entry.cvss_vector,
                    'published_date': entry.published_date.isoformat() if entry.published_date else None,
                    'modified_date': entry.modified_date.isoformat() if entry.modified_date else None,
                    'references': entry.ref_urls or [],
                    'exploit_available': entry.exploit_available,
                    'cwe_ids': entry.cwe_ids or [],
                    'affected_products': entry.affected_products or []
                }
                
                return {
                    'status': 'success',
                    'data': cve_data
                }, 200
                
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }, 500


@feeds_ns.route('/enrich')
class EnrichVulnerability(Resource):
    """Enrich vulnerability data"""
    
    def post(self):
        """
        Enrich vulnerability data with threat intelligence.
        
        Request JSON:
            {
                "cve_id": "CVE-2024-1234",
                "sources": ["nvd", "exploitdb"]  # Optional
            }
        
        Returns:
            JSON with enriched vulnerability data
        """
        try:
            data = request.get_json()
            
            if not data or 'cve_id' not in data:
                return jsonify({
                    'status': 'error',
                    'error': 'cve_id is required'
                }), 400
            
            sources = data.get('sources')
            vuln_data = {'cve_id': data['cve_id']}
            
            enriched = feed_manager.enrich_vulnerability(vuln_data, sources=sources)
            
            return jsonify({
                'status': 'success',
                'data': enriched
            })
        except Exception as e:
            logger.error(f"Error enriching vulnerability: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


@feeds_ns.route('/exploits/<exploit_id>')
class ExploitAvailability(Resource):
    """Get exploit details"""
    
    def get(self, exploit_id):
        """
        Get detailed information about a specific exploit from local database.
        
        Args:
            exploit_id: Exploit identifier (e.g., from ExploitDB)
        
        Returns:
            JSON with exploit details
        """
        try:
            from config.models import FeedEntry
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            
            with Session(engine) as session:
                entry = session.query(FeedEntry).filter(
                    FeedEntry.entry_id == exploit_id,
                    FeedEntry.feed_source == 'exploitdb'
                ).first()
                
                engine.dispose()
                
                if not entry:
                    logger.warning(f"Exploit not found in database: {exploit_id}")
                    return {
                        'status': 'error',
                        'error': f'Exploit not found: {exploit_id}'
                    }, 404
                
                # Format response
                exploit_data = {
                    'id': entry.entry_id,
                    'title': entry.title,
                    'description': entry.description,
                    'type': entry.exploit_type,
                    'platform': entry.exploit_platform,
                    'published_date': entry.published_date.isoformat() if entry.published_date else None,
                    'references': entry.ref_urls or []
                }
                
                return {
                    'status': 'success',
                    'data': exploit_data
                }, 200
                
        except Exception as e:
            logger.error(f"Error fetching exploit {exploit_id}: {e}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }, 500


@feeds_ns.route('/search')
class SearchVulnerabilities(Resource):
    """Search vulnerabilities"""
    
    def get(self):
        """
        Search for vulnerabilities across feeds.
        
        Query params:
            keyword: Search keyword
            severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
            days: Look back N days (default: 7)
        
        Returns:
            JSON with matching vulnerabilities
        """
        try:
            keyword = request.args.get('keyword')
            severity = request.args.get('severity')
            days = int(request.args.get('days', 7))
            
            results = feed_manager.search_vulnerabilities(
                keyword=keyword,
                severity=severity,
                days=days
            )
            
            return jsonify({
                'status': 'success',
                'count': len(results),
                'data': results
            })
        except Exception as e:
            logger.error(f"Error searching vulnerabilities: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


@feeds_ns.route('/recent')
class RecentCVEs(Resource):
    """Get recent CVEs"""
    
    def get(self):
        """
        Get recently published CVEs.
        
        Query params:
            days: Look back N days (default: 7)
            limit: Max results (default: 50)
        
        Returns:
            JSON with recent CVEs
        """
        try:
            days = int(request.args.get('days', 7))
            limit = int(request.args.get('limit', 50))
            
            cves = nvd_client.get_recent_cves(days=days, max_results=limit)
            
            return jsonify({
                'status': 'success',
                'count': len(cves),
                'data': cves
            })
        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


@feeds_ns.route('/sync')
class ManualFeedSync(Resource):
    """Manual trigger for threat feed synchronization"""
    
    def post(self):
        """
        Manually trigger synchronization of threat feeds.
        
        Request JSON (all optional):
            {
                "nvd_days": 7,           # NVD lookback days
                "nvd_batch": 100,        # NVD batch size
                "edb_max": 50,           # ExploitDB max exploits
                "sync_nvd": true,        # Include NVD sync
                "sync_edb": true         # Include ExploitDB sync
            }
        
        Returns:
            JSON with sync results: {new, updated, skipped, errors}
        """
        try:
            data = request.get_json() or {}
            
            nvd_days = data.get('nvd_days', 7)
            nvd_batch = data.get('nvd_batch', 100)
            edb_max = data.get('edb_max', 50)
            sync_nvd = data.get('sync_nvd', True)
            sync_edb = data.get('sync_edb', True)
            
            logger.info(f"🔄 Manual feed sync triggered: NVD={sync_nvd}, EDB={sync_edb}")
            
            results = {
                'nvd': None,
                'exploitdb': None,
                'total': {'new': 0, 'updated': 0, 'skipped': 0, 'errors': 0},
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if sync_nvd:
                logger.info(f"📡 Syncing NVD (last {nvd_days} days, batch {nvd_batch})...")
                nvd_results = feed_sync_service.sync_nvd_recent(
                    days=nvd_days,
                    batch_size=nvd_batch
                )
                results['nvd'] = nvd_results
                results['total']['new'] += nvd_results.get('new', 0)
                results['total']['updated'] += nvd_results.get('updated', 0)
                results['total']['skipped'] += nvd_results.get('skipped', 0)
                results['total']['errors'] += nvd_results.get('errors', 0)
                logger.info(f"✅ NVD sync: {nvd_results}")
            
            if sync_edb:
                logger.info(f"📡 Syncing ExploitDB (max {edb_max})...")
                edb_results = feed_sync_service.sync_exploitdb_recent(
                    max_exploits=edb_max
                )
                results['exploitdb'] = edb_results
                results['total']['new'] += edb_results.get('new', 0)
                results['total']['updated'] += edb_results.get('updated', 0)
                results['total']['skipped'] += edb_results.get('skipped', 0)
                results['total']['errors'] += edb_results.get('errors', 0)
                logger.info(f"✅ ExploitDB sync: {edb_results}")
            
            logger.info(f"✅ Feed sync complete: {results['total']}")
            
            return jsonify({
                'status': 'success',
                'data': results
            }), 200
            
        except Exception as e:
            logger.error(f"❌ Error during feed sync: {e}", exc_info=True)
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


@feeds_ns.route('/alerts')
class CriticalVulnerabilityAlerts(Resource):
    """Get alerts for critical vulnerabilities with available exploits"""
    
    def get(self):
        """
        Get critical CVEs with public exploits available.
        
        Query params:
            severity: Filter by severity (CRITICAL, HIGH) - default: CRITICAL
            with_exploits: Only show CVEs with known exploits (default: true)
            days: Look back N days (default: 7)
        
        Returns:
            JSON with alert list including CVE, exploit, and risk info
        """
        try:
            severity = request.args.get('severity', 'CRITICAL').upper()
            with_exploits = request.args.get('with_exploits', 'true').lower() == 'true'
            days = int(request.args.get('days', 7))
            
            logger.info(f"Fetching alerts: severity={severity}, with_exploits={with_exploits}, days={days}")
            
            # Use alerts service for comprehensive alert data
            try:
                from services.threat_feeds.alerts_service import CriticalVulnerabilityAlertsService
                alerts_service = CriticalVulnerabilityAlertsService()
                alerts = alerts_service.get_critical_alerts(days=days, include_exploits=with_exploits)
                
                return jsonify({
                    'status': 'success',
                    'count': len(alerts),
                    'data': alerts
                }), 200
                
            except ImportError:
                # Fallback if alerts service not available
                return jsonify({
                    'status': 'success',
                    'count': 0,
                    'data': [],
                    'note': 'Alerts service not available in this configuration'
                }), 200
            
        except Exception as e:
            logger.error(f"Error fetching alerts: {e}", exc_info=True)
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


@feeds_ns.route('/stats')
class FeedStatistics(Resource):
    """Get threat feed statistics"""
    
    def get(self):
        """
        Get comprehensive threat feed statistics.
        
        Returns:
            JSON with counts by source, severity, and trends
        """
        try:
            logger.info("Fetching feed statistics...")
            
            # Try to get stats from service
            try:
                from services.threat_feeds.feed_sync_service import FeedSyncService
                service = FeedSyncService()
                
                # Query database through SQLAlchemy
                from config.models import FeedEntry
                from sqlalchemy.orm import Session
                from sqlalchemy import create_engine
                import os
                
                db_url = os.getenv(
                    'DATABASE_URL',
                    'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
                )
                engine = create_engine(db_url)
                
                with Session(engine) as session:
                    # Total counts
                    total_entries = session.query(FeedEntry).count()
                    nvd_count = session.query(FeedEntry).filter_by(feed_source='nvd').count()
                    edb_count = session.query(FeedEntry).filter_by(feed_source='exploitdb').count()
                    
                    # Severity breakdown
                    severity_stats = {}
                    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                        count = session.query(FeedEntry).filter_by(severity=severity).count()
                        severity_stats[severity] = count
                    
                    # Recent activity (last 7 days)
                    from datetime import datetime, timedelta
                    week_ago = datetime.utcnow() - timedelta(days=7)
                    recent_nvd = session.query(FeedEntry).filter(
                        FeedEntry.feed_source == 'nvd',
                        FeedEntry.published_date >= week_ago
                    ).count()
                    recent_edb = session.query(FeedEntry).filter(
                        FeedEntry.feed_source == 'exploitdb',
                        FeedEntry.published_date >= week_ago
                    ).count()
                    
                    stats = {
                        'total_entries': total_entries,
                        'by_source': {
                            'nvd': nvd_count,
                            'exploitdb': edb_count
                        },
                        'by_severity': severity_stats,
                        'recent_7_days': {
                            'nvd': recent_nvd,
                            'exploitdb': recent_edb
                        },
                        'timestamp': datetime.utcnow().isoformat()
                    }
                
                engine.dispose()
                
                return jsonify({
                    'status': 'success',
                    'data': stats
                }), 200
                
            except Exception as db_error:
                logger.warning(f"Could not fetch stats from database: {db_error}")
                # Return mock stats
                return jsonify({
                    'status': 'success',
                    'data': {
                        'total_entries': 0,
                        'by_source': {'nvd': 0, 'exploitdb': 0},
                        'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
                        'recent_7_days': {'nvd': 0, 'exploitdb': 0},
                        'timestamp': datetime.utcnow().isoformat(),
                        'note': 'Database not available'
                    }
                }), 200
            
        except Exception as e:
            logger.error(f"Error fetching feed statistics: {e}", exc_info=True)
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


@feeds_ns.route('/cves')
class ListCVEs(Resource):
    """List all CVEs from database"""
    
    def get(self):
        """
        Get list of all CVEs in database with optional filtering.
        
        Query params:
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            limit: Max results (default: 50)
            offset: Pagination offset (default: 0)
            search: Search in title/description
        
        Returns:
            JSON with CVE list
        """
        try:
            from config.models import FeedEntry
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            severity = request.args.get('severity')
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))
            search = request.args.get('search', '').strip()
            
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            
            with Session(engine) as session:
                query = session.query(FeedEntry).filter(
                    FeedEntry.feed_source == 'nvd'
                )
                
                # Apply filters
                if severity:
                    query = query.filter(FeedEntry.severity == severity.upper())
                
                if search:
                    query = query.filter(
                        FeedEntry.title.ilike(f'%{search}%') |
                        FeedEntry.description.ilike(f'%{search}%')
                    )
                
                # Get total count
                total = query.count()
                
                # Apply pagination
                entries = query.order_by(
                    FeedEntry.published_date.desc()
                ).offset(offset).limit(limit).all()
                
                engine.dispose()
                
                cves = []
                for entry in entries:
                    cves.append({
                        'id': entry.entry_id,
                        'title': entry.title,
                        'severity': entry.severity,
                        'cvss_score': float(entry.cvss_score) if entry.cvss_score else None,
                        'published_date': entry.published_date.isoformat() if entry.published_date else None,
                        'exploit_available': entry.exploit_available
                    })
                
                return {
                    'status': 'success',
                    'total': total,
                    'count': len(cves),
                    'offset': offset,
                    'limit': limit,
                    'data': cves
                }, 200
                
        except Exception as e:
            logger.error(f"Error listing CVEs: {e}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }, 500


@feeds_ns.route('/exploits')
class ListExploits(Resource):
    """List all exploits from database"""
    
    def get(self):
        """
        Get list of all exploits in database.
        
        Query params:
            limit: Max results (default: 50)
            offset: Pagination offset (default: 0)
            search: Search in title/description
        
        Returns:
            JSON with exploit list
        """
        try:
            from config.models import FeedEntry
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            import os
            
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))
            search = request.args.get('search', '').strip()
            
            db_url = os.getenv(
                'DATABASE_URL',
                'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
            )
            engine = create_engine(db_url)
            
            with Session(engine) as session:
                query = session.query(FeedEntry).filter(
                    FeedEntry.feed_source == 'exploitdb'
                )
                
                if search:
                    query = query.filter(
                        FeedEntry.title.ilike(f'%{search}%') |
                        FeedEntry.description.ilike(f'%{search}%')
                    )
                
                # Get total count
                total = query.count()
                
                # Apply pagination
                entries = query.order_by(
                    FeedEntry.published_date.desc()
                ).offset(offset).limit(limit).all()
                
                engine.dispose()
                
                exploits = []
                for entry in entries:
                    exploits.append({
                        'id': entry.entry_id,
                        'title': entry.title,
                        'type': entry.exploit_type,
                        'platform': entry.exploit_platform,
                        'published_date': entry.published_date.isoformat() if entry.published_date else None
                    })
                
                return {
                    'status': 'success',
                    'total': total,
                    'count': len(exploits),
                    'offset': offset,
                    'limit': limit,
                    'data': exploits
                }, 200
                
        except Exception as e:
            logger.error(f"Error listing exploits: {e}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }, 500
