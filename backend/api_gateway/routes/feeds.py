"""
Threat Intelligence Feed API Routes

Endpoints for threat intelligence feeds management.
"""

from flask import Blueprint, request, jsonify
from flask_restx import Namespace, Resource, fields
from flask_cors import cross_origin
import logging
import threading
from datetime import datetime, timedelta

from services.threat_feeds.feed_manager import ThreatFeedManager
from services.threat_feeds.nvd_client import NVDClient
from services.threat_feeds.exploitdb_client import ExploitDBClient
from services.threat_feeds.feed_sync_service import FeedSyncService
from sqlalchemy import func

logger = logging.getLogger(__name__)

# Create namespace
feeds_ns = Namespace('feeds', description='Threat intelligence feeds operations')

# Simple cache for feed statistics (5-minute TTL)
_stats_cache = {'data': None, 'timestamp': None}
_stats_cache_lock = threading.Lock()
_stats_cache_ttl = 300  # 5 minutes in seconds

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
        Get detailed information for a specific CVE.
        First checks local database, then falls back to NVD API if not found.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            JSON with CVE details from database or NVD API
        """
        try:
            from utils.validation import validate_cve_id
            
            # Validate CVE ID format
            try:
                cve_id = validate_cve_id(cve_id)
            except ValueError as e:
                return {
                    'status': 'error',
                    'error': str(e)
                }, 400
            
            from config.models import FeedEntry
            from config.database import SessionLocal
            
            # Query database using configured session
            session = SessionLocal()
            try:
                entry = session.query(FeedEntry).filter(
                    FeedEntry.entry_id == cve_id,
                    FeedEntry.feed_source == 'nvd'
                ).first()
                
                if entry:
                    # Format response from database
                    cvss_score = float(entry.cvss_score) if entry.cvss_score else None
                    
                    cve_data = {
                        'id': entry.entry_id,
                        'title': entry.title,
                        'description': entry.description,
                        'severity': entry.severity,
                        'cvss_score': cvss_score,
                        'cvss_v3': cvss_score,  # Database stores combined score - use for both
                        'cvss_v2': cvss_score,
                        'cvss_vector': entry.cvss_vector,
                        'published_date': entry.published_date.isoformat() + 'Z' if entry.published_date else None,
                        'modified_date': entry.modified_date.isoformat() + 'Z' if entry.modified_date else None,
                        'references': entry.ref_urls or [],
                        'exploit_available': entry.exploit_available,
                        'cwe_ids': entry.cwe_ids or [],
                        'affected_products': entry.affected_products or [],
                        'source': 'database'
                    }
                    
                    return {
                        'status': 'success',
                        'data': cve_data
                    }, 200
                
                # Not in database - try fetching from NVD API
                logger.info(f"CVE {cve_id} not in database, fetching from NVD API...")
                
                from services.threat_feeds.nvd_client import NVDClient
                nvd_client = NVDClient()
                
                nvd_data = nvd_client.get_cve(cve_id)
                
                if not nvd_data:
                    logger.warning(f"CVE not found in database or NVD: {cve_id}")
                    return {
                        'status': 'error',
                        'error': f'CVE not found: {cve_id}. This CVE may not exist or has not been published yet.'
                    }, 404
                
                # Format NVD response to match database format
                cvss_v3_data = nvd_data.get('cvss_v3')
                cvss_v2_data = nvd_data.get('cvss_v2')
                
                cve_data = {
                    'id': nvd_data.get('cve_id', cve_id),
                    'title': nvd_data.get('title', f"CVE {cve_id}"),
                    'description': nvd_data.get('description', ''),
                    'severity': nvd_data.get('severity', 'UNKNOWN'),
                    'cvss_score': cvss_v3_data.get('baseScore') if cvss_v3_data else (cvss_v2_data.get('baseScore') if cvss_v2_data else None),
                    'cvss_v3': cvss_v3_data.get('baseScore') if cvss_v3_data else None,
                    'cvss_v2': cvss_v2_data.get('baseScore') if cvss_v2_data else None,
                    'cvss_vector': cvss_v3_data.get('vectorString') if cvss_v3_data else (cvss_v2_data.get('vectorString') if cvss_v2_data else None),
                    'published_date': nvd_data.get('published'),
                    'modified_date': nvd_data.get('last_modified'),
                    'references': [ref.get('url') for ref in nvd_data.get('references', []) if ref.get('url')],
                    'exploit_available': False,  # NVD API doesn't provide this directly
                    'cwe_ids': nvd_data.get('weaknesses', []),
                    'affected_products': nvd_data.get('affected_products', []),
                    'source': 'nvd_api',
                    'source_url': nvd_data.get('source_url')
                }
                
                logger.info(f"Successfully fetched {cve_id} from NVD API")
                
                return {
                    'status': 'success',
                    'data': cve_data
                }, 200
                
            finally:
                session.close()
                
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
            from utils.validation import validate_cve_id
            
            data = request.get_json()
            
            if not data or 'cve_id' not in data:
                return jsonify({
                    'status': 'error',
                    'error': 'cve_id is required'
                }), 400
            
            # Validate CVE ID format
            try:
                cve_id = validate_cve_id(data['cve_id'])
            except ValueError as e:
                return jsonify({
                    'status': 'error',
                    'error': str(e)
                }), 400
            
            sources = data.get('sources')
            vuln_data = {'cve_id': cve_id}
            
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
            from utils.validation import validate_scan_id
            
            # Validate exploit ID to prevent injection
            try:
                exploit_id = validate_scan_id(exploit_id)
            except ValueError as e:
                return {
                    'status': 'error',
                    'error': str(e)
                }, 400
            
            from config.models import FeedEntry
            from config.database import SessionLocal
            
            session = SessionLocal()
            try:
                entry = session.query(FeedEntry).filter(
                    FeedEntry.entry_id == exploit_id,
                    FeedEntry.feed_source == 'exploitdb'
                ).first()
                
                if not entry:
                    logger.warning(f"Exploit not found in database: {exploit_id}")
                    return {
                        'status': 'error',
                        'error': f'Exploit not found: {exploit_id}'
                    }, 404
            finally:
                session.close()
                
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
            from utils.validation import sanitize_search_query, validate_severity, validate_days
            
            # Validate and sanitize inputs
            keyword = request.args.get('keyword')
            if keyword:
                keyword = sanitize_search_query(keyword)
            
            severity = validate_severity(request.args.get('severity'))
            
            try:
                days = validate_days(int(request.args.get('days', 7)))
            except (ValueError, TypeError) as e:
                return {'status': 'error', 'error': f'Invalid days parameter: {e}'}, 400
            
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
            from utils.validation import validate_days, validate_limit_offset
            
            try:
                days = validate_days(int(request.args.get('days', 7)))
                limit = int(request.args.get('limit', 50))
                limit, _ = validate_limit_offset(limit, 0)
            except (ValueError, TypeError) as e:
                return jsonify({
                    'status': 'error',
                    'error': f'Invalid parameters: {e}'
                }), 400
            
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
            from utils.validation import validate_days, validate_positive_integer, validate_boolean_param
            
            data = request.get_json() or {}
            
            # Validate numeric parameters
            try:
                nvd_days = validate_days(int(data.get('nvd_days', 7)))
                nvd_batch = validate_positive_integer(int(data.get('nvd_batch', 100)), 'nvd_batch', max_value=1000)
                edb_max = validate_positive_integer(int(data.get('edb_max', 50)), 'edb_max', max_value=500)
            except (ValueError, TypeError) as e:
                return jsonify({
                    'status': 'error',
                    'error': f'Invalid parameters: {e}'
                }), 400
            
            # Validate boolean parameters
            try:
                sync_nvd = validate_boolean_param(str(data.get('sync_nvd', True)), 'sync_nvd')
                sync_edb = validate_boolean_param(str(data.get('sync_edb', True)), 'sync_edb')
            except ValueError as e:
                return jsonify({
                    'status': 'error',
                    'error': str(e)
                }), 400
            
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
            from utils.validation import validate_severity, validate_boolean_param, validate_days
            
            # Validate inputs
            try:
                severity_param = request.args.get('severity', 'CRITICAL')
                severity = validate_severity(severity_param)
                
                with_exploits = validate_boolean_param(
                    request.args.get('with_exploits', 'true'),
                    'with_exploits'
                )
                
                days = validate_days(int(request.args.get('days', 7)))
            except (ValueError, TypeError) as e:
                return {
                    'status': 'error',
                    'error': f'Invalid parameters: {e}'
                }, 400
            
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
            
        Note: Results cached for 5 minutes to reduce database load
        """
        try:
            # Check cache first
            with _stats_cache_lock:
                if _stats_cache['data'] is not None and _stats_cache['timestamp'] is not None:
                    age = (datetime.utcnow() - _stats_cache['timestamp']).total_seconds()
                    if age < _stats_cache_ttl:
                        logger.debug(f"Returning cached feed statistics (age: {age:.1f}s)")
                        return jsonify({
                            'status': 'success',
                            'data': _stats_cache['data'],
                            'cached': True,
                            'cache_age_seconds': round(age, 1)
                        }), 200
            
            logger.info("Fetching feed statistics from database (cache miss or expired)...")
            
            from config.models import FeedEntry
            from config.database import SessionLocal
            
            session = SessionLocal()
            try:
                # Optimize: Use single aggregated query instead of multiple COUNT queries (Issue P6)
                # OLD: 8 separate COUNT queries (slow)
                # NEW: 2 aggregated queries (5-10x faster)
                
                # Query 1: Count by source
                source_stats = session.query(
                    FeedEntry.feed_source,
                    func.count(FeedEntry.id).label('count')
                ).group_by(FeedEntry.feed_source).all()
                
                source_counts = {row.feed_source: row.count for row in source_stats}
                total_entries = sum(source_counts.values())
                nvd_count = source_counts.get('nvd', 0)
                edb_count = source_counts.get('exploitdb', 0)
                
                # Query 2: Count by severity
                severity_stats_query = session.query(
                    FeedEntry.severity,
                    func.count(FeedEntry.id).label('count')
                ).group_by(FeedEntry.severity).all()
                
                severity_stats = {row.severity: row.count for row in severity_stats_query if row.severity}
                # Ensure all severities present
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    severity_stats.setdefault(severity, 0)
                
                # Query 3: Recent activity (last 7 days) by source
                week_ago = datetime.utcnow() - timedelta(days=7)
                recent_stats = session.query(
                    FeedEntry.feed_source,
                    func.count(FeedEntry.id).label('count')
                ).filter(
                    FeedEntry.published_date >= week_ago
                ).group_by(FeedEntry.feed_source).all()
                
                recent_counts = {row.feed_source: row.count for row in recent_stats}
                recent_nvd = recent_counts.get('nvd', 0)
                recent_edb = recent_counts.get('exploitdb', 0)
                
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
                
                # Update cache
                with _stats_cache_lock:
                    _stats_cache['data'] = stats
                    _stats_cache['timestamp'] = datetime.utcnow()
                    logger.info("Feed statistics cached for 5 minutes")
                    
            finally:
                session.close()
            
            return jsonify({
                'status': 'success',
                'data': stats,
                'cached': False
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
            from config.database import SessionLocal
            
            from utils.validation import validate_severity, validate_limit_offset, sanitize_search_query
            
            # Validate inputs
            severity = validate_severity(request.args.get('severity'))
            
            try:
                limit = int(request.args.get('limit', 50))
                offset = int(request.args.get('offset', 0))
                limit, offset = validate_limit_offset(limit, offset)
            except (ValueError, TypeError) as e:
                return {'status': 'error', 'error': f'Invalid pagination: {e}'}, 400
            
            search = request.args.get('search', '').strip()
            if search:
                try:
                    search = sanitize_search_query(search)
                except ValueError as e:
                    return {'status': 'error', 'error': str(e)}, 400
            
            session = SessionLocal()
            try:
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
            finally:
                session.close()
                
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
            from config.database import SessionLocal
            from utils.validation import validate_limit_offset, sanitize_search_query
            
            try:
                limit = int(request.args.get('limit', 50))
                offset = int(request.args.get('offset', 0))
                limit, offset = validate_limit_offset(limit, offset)
            except (ValueError, TypeError) as e:
                return {'status': 'error', 'error': f'Invalid pagination: {e}'}, 400
            
            search = request.args.get('search', '').strip()
            if search:
                try:
                    search = sanitize_search_query(search)
                except ValueError as e:
                    return {'status': 'error', 'error': str(e)}, 400
            search = request.args.get('search', '').strip()
            
            session = SessionLocal()
            try:
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
            finally:
                session.close()
                
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
