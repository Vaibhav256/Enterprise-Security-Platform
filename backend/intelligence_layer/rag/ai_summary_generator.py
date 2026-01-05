"""
AI Summary Generator Module
Converts tool outputs and vulnerability data into AI-powered executive summaries.
Uses LLM to generate concise, actionable summaries with key insights.
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SummaryType(Enum):
    """Types of summaries"""
    SCAN_EXECUTIVE = "scan_executive"  # High-level scan summary
    FINDING_DETAIL = "finding_detail"  # Single vulnerability detail
    RISK_ASSESSMENT = "risk_assessment"  # Risk analysis and ranking
    REMEDIATION_PLAN = "remediation_plan"  # Action items
    TREND_ANALYSIS = "trend_analysis"  # Vulnerability trends


@dataclass
class AISummary:
    """Structured AI-generated summary"""
    summary_id: str
    type: str  # SummaryType
    title: str
    executive_summary: str  # Main summary (2-3 sentences)
    key_findings: List[str]  # Top 3-5 findings
    risk_score: float  # 0.0-1.0
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    recommendations: List[str]  # Action items
    affected_systems: List[str] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    source_tool: str = ""  # Nessus, OpenVAS, Nmap, etc.
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    confidence: float = 0.8
    
    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)
    
    def to_markdown(self) -> str:
        """Convert to markdown format"""
        md = f"""# {self.title}

**Risk Level:** {self.risk_level} (Score: {self.risk_score:.2f})

## Executive Summary
{self.executive_summary}

## Key Findings
{chr(10).join(f"- {finding}" for finding in self.key_findings)}

## Affected Systems
{chr(10).join(f"- {system}" for system in self.affected_systems) if self.affected_systems else "- No specific systems identified"}

## Related CVEs
{chr(10).join(f"- {cve}" for cve in self.related_cves) if self.related_cves else "- No CVEs directly related"}

## Recommendations
{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(self.recommendations))}

---
*Summary generated: {self.generated_at} | Confidence: {self.confidence:.0%}*
"""
        return md


@dataclass
class ScanData:
    """Input scan data for summary generation"""
    scan_id: str
    tool_name: str  # Nessus, OpenVAS, Nmap, etc.
    scan_type: str  # vulnerability, port_scan, etc.
    findings: List[Dict[str, Any]]
    scan_date: Optional[str] = None
    target: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AISummaryGenerator:
    """
    Generates AI-powered summaries using LLM.
    
    Features:
    - Multi-format input support (Nessus, OpenVAS, Nmap, custom JSON)
    - Intelligent finding prioritization
    - Risk scoring and assessment
    - Actionable recommendations
    - Streaming support for large summaries
    """
    
    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        model_name: str = "llama3.2:3b-instruct-q4_K_M",
        temperature: float = 0.4,
        max_tokens: int = 1024,
        stream: bool = False
    ):
        """
        Initialize AI Summary Generator.
        
        Args:
            ollama_base_url: Ollama API endpoint
            model_name: LLM model name
            temperature: Temperature (lower = more factual)
            max_tokens: Max tokens in summary
            stream: Enable streaming responses
        """
        self.ollama_base_url = ollama_base_url
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.stream = stream
        
        # Verify connection
        self._verify_ollama()
    
    def _verify_ollama(self) -> bool:
        """Verify Ollama is running"""
        try:
            response = requests.get(
                f"{self.ollama_base_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                logger.info("✓ Ollama connection verified")
                return True
        except Exception as e:
            logger.error(f"✗ Ollama not available: {e}")
        return False
    
    def generate_scan_summary(
        self,
        scan_data: ScanData,
        summary_type: str = "scan_executive"
    ) -> AISummary:
        """
        Generate AI summary for a complete scan.
        
        Args:
            scan_data: ScanData object with findings
            summary_type: Type of summary (scan_executive, risk_assessment, etc.)
        
        Returns:
            AISummary object
        """
        logger.info(f"Generating {summary_type} summary for scan {scan_data.scan_id}")
        
        # Prepare context
        context = self._prepare_scan_context(scan_data)
        
        # Get LLM response
        summary_response = self._call_llm_for_summary(context, summary_type)
        
        # Parse response and create AISummary
        summary = self._parse_summary_response(
            summary_response,
            scan_data,
            summary_type
        )
        
        return summary
    
    def generate_finding_summary(
        self,
        finding: Dict[str, Any],
        tool_name: str = "Generic"
    ) -> AISummary:
        """
        Generate AI summary for a single finding.
        
        Args:
            finding: Finding dictionary
            tool_name: Source tool name
        
        Returns:
            AISummary object
        """
        logger.info(f"Generating finding summary for {finding.get('id', 'unknown')}")
        
        # Prepare context
        context = self._prepare_finding_context(finding, tool_name)
        
        # Get LLM response
        summary_response = self._call_llm_for_finding(context)
        
        # Parse and return
        summary = self._parse_finding_response(summary_response, finding, tool_name)
        
        return summary
    
    def generate_risk_assessment(
        self,
        scan_data: ScanData
    ) -> AISummary:
        """
        Generate AI risk assessment and prioritization.
        
        Args:
            scan_data: ScanData object with findings
        
        Returns:
            AISummary with risk assessment
        """
        logger.info(f"Generating risk assessment for scan {scan_data.scan_id}")
        
        # Analyze findings
        context = self._prepare_risk_context(scan_data)
        
        # Get LLM analysis
        response = self._call_llm_for_risk(context)
        
        # Parse and return
        summary = self._parse_risk_response(response, scan_data)
        
        return summary
    
    def generate_remediation_plan(
        self,
        scan_data: ScanData
    ) -> AISummary:
        """
        Generate prioritized remediation plan.
        
        Args:
            scan_data: ScanData object with findings
        
        Returns:
            AISummary with remediation steps
        """
        logger.info(f"Generating remediation plan for scan {scan_data.scan_id}")
        
        # Prepare context
        context = self._prepare_remediation_context(scan_data)
        
        # Get LLM recommendations
        response = self._call_llm_for_remediation(context)
        
        # Parse and return
        summary = self._parse_remediation_response(response, scan_data)
        
        return summary
    
    # --- Private Helper Methods ---
    
    def _prepare_scan_context(self, scan_data: ScanData) -> str:
        """Prepare context for scan summary"""
        findings_summary = self._summarize_findings(scan_data.findings)
        detailed_findings = self._create_detailed_findings_list(scan_data.findings)
        severity_counts = self._get_severity_counts(scan_data.findings)
        
        context = f"""
Analyze this security scan data and provide a COMPREHENSIVE executive summary with ALL findings explained in detail:

Tool: {scan_data.tool_name}
Scan Type: {scan_data.scan_type}
Target: {scan_data.target or 'Not specified'}
Scan Date: {scan_data.scan_date or 'Not specified'}
Total Findings: {len(scan_data.findings)}

Severity Distribution:
{severity_counts}

COMPLETE FINDINGS LIST (ALL {len(scan_data.findings)} items):
{detailed_findings}

IMPORTANT INSTRUCTIONS:
1. Create a detailed summary that lists EVERY finding, not just top 3
2. For each finding, explain WHAT it is, WHY it matters, and WHAT to do about it
3. Group findings by type or category for better organization
4. Set risk_level based on ACTUAL severity: if all are INFO, use INFO; if has CRITICAL, use CRITICAL
5. Set risk_score accurately: INFO=0.0-0.2, LOW=0.2-0.4, MEDIUM=0.4-0.6, HIGH=0.6-0.8, CRITICAL=0.8-1.0
6. Include specific technical details from descriptions
7. Provide actionable recommendations for each finding type

Generate comprehensive analysis with:
- Executive summary covering all findings
- Key findings list with at least 10+ items (covering all major finding types)
- Accurate risk_level matching the actual severity distribution
- Detailed recommendations for each finding category

Format as JSON with fields: title, executive_summary, key_findings (comprehensive list with descriptions), risk_score (accurate based on severity), risk_level (matching severity distribution), recommendations (detailed list)
"""
        return context
    
    def _prepare_finding_context(self, finding: Dict, tool_name: str) -> str:
        """Prepare context for single finding summary"""
        context = f"""
Analyze this security finding and provide detailed insights:

Source Tool: {tool_name}
Finding ID: {finding.get('id', 'unknown')}
Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'unknown')}
Description: {finding.get('description', 'No description')}
Affected: {finding.get('affected_component', 'unknown')}
CWE: {finding.get('cwe', 'N/A')}
CVE: {finding.get('cve', 'N/A')}

Provide detailed analysis including:
1. What this vulnerability means
2. Potential impact
3. How to remediate
4. Prevention strategies

Format as JSON with: title, executive_summary, key_findings (list), risk_score, risk_level, recommendations (list), related_cves (list)
"""
        return context
    
    def _prepare_risk_context(self, scan_data: ScanData) -> str:
        """Prepare context for risk assessment"""
        findings_by_severity = self._group_findings_by_severity(scan_data.findings)
        
        context = f"""
Perform a risk assessment on this scan data:

Scan: {scan_data.scan_id}
Tool: {scan_data.tool_name}
Target: {scan_data.target or 'Multiple'}

Findings by Severity:
{findings_by_severity}

Provide risk assessment including:
1. Overall risk score (0-1)
2. Risk level (CRITICAL/HIGH/MEDIUM/LOW)
3. Top 5 risks to address
4. Business impact
5. Recommended prioritization

Format as JSON: title, executive_summary, key_findings, risk_score, risk_level, recommendations
"""
        return context
    
    def _prepare_remediation_context(self, scan_data: ScanData) -> str:
        """Prepare context for remediation planning"""
        findings_summary = self._summarize_findings(scan_data.findings)
        
        context = f"""
Create a prioritized remediation plan for these findings:

Scan: {scan_data.scan_id}
Tool: {scan_data.tool_name}

Findings:
{findings_summary}

Generate a remediation plan with:
1. Priority 1 items (immediate)
2. Priority 2 items (this week)
3. Priority 3 items (this month)
4. Long-term improvements
5. Testing/validation steps

Include effort estimation and expected impact for each.

Format as JSON: title, executive_summary, recommendations (list with priority), key_findings, risk_level
"""
        return context
    
    def _summarize_findings(self, findings: List[Dict]) -> str:
        """Create text summary of findings"""
        if not findings:
            return "No findings"
        
        summary_lines = []
        for i, finding in enumerate(findings[:10], 1):  # First 10 findings
            severity = finding.get('severity', 'unknown').upper()
            title = finding.get('title', 'Unknown')
            summary_lines.append(f"{i}. [{severity}] {title}")
        
        if len(findings) > 10:
            summary_lines.append(f"... and {len(findings) - 10} more findings")
        
        return "\n".join(summary_lines)
    
    def _create_detailed_findings_list(self, findings: List[Dict]) -> str:
        """Create detailed list of ALL findings with descriptions"""
        if not findings:
            return "No findings"
        
        detailed_lines = []
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'unknown').upper()
            title = finding.get('title', 'Unknown')
            
            # Extract description from various sources
            description = None
            metadata = finding.get('metadata', {})
            
            # Try to get description from different locations
            if 'description' in metadata:
                description = metadata['description']
            elif 'info' in metadata and isinstance(metadata['info'], dict):
                info = metadata['info']
                description = info.get('description', '')
            
            # Build detailed entry
            entry = f"{i}. [{severity}] {title}"
            if description:
                # Truncate long descriptions
                desc_preview = description[:200] if len(description) > 200 else description
                entry += f"\n   Description: {desc_preview}"
            
            # Add host/port if available
            host = metadata.get('host', '')
            port = finding.get('port', metadata.get('port'))
            if host:
                entry += f"\n   Host: {host}"
            if port:
                entry += f"\n   Port: {port}"
            
            detailed_lines.append(entry)
        
        return "\n".join(detailed_lines)
    
    def _get_severity_counts(self, findings: List[Dict]) -> str:
        """Get severity distribution"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        
        lines = []
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if counts[sev] > 0:
                lines.append(f"- {sev.upper()}: {counts[sev]}")
        
        return "\n".join(lines) if lines else "- No findings"
    
    def _group_findings_by_severity(self, findings: List[Dict]) -> str:
        """Group findings by severity"""
        severity_groups = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'INFO').upper()
            if severity not in severity_groups:
                severity = 'INFO'
            severity_groups[severity].append(finding.get('title', 'Unknown'))
        
        lines = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = len(severity_groups[severity])
            if count > 0:
                lines.append(f"- {severity}: {count} issues")
        
        return "\n".join(lines) if lines else "- No findings"
    
    def _call_llm_for_summary(self, context: str, summary_type: str) -> str:
        """Call LLM to generate summary"""
        prompt = f"Task: Generate {summary_type}\n\n{context}"
        return self._call_ollama(prompt)
    
    def _call_llm_for_finding(self, context: str) -> str:
        """Call LLM to analyze finding"""
        return self._call_ollama(context)
    
    def _call_llm_for_risk(self, context: str) -> str:
        """Call LLM for risk assessment"""
        return self._call_ollama(context)
    
    def _call_llm_for_remediation(self, context: str) -> str:
        """Call LLM for remediation planning"""
        return self._call_ollama(context)
    
    def _call_ollama(self, prompt: str, stream: bool = False, max_retries: int = 3) -> str:
        """
        Call Ollama LLM with retry logic.
        
        Args:
            prompt: The prompt to send to the LLM
            stream: Whether to use streaming response
            max_retries: Maximum number of retry attempts (default: 3)
        
        Returns:
            LLM response string, or empty string on failure
        """
        import time
        
        for attempt in range(max_retries):
            try:
                payload = {
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": stream or self.stream,
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                }
                
                # Exponential backoff: 2^attempt seconds (0s, 2s, 4s)
                if attempt > 0:
                    backoff_time = 2 ** attempt
                    logger.info(f"Retry attempt {attempt + 1}/{max_retries} after {backoff_time}s backoff")
                    time.sleep(backoff_time)
                
                response = requests.post(
                    f"{self.ollama_base_url}/api/generate",
                    json=payload,
                    timeout=60,  # 60 second timeout for LLM generation
                    stream=stream or self.stream
                )
                
                if response.status_code == 200:
                    if stream or self.stream:
                        # Streaming response
                        full_response = ""
                        for line in response.iter_lines():
                            if line:
                                data = json.loads(line)
                                full_response += data.get('response', '')
                        
                        if full_response.strip():
                            logger.info(f"✓ LLM call succeeded on attempt {attempt + 1}")
                            return full_response
                        else:
                            logger.warning(f"⚠ LLM returned empty response on attempt {attempt + 1}")
                            if attempt < max_retries - 1:
                                continue  # Retry
                            else:
                                return ""  # Final attempt failed
                    else:
                        # Non-streaming response
                        data = response.json()
                        llm_response = data.get('response', '')
                        
                        if llm_response.strip():
                            logger.info(f"✓ LLM call succeeded on attempt {attempt + 1}")
                            return llm_response
                        else:
                            logger.warning(f"⚠ LLM returned empty response on attempt {attempt + 1}")
                            if attempt < max_retries - 1:
                                continue  # Retry
                            else:
                                return ""  # Final attempt failed
                else:
                    logger.error(f"✗ LLM error on attempt {attempt + 1}: HTTP {response.status_code}")
                    if attempt < max_retries - 1:
                        continue  # Retry on HTTP errors
                    else:
                        return ""  # Final attempt failed
            
            except requests.exceptions.Timeout:
                logger.error(f"✗ LLM timeout on attempt {attempt + 1} (60s limit exceeded)")
                if attempt < max_retries - 1:
                    continue  # Retry on timeout
                else:
                    return ""  # Final attempt failed
            
            except requests.exceptions.ConnectionError as e:
                logger.error(f"✗ LLM connection error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    continue  # Retry on connection errors
                else:
                    return ""  # Final attempt failed
            
            except Exception as e:
                logger.error(f"✗ LLM call failed on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    continue  # Retry on unexpected errors
                else:
                    return ""  # Final attempt failed
        
        # Should never reach here, but just in case
        logger.error(f"✗ All {max_retries} retry attempts exhausted")
        return ""
    
    def _parse_summary_response(
        self,
        response: str,
        scan_data: ScanData,
        summary_type: str
    ) -> AISummary:
        """Parse LLM response into AISummary"""
        try:
            # Try to extract JSON from response
            json_str = self._extract_json(response)
            data = json.loads(json_str) if json_str else {}
        except Exception as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            data = {}
        
        # Calculate accurate risk level from actual findings
        calculated_risk = self._calculate_risk_from_findings(scan_data.findings)
        
        # Parse key findings - handle both string and dict formats
        key_findings = data.get('key_findings', [])
        formatted_findings = []
        for finding in key_findings:
            if isinstance(finding, dict):
                # Extract readable text from dict
                title = finding.get('title', '')
                desc = finding.get('description', '')
                why = finding.get('why_matters', '')
                what = finding.get('what_to_do', '')
                
                finding_text = title
                if desc:
                    finding_text += f": {desc}"
                if why:
                    finding_text += f" | Impact: {why}"
                if what:
                    finding_text += f" | Action: {what}"
                
                formatted_findings.append(finding_text)
            elif isinstance(finding, str):
                formatted_findings.append(finding)
        
        # Parse recommendations
        recommendations = data.get('recommendations', [])
        formatted_recommendations = []
        for rec in recommendations:
            if isinstance(rec, dict):
                # Extract readable text from dict
                rec_type = rec.get('type', '')
                rec_desc = rec.get('description', '')
                
                if rec_desc:
                    formatted_recommendations.append(rec_desc)
                elif rec_type:
                    formatted_recommendations.append(rec_type.replace('_', ' ').title())
            elif isinstance(rec, str):
                formatted_recommendations.append(rec)
        
        # If no recommendations from LLM, generate defaults
        if not formatted_recommendations:
            formatted_recommendations = self._generate_default_recommendations(scan_data.findings)
        
        # Create summary with calculated risk
        summary = AISummary(
            summary_id=f"summary_{scan_data.scan_id}",
            type=summary_type,
            title=data.get('title', f"{scan_data.tool_name} Scan Summary"),
            executive_summary=data.get('executive_summary', response[:500]),
            key_findings=formatted_findings,
            risk_score=calculated_risk['risk_score'],  # Use calculated score
            risk_level=calculated_risk['risk_level'],  # Use calculated level
            recommendations=formatted_recommendations,  # Use formatted recommendations
            source_tool=scan_data.tool_name,
            confidence=0.85
        )
        
        return summary
    
    def _generate_default_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate default recommendations based on findings"""
        recommendations = []
        severity_counts = self._calculate_risk_from_findings(findings)['severity_counts']
        
        # Add recommendations based on what was found
        if severity_counts['info'] > 0:
            recommendations.append("Review informational findings for potential misconfigurations")
        if severity_counts['low'] > 0:
            recommendations.append("Address low severity findings during regular maintenance cycles")
        if severity_counts['medium'] > 0:
            recommendations.append("Prioritize medium severity findings for resolution within 30 days")
        if severity_counts['high'] > 0:
            recommendations.append("Address high severity findings within 7 days")
        if severity_counts['critical'] > 0:
            recommendations.append("URGENT: Address critical findings immediately")
        
        recommendations.append("Conduct follow-up scans to verify fixes")
        recommendations.append("Update security documentation with findings")
        
        return recommendations
    
    def _calculate_risk_from_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate accurate risk level and score from findings"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Determine risk level based on highest severity with findings
        if severity_counts['critical'] > 0:
            risk_level = 'CRITICAL'
            risk_score = 0.9
        elif severity_counts['high'] > 0:
            risk_level = 'HIGH'
            risk_score = 0.7
        elif severity_counts['medium'] > 0:
            risk_level = 'MEDIUM'
            risk_score = 0.5
        elif severity_counts['low'] > 0:
            risk_level = 'LOW'
            risk_score = 0.3
        else:
            risk_level = 'INFO'
            risk_score = 0.1
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'severity_counts': severity_counts
        }
    
    def _parse_finding_response(
        self,
        response: str,
        finding: Dict,
        tool_name: str
    ) -> AISummary:
        """Parse finding analysis response"""
        try:
            json_str = self._extract_json(response)
            data = json.loads(json_str) if json_str else {}
        except Exception as e:
            logger.warning(f"Failed to parse finding response: {e}")
            data = {}
        
        cves = finding.get('cve', [])
        if isinstance(cves, str):
            cves = [cves] if cves != 'N/A' else []
        
        summary = AISummary(
            summary_id=f"finding_{finding.get('id', 'unknown')}",
            type="finding_detail",
            title=data.get('title', finding.get('title', 'Unknown')),
            executive_summary=data.get('executive_summary', response[:200]),
            key_findings=data.get('key_findings', []),
            risk_score=float(data.get('risk_score', 0.5)),
            risk_level=data.get('risk_level', 'MEDIUM'),
            recommendations=data.get('recommendations', []),
            related_cves=cves,
            source_tool=tool_name,
            confidence=0.85
        )
        
        return summary
    
    def _parse_risk_response(
        self,
        response: str,
        scan_data: ScanData
    ) -> AISummary:
        """Parse risk assessment response"""
        try:
            json_str = self._extract_json(response)
            data = json.loads(json_str) if json_str else {}
        except Exception as e:
            logger.warning(f"Failed to parse risk response: {e}")
            data = {}
        
        summary = AISummary(
            summary_id=f"risk_{scan_data.scan_id}",
            type="risk_assessment",
            title=data.get('title', "Risk Assessment"),
            executive_summary=data.get('executive_summary', response[:200]),
            key_findings=data.get('key_findings', []),
            risk_score=float(data.get('risk_score', 0.5)),
            risk_level=data.get('risk_level', 'MEDIUM'),
            recommendations=data.get('recommendations', []),
            source_tool=scan_data.tool_name,
            confidence=0.85
        )
        
        return summary
    
    def _parse_remediation_response(
        self,
        response: str,
        scan_data: ScanData
    ) -> AISummary:
        """Parse remediation plan response"""
        try:
            json_str = self._extract_json(response)
            data = json.loads(json_str) if json_str else {}
        except Exception as e:
            logger.warning(f"Failed to parse remediation response: {e}")
            data = {}
        
        summary = AISummary(
            summary_id=f"remediation_{scan_data.scan_id}",
            type="remediation_plan",
            title=data.get('title', "Remediation Plan"),
            executive_summary=data.get('executive_summary', response[:200]),
            key_findings=data.get('key_findings', []),
            risk_score=float(data.get('risk_score', 0.5)),
            risk_level=data.get('risk_level', 'MEDIUM'),
            recommendations=data.get('recommendations', []),
            source_tool=scan_data.tool_name,
            confidence=0.85
        )
        
        return summary
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from text"""
        import re
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return match.group(0)
        return ""


# Singleton instance
_summary_generator = None


def get_summary_generator(
    ollama_url: str = "http://localhost:11434"
) -> AISummaryGenerator:
    """Get or create summary generator singleton"""
    global _summary_generator
    if _summary_generator is None:
        _summary_generator = AISummaryGenerator(ollama_base_url=ollama_url)
    return _summary_generator
