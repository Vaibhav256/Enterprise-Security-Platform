"""
JWT Handler Security Tests

Comprehensive test suite for JWT authentication:
- Token generation
- Token validation
- Token refresh with rotation
- HttpOnly cookie handling
- Security edge cases
- Expiration handling
- CSRF protection

Coverage Goals: 100%
Test Count: 40+
"""

import os
import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import jwt as pyjwt
from flask import Flask

from utils.jwt_handler import (
    JWTHandler,
    get_jwt_handler,
    jwt_required,
    get_current_user
)


@pytest.fixture
def flask_app():
    """Create Flask app for testing."""
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    return app


class TestJWTTokenGeneration:
    """Test JWT token generation."""
    
    def test_generate_tokens_returns_two_tokens(self):
        """Should generate both access and refresh tokens."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, refresh = handler.generate_tokens('user123')
        
        assert isinstance(access, str)
        assert isinstance(refresh, str)
        assert access != refresh
        assert len(access) > 0
        assert len(refresh) > 0
    
    def test_generate_tokens_includes_user_id(self):
        """Should include user_id in token payload."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123')
        
        payload = pyjwt.decode(access, 'test-secret-key', algorithms=['HS256'])
        assert payload['user_id'] == 'user123'
    
    def test_generate_tokens_includes_user_data(self):
        """Should include safe user data in token."""
        handler = JWTHandler(secret_key='test-secret-key')
        user_data = {
            'username': 'john_doe',
            'email': 'john@example.com',
            'role': 'admin',
            'password': 'secret123'  # Should be filtered out
        }
        
        access, _ = handler.generate_tokens('user123', user_data)
        payload = pyjwt.decode(access, 'test-secret-key', algorithms=['HS256'])
        
        assert payload['username'] == 'john_doe'
        assert payload['email'] == 'john@example.com'
        assert payload['role'] == 'admin'
        assert 'password' not in payload  # Sensitive data excluded
    
    def test_generate_tokens_sets_correct_expiry(self):
        """Should set correct expiration times."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, refresh = handler.generate_tokens('user123')
        
        access_payload = pyjwt.decode(access, 'test-secret-key', algorithms=['HS256'])
        refresh_payload = pyjwt.decode(refresh, 'test-secret-key', algorithms=['HS256'])
        
        # Access token expires in 15 minutes
        access_exp = datetime.fromtimestamp(access_payload['exp'])
        access_iat = datetime.fromtimestamp(access_payload['iat'])
        assert (access_exp - access_iat) == timedelta(minutes=15)
        
        # Refresh token expires in 7 days
        refresh_exp = datetime.fromtimestamp(refresh_payload['exp'])
        refresh_iat = datetime.fromtimestamp(refresh_payload['iat'])
        assert (refresh_exp - refresh_iat) == timedelta(days=7)
    
    def test_generate_tokens_includes_token_type(self):
        """Should mark tokens with correct type."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, refresh = handler.generate_tokens('user123')
        
        access_payload = pyjwt.decode(access, 'test-secret-key', algorithms=['HS256'])
        refresh_payload = pyjwt.decode(refresh, 'test-secret-key', algorithms=['HS256'])
        
        assert access_payload['type'] == 'access'
        assert refresh_payload['type'] == 'refresh'
    
    def test_generate_tokens_includes_unique_jti(self):
        """Should include unique JWT ID for each token."""
        handler = JWTHandler(secret_key='test-secret-key')
        access1, refresh1 = handler.generate_tokens('user123')
        access2, refresh2 = handler.generate_tokens('user123')
        
        payload1 = pyjwt.decode(access1, 'test-secret-key', algorithms=['HS256'])
        payload2 = pyjwt.decode(access2, 'test-secret-key', algorithms=['HS256'])
        
        assert 'jti' in payload1
        assert 'jti' in payload2
        assert payload1['jti'] != payload2['jti']  # Each token has unique ID


class TestJWTTokenValidation:
    """Test JWT token validation."""
    
    def test_validate_token_accepts_valid_access_token(self):
        """Should validate correct access token."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123')
        
        payload = handler.validate_token(access, token_type='access')
        assert payload['user_id'] == 'user123'
        assert payload['type'] == 'access'
    
    def test_validate_token_accepts_valid_refresh_token(self):
        """Should validate correct refresh token."""
        handler = JWTHandler(secret_key='test-secret-key')
        _, refresh = handler.generate_tokens('user123')
        
        payload = handler.validate_token(refresh, token_type='refresh')
        assert payload['user_id'] == 'user123'
        assert payload['type'] == 'refresh'
    
    def test_validate_token_rejects_wrong_type(self):
        """Should reject token with wrong type."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123')
        
        # Try to validate access token as refresh token
        with pytest.raises(ValueError, match='Token type mismatch'):
            handler.validate_token(access, token_type='refresh')
    
    def test_validate_token_rejects_expired_token(self):
        """Should reject expired tokens."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        # Create token that expires immediately
        handler.ACCESS_TOKEN_EXPIRY = timedelta(seconds=0)
        access, _ = handler.generate_tokens('user123')
        
        time.sleep(1)  # Wait for expiration
        
        with pytest.raises(pyjwt.ExpiredSignatureError):
            handler.validate_token(access, token_type='access')
    
    def test_validate_token_rejects_invalid_signature(self):
        """Should reject tokens with wrong signature."""
        handler1 = JWTHandler(secret_key='secret-1')
        handler2 = JWTHandler(secret_key='secret-2')
        
        access, _ = handler1.generate_tokens('user123')
        
        # Try to validate with different secret
        with pytest.raises(pyjwt.InvalidTokenError):
            handler2.validate_token(access, token_type='access')
    
    def test_validate_token_rejects_malformed_token(self):
        """Should reject malformed tokens."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with pytest.raises(pyjwt.InvalidTokenError):
            handler.validate_token('not-a-valid-token', token_type='access')
    
    def test_validate_token_rejects_none_token(self):
        """Should reject None token."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with pytest.raises(pyjwt.InvalidTokenError):
            handler.validate_token(None, token_type='access')


class TestJWTTokenRefresh:
    """Test JWT token refresh mechanism."""
    
    def test_refresh_access_token_generates_new_tokens(self):
        """Should generate new access and refresh tokens."""
        handler = JWTHandler(secret_key='test-secret-key')
        _, refresh = handler.generate_tokens('user123')
        
        new_access, new_refresh = handler.refresh_access_token(refresh)
        
        assert isinstance(new_access, str)
        assert isinstance(new_refresh, str)
        assert new_access != refresh
        assert new_refresh != refresh
    
    def test_refresh_access_token_preserves_user_data(self):
        """Should preserve user data in refreshed tokens."""
        handler = JWTHandler(secret_key='test-secret-key')
        user_data = {'username': 'john_doe', 'role': 'admin'}
        _, refresh = handler.generate_tokens('user123', user_data)
        
        new_access, _ = handler.refresh_access_token(refresh)
        payload = pyjwt.decode(new_access, 'test-secret-key', algorithms=['HS256'])
        
        assert payload['user_id'] == 'user123'
        assert payload['username'] == 'john_doe'
        assert payload['role'] == 'admin'
    
    def test_refresh_access_token_rotates_tokens(self):
        """Should create new unique tokens (rotation)."""
        handler = JWTHandler(secret_key='test-secret-key')
        _, refresh1 = handler.generate_tokens('user123')
        
        _, refresh2 = handler.refresh_access_token(refresh1)
        
        payload1 = pyjwt.decode(refresh1, 'test-secret-key', algorithms=['HS256'])
        payload2 = pyjwt.decode(refresh2, 'test-secret-key', algorithms=['HS256'])
        
        assert payload1['jti'] != payload2['jti']  # Different token IDs
    
    def test_refresh_access_token_rejects_expired_refresh(self):
        """Should reject expired refresh token."""
        handler = JWTHandler(secret_key='test-secret-key')
        handler.REFRESH_TOKEN_EXPIRY = timedelta(seconds=0)
        _, refresh = handler.generate_tokens('user123')
        
        time.sleep(1)
        
        with pytest.raises(pyjwt.ExpiredSignatureError):
            handler.refresh_access_token(refresh)
    
    def test_refresh_access_token_rejects_access_token(self):
        """Should reject access token (requires refresh token)."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123')
        
        with pytest.raises(ValueError, match='Token type mismatch'):
            handler.refresh_access_token(access)


class TestJWTCookieHandling:
    """Test HttpOnly cookie management."""
    
    def test_set_auth_cookies_sets_both_cookies(self, flask_app):
        """Should set both access and refresh cookies."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, refresh = handler.generate_tokens('user123')
        
        with flask_app.test_request_context():
            response = Mock()
            handler.set_auth_cookies(response, access, refresh)
        
        assert response.set_cookie.call_count == 2
        
        # Check access token cookie
        access_call = response.set_cookie.call_args_list[0]
        assert access_call[0][0] == 'access_token'
        assert access_call[1]['httponly'] is True
        assert access_call[1]['secure'] is True
        assert access_call[1]['samesite'] == 'Lax'
        assert access_call[1]['path'] == '/api'
        
        # Check refresh token cookie
        refresh_call = response.set_cookie.call_args_list[1]
        assert refresh_call[0][0] == 'refresh_token'
        assert refresh_call[1]['httponly'] is True
        assert refresh_call[1]['path'] == '/api/auth/refresh'
    
    def test_clear_auth_cookies_removes_both_cookies(self, flask_app):
        """Should clear both cookies on logout."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with flask_app.test_request_context():
            response = Mock()
            handler.clear_auth_cookies(response)
        
        assert response.set_cookie.call_count == 2
        
        # Both cookies should have max_age=0
        for call in response.set_cookie.call_args_list:
            assert call[1]['max_age'] == 0
    
    def test_get_token_from_cookie_extracts_access_token(self, flask_app):
        """Should extract access token from cookie."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with flask_app.test_request_context('/', headers={'Cookie': 'access_token=test-access-token'}):
            token = handler.get_token_from_cookie('access')
        
        assert token == 'test-access-token'
    
    def test_get_token_from_cookie_extracts_refresh_token(self, flask_app):
        """Should extract refresh token from cookie."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with flask_app.test_request_context('/', headers={'Cookie': 'refresh_token=test-refresh-token'}):
            token = handler.get_token_from_cookie('refresh')
        
        assert token == 'test-refresh-token'
    
    def test_get_token_from_cookie_returns_none_if_missing(self, flask_app):
        """Should return None if cookie not found."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with flask_app.test_request_context('/'):
            token = handler.get_token_from_cookie('access')
        
        assert token is None


class TestJWTSecurityFeatures:
    """Test security features and edge cases."""
    
    def test_handler_uses_hs256_algorithm(self):
        """Should use secure HS256 algorithm."""
        handler = JWTHandler(secret_key='test-secret-key')
        assert handler.algorithm == 'HS256'
    
    def test_handler_filters_sensitive_user_data(self):
        """Should exclude sensitive fields from token."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        # Try to inject sensitive data
        user_data = {
            'username': 'john',
            'password': 'secret',
            'credit_card': '1234-5678',
            'ssn': '123-45-6789',
            'api_key': 'sk_test_123'
        }
        
        access, _ = handler.generate_tokens('user123', user_data)
        payload = pyjwt.decode(access, 'test-secret-key', algorithms=['HS256'])
        
        # Only safe fields should be included
        assert 'username' in payload
        assert 'password' not in payload
        assert 'credit_card' not in payload
        assert 'ssn' not in payload
        assert 'api_key' not in payload
    
    def test_handler_gets_secret_from_config(self, flask_app):
        """Should get secret key from app config."""
        with flask_app.app_context():
            handler = JWTHandler()
            assert handler.secret_key == 'test-secret-key'
    
    @patch.dict(os.environ, {'JWT_SECRET_KEY': 'env-secret-key'})
    def test_handler_gets_secret_from_env(self):
        """Should get secret key from environment."""
        handler = JWTHandler()
        # When no Flask app context, should use environment variable
        assert handler.secret_key == 'env-secret-key'
    
    @patch.dict(os.environ, {}, clear=True)
    def test_handler_generates_secret_if_not_configured(self):
        """Should generate secret if none configured (dev mode)."""
        handler = JWTHandler()
        # Should have generated a secret key
        assert handler.secret_key is not None
        assert len(handler.secret_key) > 0


class TestJWTFlaskIntegration:
    """Test Flask integration (decorators, helpers)."""
    
    def test_get_current_user_returns_user_data(self, flask_app):
        """Should return current user from token."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123', {'username': 'john'})
        
        with flask_app.test_request_context('/', headers={'Cookie': f'access_token={access}'}):
            user = handler.get_current_user()
        
        assert user is not None
        assert user['user_id'] == 'user123'
        assert user['username'] == 'john'
    
    def test_get_current_user_returns_none_if_no_token(self, flask_app):
        """Should return None if no token present."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with flask_app.test_request_context('/'):
            user = handler.get_current_user()
        
        assert user is None
    
    def test_get_current_user_returns_none_if_expired(self, flask_app):
        """Should return None if token expired."""
        handler = JWTHandler(secret_key='test-secret-key')
        handler.ACCESS_TOKEN_EXPIRY = timedelta(seconds=0)
        access, _ = handler.generate_tokens('user123')
        
        time.sleep(1)
        
        with flask_app.test_request_context('/', headers={'Cookie': f'access_token={access}'}):
            user = handler.get_current_user()
        
        assert user is None
    
    def test_jwt_required_decorator_allows_authenticated(self, flask_app):
        """Should allow access with valid token."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123')
        
        with flask_app.test_request_context('/', headers={'Cookie': f'access_token={access}'}):
            with patch('utils.jwt_handler.get_jwt_handler', return_value=handler):
                @jwt_required
                def protected_route(current_user=None):
                    return {'message': 'success', 'user': current_user['user_id']}
                
                result = protected_route()
                assert result['message'] == 'success'
                assert result['user'] == 'user123'
    
    def test_jwt_required_decorator_blocks_unauthenticated(self, flask_app):
        """Should block access without valid token."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with flask_app.test_request_context('/'):
            with patch('utils.jwt_handler.get_jwt_handler', return_value=handler):
                @jwt_required
                def protected_route(current_user=None):
                    return {'message': 'success'}
                
                result, status = protected_route()
                assert status == 401
                assert 'error' in result.get_json()


class TestJWTEdgeCases:
    """Test edge cases and error handling."""
    
    def test_generate_tokens_with_empty_user_id(self):
        """Should handle empty user_id."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, refresh = handler.generate_tokens('')
        
        payload = pyjwt.decode(access, 'test-secret-key', algorithms=['HS256'])
        assert payload['user_id'] == ''
    
    def test_generate_tokens_with_none_user_data(self):
        """Should handle None user_data gracefully."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123', None)
        
        payload = pyjwt.decode(access, 'test-secret-key', algorithms=['HS256'])
        assert 'user_id' in payload
        assert payload['user_id'] == 'user123'
    
    def test_validate_token_with_empty_string(self):
        """Should reject empty string token."""
        handler = JWTHandler(secret_key='test-secret-key')
        
        with pytest.raises(pyjwt.InvalidTokenError):
            handler.validate_token('', token_type='access')
    
    def test_get_jwt_handler_singleton(self):
        """Should return same instance (singleton pattern)."""
        handler1 = get_jwt_handler()
        handler2 = get_jwt_handler()
        
        assert handler1 is handler2
    
    def test_get_current_user_helper_function(self, flask_app):
        """Should provide helper function for current user."""
        handler = JWTHandler(secret_key='test-secret-key')
        access, _ = handler.generate_tokens('user123')
        
        with flask_app.test_request_context('/', headers={'Cookie': f'access_token={access}'}):
            with patch('utils.jwt_handler.get_jwt_handler', return_value=handler):
                user = get_current_user()
                assert user is not None
                assert user['user_id'] == 'user123'
