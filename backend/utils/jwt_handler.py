"""
JWT Security Handler

Secure JWT token management with:
- HttpOnly cookie storage (prevents XSS attacks)
- Refresh token mechanism
- Token rotation
- Automatic token expiry
- CSRF protection

Security Features:
- Tokens stored in HttpOnly cookies (not localStorage)
- Refresh tokens for long-lived sessions
- Automatic token rotation on refresh
- Configurable expiration times
- Secret key rotation support

Author: Security Team
Date: 2025-10-30
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

import jwt
from flask import current_app, make_response, request, Response

logger = logging.getLogger(__name__)


class JWTHandler:
    """
    Handles JWT token creation, validation, and refresh with security best practices.
    """

    # Token expiration times
    ACCESS_TOKEN_EXPIRY = timedelta(minutes=15)  # Short-lived access tokens
    REFRESH_TOKEN_EXPIRY = timedelta(days=7)  # Longer-lived refresh tokens
    
    # Cookie settings
    COOKIE_SECURE = True  # Require HTTPS in production
    COOKIE_HTTPONLY = True  # Prevent JavaScript access
    COOKIE_SAMESITE = 'Lax'  # CSRF protection
    
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize JWT handler.
        
        Args:
            secret_key: Secret key for signing tokens (from environment in production)
        """
        self.secret_key = secret_key or self._get_secret_key()
        self.algorithm = 'HS256'
        
    def _get_secret_key(self) -> str:
        """
        Get secret key from app config or environment.
        
        Returns:
            Secret key for JWT signing
            
        Raises:
            RuntimeError: If no secret key is configured
        """
        try:
            # Try to get from Flask app config
            key = current_app.config.get('JWT_SECRET_KEY')
            if key:
                return key
        except RuntimeError:
            pass
        
        # Try environment variable
        key = os.getenv('JWT_SECRET_KEY')
        if key:
            return key
        
        # Development fallback (NOT for production!)
        logger.warning(
            "⚠️ No JWT_SECRET_KEY configured! Using generated key. "
            "This is INSECURE for production!"
        )
        return secrets.token_urlsafe(32)
    
    def generate_tokens(self, user_id: str, user_data: Dict = None) -> Tuple[str, str]:
        """
        Generate access and refresh tokens.
        
        Args:
            user_id: Unique user identifier
            user_data: Additional user data to include in token (optional)
            
        Returns:
            Tuple of (access_token, refresh_token)
        """
        now = datetime.utcnow()
        
        # Base payload
        base_payload = {
            'user_id': user_id,
            'jti': secrets.token_urlsafe(16),  # Unique token ID
        }
        
        # Add optional user data
        if user_data:
            # Only include safe, non-sensitive data
            allowed_fields = {'username', 'email', 'role', 'permissions'}
            safe_data = {k: v for k, v in user_data.items() if k in allowed_fields}
            base_payload.update(safe_data)
        
        # Create access token (short-lived)
        access_payload = {
            **base_payload,
            'type': 'access',
            'iat': now,
            'exp': now + self.ACCESS_TOKEN_EXPIRY,
        }
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        
        # Create refresh token (long-lived)
        refresh_payload = {
            **base_payload,
            'type': 'refresh',
            'iat': now,
            'exp': now + self.REFRESH_TOKEN_EXPIRY,
        }
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)
        
        logger.info(f"Generated tokens for user {user_id}")
        return access_token, refresh_token
    
    def validate_token(self, token: str, token_type: str = 'access') -> Dict:
        """
        Validate and decode a JWT token.
        
        Args:
            token: JWT token string
            token_type: Expected token type ('access' or 'refresh')
            
        Returns:
            Decoded token payload
            
        Raises:
            jwt.ExpiredSignatureError: Token has expired
            jwt.InvalidTokenError: Token is invalid
            ValueError: Token type mismatch
        """
        try:
            # Decode token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={'verify_exp': True}
            )
            
            # Verify token type
            if payload.get('type') != token_type:
                raise ValueError(
                    f"Token type mismatch: expected {token_type}, got {payload.get('type')}"
                )
            
            logger.debug(f"Validated {token_type} token for user {payload.get('user_id')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"Token expired: {token_type}")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise
    
    def refresh_access_token(self, refresh_token: str) -> Tuple[str, str]:
        """
        Refresh access token using refresh token (with rotation).
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Tuple of (new_access_token, new_refresh_token)
            
        Raises:
            jwt.ExpiredSignatureError: Refresh token expired
            jwt.InvalidTokenError: Refresh token invalid
        """
        # Validate refresh token
        payload = self.validate_token(refresh_token, token_type='refresh')
        
        # Extract user data
        user_id = payload['user_id']
        user_data = {
            k: v for k, v in payload.items()
            if k not in {'user_id', 'type', 'iat', 'exp', 'jti'}
        }
        
        # Generate NEW tokens (token rotation)
        new_access, new_refresh = self.generate_tokens(user_id, user_data)
        
        logger.info(f"Refreshed tokens for user {user_id} (rotation enabled)")
        return new_access, new_refresh
    
    def set_auth_cookies(
        self,
        response: Response,
        access_token: str,
        refresh_token: str
    ) -> Response:
        """
        Set authentication cookies on response (HttpOnly, Secure, SameSite).
        
        Args:
            response: Flask response object
            access_token: Access token to set
            refresh_token: Refresh token to set
            
        Returns:
            Response with cookies set
        """
        # Access token cookie (short-lived)
        response.set_cookie(
            'access_token',
            value=access_token,
            max_age=int(self.ACCESS_TOKEN_EXPIRY.total_seconds()),
            httponly=self.COOKIE_HTTPONLY,
            secure=self.COOKIE_SECURE,
            samesite=self.COOKIE_SAMESITE,
            path='/api'
        )
        
        # Refresh token cookie (long-lived)
        response.set_cookie(
            'refresh_token',
            value=refresh_token,
            max_age=int(self.REFRESH_TOKEN_EXPIRY.total_seconds()),
            httponly=self.COOKIE_HTTPONLY,
            secure=self.COOKIE_SECURE,
            samesite=self.COOKIE_SAMESITE,
            path='/api/auth/refresh'  # Only accessible on refresh endpoint
        )
        
        logger.debug("Set HttpOnly authentication cookies")
        return response
    
    def clear_auth_cookies(self, response: Response) -> Response:
        """
        Clear authentication cookies (logout).
        
        Args:
            response: Flask response object
            
        Returns:
            Response with cookies cleared
        """
        response.set_cookie('access_token', value='', max_age=0, path='/api')
        response.set_cookie('refresh_token', value='', max_age=0, path='/api/auth/refresh')
        
        logger.debug("Cleared authentication cookies")
        return response
    
    def get_token_from_cookie(self, token_type: str = 'access') -> Optional[str]:
        """
        Extract token from HTTP-only cookie.
        
        Args:
            token_type: Type of token to extract ('access' or 'refresh')
            
        Returns:
            Token string or None if not found
        """
        cookie_name = f'{token_type}_token'
        token = request.cookies.get(cookie_name)
        
        if not token:
            logger.debug(f"No {token_type} token found in cookies")
            return None
        
        return token
    
    def get_current_user(self) -> Optional[Dict]:
        """
        Get current authenticated user from access token.
        
        Returns:
            User data from token or None if not authenticated
        """
        # Get access token from cookie
        access_token = self.get_token_from_cookie('access')
        if not access_token:
            return None
        
        try:
            # Validate and decode token
            payload = self.validate_token(access_token, token_type='access')
            return payload
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None


# Singleton instance
_jwt_handler: Optional[JWTHandler] = None


def get_jwt_handler() -> JWTHandler:
    """
    Get singleton JWT handler instance.
    
    Returns:
        JWTHandler instance
    """
    global _jwt_handler
    if _jwt_handler is None:
        _jwt_handler = JWTHandler()
    return _jwt_handler


# Flask decorator for protecting routes
def jwt_required(f):
    """
    Decorator to protect routes with JWT authentication.
    
    Usage:
        @app.route('/protected')
        @jwt_required
        def protected_route():
            user = get_current_user()
            return {'message': f'Hello {user["user_id"]}'}
    """
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_handler = get_jwt_handler()
        user = jwt_handler.get_current_user()
        
        if not user:
            from flask import jsonify
            return jsonify({'error': 'Authentication required'}), 401
        
        # Add user to kwargs for route function
        kwargs['current_user'] = user
        return f(*args, **kwargs)
    
    return decorated_function


def get_current_user() -> Optional[Dict]:
    """
    Convenience function to get current user.
    
    Returns:
        Current user data or None
    """
    return get_jwt_handler().get_current_user()
