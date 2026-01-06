"""
Authentication Routes

JWT-based authentication endpoints:
- /api/auth/login - User login with credentials (rate limited: 5/minute)
- /api/auth/logout - User logout (clear cookies)
- /api/auth/refresh - Refresh access token
- /api/auth/me - Get current user info

Security Features:
- HttpOnly cookies for token storage
- Token rotation on refresh
- CSRF protection with SameSite cookies
- Rate limiting: 5 login attempts per minute per IP

Author: Security Team
Date: 2025-10-30
"""

import logging
from typing import Dict
from functools import wraps
import threading

from flask import Blueprint, jsonify, make_response, request
from flask_restx import Api, Namespace, Resource, fields
import jwt

from utils.jwt_handler import get_jwt_handler, jwt_required, get_current_user

logger = logging.getLogger(__name__)

# Thread-safe rate limiter storage
_limiter = None
_limiter_lock = threading.Lock()

def set_limiter(limiter_instance):
    """Set the rate limiter instance from app factory (thread-safe)"""
    global _limiter
    with _limiter_lock:
        _limiter = limiter_instance
        logger.info("Rate limiter configured for auth routes")

def rate_limit(limit_string):
    """
    Decorator to apply rate limiting to Flask-RESTX Resource methods (thread-safe).
    
    Args:
        limit_string: Rate limit string (e.g., "5 per minute")
    
    Thread Safety: Uses lock to safely access _limiter instance
    """
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            with _limiter_lock:
                limiter = _limiter
            
            if limiter is not None:
                # Apply rate limit using the limiter instance
                limited_func = limiter.limit(limit_string)(func)
                return limited_func(*args, **kwargs)
            else:
                # If limiter not available, log warning and proceed
                logger.warning(
                    "Rate limiter not configured - %s proceeding without rate limiting",
                    func.__name__
                )
                return func(*args, **kwargs)
        return wrapped
    return decorator

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Create API namespace
auth_ns = Namespace('auth', description='Authentication operations')

# Request/response models
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password')
})

login_response = auth_ns.model('LoginResponse', {
    'message': fields.String(description='Success message'),
    'user': fields.Raw(description='User information')
})

user_info_response = auth_ns.model('UserInfo', {
    'user_id': fields.String(description='User ID'),
    'username': fields.String(description='Username'),
    'email': fields.String(description='Email address'),
    'role': fields.String(description='User role')
})

error_response = auth_ns.model('Error', {
    'error': fields.String(description='Error message')
})


@auth_ns.route('/login')
class Login(Resource):
    """User login endpoint with strict rate limiting"""
    
    @rate_limit("5 per minute")
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Success', login_response)
    @auth_ns.response(401, 'Invalid credentials', error_response)
    @auth_ns.response(429, 'Too many requests - rate limit exceeded')
    def post(self):
        """
        Authenticate user and return JWT tokens in HttpOnly cookies.
        
        Rate Limit: 5 requests per minute per IP address
        
        Security: This endpoint is protected against brute force attacks
        with strict rate limiting. After 5 attempts, wait 1 minute.
        
        Note: This is a placeholder implementation. In production:
        1. Validate credentials against database
        2. Hash passwords with bcrypt/argon2
        3. Log authentication attempts
        4. Implement account lockout after failed attempts
        """
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return {'error': 'Username and password required'}, 400
        
        username = data['username']
        password = data['password']
        
        # TODO: Replace with actual database authentication
        # For now, accept any non-empty credentials for testing
        # 
        # ⚠️  SECURITY WARNING (Issue Q2): Mock Authentication Active
        # This is INTENTIONAL for development/testing environment.
        # Production deployment MUST implement proper user database:
        #   1. Create User model with password hashing (bcrypt/argon2)
        #   2. Implement user registration endpoint
        #   3. Add role-based access control (RBAC)
        #   4. Enable database authentication below
        #   5. Remove mock user creation
        # 
        # Current behavior: Accepts ANY non-empty username/password
        # DO NOT DEPLOY TO PRODUCTION without proper authentication!
        if not username or not password:
            logger.warning(f"Failed login attempt: empty credentials")
            return {'error': 'Invalid credentials'}, 401
        
        # TODO: Verify password hash from database
        # user = User.query.filter_by(username=username).first()
        # if not user or not user.check_password(password):
        #     logger.warning(f"Failed login attempt for user: {username}")
        #     return {'error': 'Invalid credentials'}, 401
        
        # TEMPORARY: Create mock user for testing
        user_id = f"user_{username}"
        user_data = {
            'username': username,
            'email': f"{username}@example.com",
            'role': 'user',  # TODO: Get from database
            'permissions': ['scan:read', 'scan:write']  # TODO: Get from database
        }
        
        # Generate JWT tokens
        jwt_handler = get_jwt_handler()
        try:
            access_token, refresh_token = jwt_handler.generate_tokens(user_id, user_data)
            
            # Create response with tokens in HttpOnly cookies
            response_data = {
                'message': 'Login successful',
                'user': {
                    'user_id': user_id,
                    'username': user_data['username'],
                    'email': user_data['email'],
                    'role': user_data['role']
                }
            }
            response = make_response(jsonify(response_data), 200)
            
            # Set HttpOnly cookies
            jwt_handler.set_auth_cookies(response, access_token, refresh_token)
            
            logger.info(f"✅ User logged in: {username}")
            return response
            
        except Exception as e:
            logger.error(f"Login error for {username}: {str(e)}")
            return {'error': 'Internal server error'}, 500


@auth_ns.route('/logout')
class Logout(Resource):
    """User logout endpoint"""
    
    @auth_ns.response(200, 'Success')
    @jwt_required
    def post(self, current_user=None):
        """
        Logout user by clearing JWT cookies.
        
        TODO: Implement token blacklist for additional security
        """
        jwt_handler = get_jwt_handler()
        
        response = make_response(jsonify({
            'message': 'Logged out successfully'
        }), 200)
        
        # Clear authentication cookies
        jwt_handler.clear_auth_cookies(response)
        
        logger.info(f"✅ User logged out: {current_user.get('username', 'unknown')}")
        return response


@auth_ns.route('/refresh')
class Refresh(Resource):
    """Token refresh endpoint"""
    
    @auth_ns.response(200, 'Success', login_response)
    @auth_ns.response(401, 'Invalid or expired refresh token', error_response)
    def post(self):
        """
        Refresh access token using refresh token (with rotation).
        
        Security: Implements token rotation - both access and refresh tokens
        are replaced with new ones on each refresh.
        """
        jwt_handler = get_jwt_handler()
        
        # Get refresh token from cookie
        refresh_token = jwt_handler.get_token_from_cookie('refresh')
        
        if not refresh_token:
            logger.warning("Refresh attempt without refresh token")
            return {'error': 'No refresh token provided'}, 401
        
        try:
            # Validate and rotate tokens
            new_access, new_refresh = jwt_handler.refresh_access_token(refresh_token)
            
            # Create response
            response = make_response(jsonify({
                'message': 'Token refreshed successfully'
            }), 200)
            
            # Set new cookies (token rotation)
            jwt_handler.set_auth_cookies(response, new_access, new_refresh)
            
            logger.info("✅ Token refreshed (rotation enabled)")
            return response
            
        except jwt.ExpiredSignatureError:
            logger.warning("Refresh token expired")
            return {'error': 'Refresh token expired'}, 401
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid refresh token: {str(e)}")
            return {'error': 'Invalid refresh token'}, 401
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return {'error': 'Internal server error'}, 500


@auth_ns.route('/me')
class CurrentUser(Resource):
    """Get current user information"""
    
    @auth_ns.response(200, 'Success', user_info_response)
    @auth_ns.response(401, 'Not authenticated', error_response)
    @jwt_required
    def get(self, current_user=None):
        """
        Get current authenticated user information.
        
        Returns user data from JWT token payload.
        """
        return {
            'user_id': current_user.get('user_id'),
            'username': current_user.get('username'),
            'email': current_user.get('email'),
            'role': current_user.get('role'),
            'permissions': current_user.get('permissions', [])
        }, 200


# Health check for auth service
@auth_ns.route('/health')
class AuthHealth(Resource):
    """Authentication service health check"""
    
    def get(self):
        """Check if authentication service is operational"""
        jwt_handler = get_jwt_handler()
        
        return {
            'status': 'healthy',
            'service': 'authentication',
            'jwt_configured': jwt_handler.secret_key is not None
        }, 200
