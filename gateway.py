from flask import Flask, request, jsonify, Response
import requests
import os
import jwt
from functools import wraps
from dotenv import load_dotenv
import logging

# Enhanced logging
logging.basicConfig(level=logging.DEBUG, 
                    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Service URLs
AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL', 'http://localhost:8081')
HELLO_WORLD_SERVICE_1_URL = os.getenv('HELLO_WORLD_SERVICE_1_URL', 'http://localhost:8080')
HELLO_WORLD_SERVICE_2_URL = os.getenv('HELLO_WORLD_SERVICE_2_URL', 'http://localhost:8082')

# JWT Secret (should match the one used in your Java services)
JWT_SECRET = os.getenv('JWT_SECRET', 'yourSecretKeyHereMustBeAdsdsdsdtLeast32CharsLongForSecurity111111dsdsdsdsdsdsdsdsdsds111')

# Print the JWT_SECRET for debugging (but mask most of it)
if len(JWT_SECRET) > 10:
    app.logger.info(f"Loaded JWT_SECRET: {JWT_SECRET[:5]}...{JWT_SECRET[-5:]}, Length: {len(JWT_SECRET)}")

# Service routes configuration
ROUTES = {
    # Auth service routes
    '/auth/register': {'target': f'{AUTH_SERVICE_URL}/auth/register', 'methods': ['POST']},
    '/auth/register/admin': {'target': f'{AUTH_SERVICE_URL}/auth/register/admin', 'methods': ['POST']},
    '/auth/login': {'target': f'{AUTH_SERVICE_URL}/auth/login', 'methods': ['POST']},
    '/auth/users': {'target': f'{AUTH_SERVICE_URL}/auth/users', 'methods': ['GET']},
    
    # Hello World Service 1 routes
    '/api/hello-1': {'target': f'{HELLO_WORLD_SERVICE_1_URL}/api/hello', 'methods': ['GET'], 'authenticated': True},
    '/api/admin-1': {'target': f'{HELLO_WORLD_SERVICE_1_URL}/api/admin', 'methods': ['GET'], 'authenticated': True, 'roles': ['ROLE_ADMIN']},
    '/api/user-1': {'target': f'{HELLO_WORLD_SERVICE_1_URL}/api/user', 'methods': ['GET'], 'authenticated': True, 'roles': ['ROLE_USER']},
    
    # Hello World Service 2 routes
    '/api/hello-2': {'target': f'{HELLO_WORLD_SERVICE_2_URL}/api/hello', 'methods': ['GET'], 'authenticated': True},
    '/api/category/create': {'target': f'{HELLO_WORLD_SERVICE_2_URL}/api/category/create', 'methods': ['POST'], 'authenticated': True, 'roles': ['ROLE_ADMIN']},
    '/api/category/edit': {'target': f'{HELLO_WORLD_SERVICE_2_URL}/api/category/edit', 'methods': ['PUT'], 'authenticated': True, 'roles': ['ROLE_ADMIN']},
    '/api/category/list': {'target': f'{HELLO_WORLD_SERVICE_2_URL}/api/category/list', 'methods': ['GET'], 'authenticated': True, 'roles': ['ROLE_USER', 'ROLE_ADMIN']},
    '/api/document/list': {'target': f'{HELLO_WORLD_SERVICE_2_URL}/api/document/list', 'methods': ['GET'], 'authenticated': True, 'roles': ['ROLE_USER', 'ROLE_ADMIN']},
    '/api/document/create': {'target': f'{HELLO_WORLD_SERVICE_2_URL}/api/document/create', 'methods': ['POST'], 'authenticated': True, 'roles': ['ROLE_ADMIN']},
}

def verify_token(token):
    """Verify JWT token and extract claims"""
    try:
        # First strip 'Bearer ' prefix if it exists
        clean_token = token
        if clean_token.startswith('Bearer '):
            clean_token = clean_token.replace('Bearer ', '')
        
        app.logger.debug(f"Token to decode: {clean_token[:20]}...")
        
        # Try to decode with HS512 algorithm
        payload = jwt.decode(clean_token, JWT_SECRET, algorithms=['HS512'])
        app.logger.debug(f"Token decoded successfully with HS512: {payload}")
        return payload
    except jwt.ExpiredSignatureError as e:
        app.logger.error(f"Token expired: {str(e)}")
        return None
    except jwt.InvalidTokenError as e:
        app.logger.error(f"Invalid token: {str(e)}")
        # Print more details for debugging
        app.logger.error(f"Token that failed: {clean_token[:20]}...")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error decoding token: {str(e)}")
        return None

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    """Main proxy function to route requests to the appropriate service"""
    full_path = f'/{path}'
    
    app.logger.debug(f"Received request for path: {full_path}")
    app.logger.debug(f"Request method: {request.method}")
    app.logger.debug(f"Request headers: {request.headers}")
    
    # Find matching route
    route_config = None
    for route, config in ROUTES.items():
        if full_path == route and request.method in config['methods']:
            route_config = config
            break
            
    if not route_config:
        app.logger.debug(f"Route not found for path: {full_path}")
        return jsonify({'error': 'Route not found'}), 404
    
    app.logger.debug(f"Found route config: {route_config}")
    
    # Create new headers dictionary to avoid any issues
    headers = {}
    for key, value in request.headers:
        if key.lower() != 'host':  # Skip the host header
            headers[key] = value
    
        # Check authentication if required
    if route_config.get('authenticated', False):
        auth_header = request.headers.get('Authorization')
        app.logger.debug(f"Auth header: {auth_header}")
        
        if not auth_header:
            return jsonify({'error': 'Missing Authorization header'}), 401
        
        # Extract token for verification
        token_for_verification = auth_header
        
        app.logger.debug(f"Token for verification: {token_for_verification[:30]}...")
        
        # IMPORTANT: For troubleshooting only - disable token verification temporarily
        # Comment this out once you've confirmed the token forwarding works
        # payload = {"sub": "bypass_verification", "roles": ["ROLE_USER", "ROLE_ADMIN"]}
        # app.logger.warning("⚠️ TOKEN VERIFICATION BYPASSED FOR DEBUGGING - REMOVE IN PRODUCTION ⚠️")
        
        # Verify the token using your secret
        payload = verify_token(token_for_verification)
        app.logger.debug(f"Token verification result: {payload is not None}")
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        app.logger.debug(f"Token payload: {payload}")
        
        # Check roles if required
        if 'roles' in route_config:
            user_roles = payload.get('roles', [])
            app.logger.debug(f"User roles: {user_roles}")
            required_roles = route_config['roles']
            app.logger.debug(f"Required roles: {required_roles}")
            
            has_required_role = any(role in user_roles for role in required_roles)
            app.logger.debug(f"Has required role: {has_required_role}")
            
            if not has_required_role:
                app.logger.debug(f"User does not have required roles")
                return jsonify({'error': 'Insufficient privileges'}), 403
    
        # CRITICAL FIX: Ensure the outgoing Authorization header matches exactly what Spring Security expects
        # Your Spring service uses JwtAuthenticationFilter which expects "Bearer " followed by the token
        # It uses authHeader.replace(jwtProperties.getTokenPrefix(), "") to extract the token
        
        # First, clean out any existing "Bearer " prefix
        clean_token = auth_header
        if clean_token.startswith('Bearer '):
            clean_token = clean_token.replace('Bearer ', '')
        
        # Now add the required "Bearer " prefix (with space) exactly as expected by Spring
        headers['Authorization'] = f'Bearer {clean_token}'
            
        app.logger.debug(f"Final Authorization header: {headers['Authorization'][:30]}...")
    
    # Forward request to the target service
    target_url = route_config['target']
    app.logger.debug(f"Forwarding request to: {target_url}")
    app.logger.debug(f"Forwarding with headers: {headers}")
    
    # Forward the request to the target service
    try:
        # Log request details for debugging
        app.logger.debug(f"Sending {request.method} request to {target_url}")
        
        # Make the actual request to the target service
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            stream=True
        )
        
        # Debug response details
        app.logger.debug(f"Response status from target service: {resp.status_code}")
        app.logger.debug(f"Response headers from target service: {resp.headers}")
        
        # For debugging, log the first part of the response content if it's an error
        if resp.status_code >= 400:
            try:
                app.logger.debug(f"Error response body: {resp.content.decode('utf-8', errors='ignore')[:500]}")
            except:
                app.logger.debug("Could not decode response body")
        
        # Prepare the response to send back to the client
        response = Response(
            resp.content,
            resp.status_code,
            {k: v for k, v in resp.headers.items() if k.lower() not in ('transfer-encoding', 'content-encoding', 'content-length')}
        )
        return response
        
    except requests.RequestException as e:
        app.logger.error(f"Request exception: {str(e)}")
        return jsonify({'error': f'Error forwarding request: {str(e)}'}), 500

@app.route('/', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'up',
        'services': {
            'auth': f"{AUTH_SERVICE_URL}",
            'hello-world-1': f"{HELLO_WORLD_SERVICE_1_URL}",
            'hello-world-2': f"{HELLO_WORLD_SERVICE_2_URL}"
        }
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.logger.info(f"Starting API Gateway on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)