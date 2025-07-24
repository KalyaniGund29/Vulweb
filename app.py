from flask import Flask, request, render_template, redirect, make_response, session
from datetime import datetime, timedelta
import secrets
import os
import json
import logging
import socket
import geoip2.database
from urllib.parse import urlparse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests  # For IP geolocation fallback
from user_agents import parse
<<<<<<< HEAD


=======
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask import Flask, request, render_template, redirect, make_response, session, jsonify



>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
# === Setup Flask ===
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
csrf = CSRFProtect(app)
# === Rate Limiter ===
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "10 per minute"]
)
limiter.init_app(app)

<<<<<<< HEAD
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",  # Use in-memory storage instead of Redis
    default_limits=["200 per day", "10 per minute"]
)

# === Geolocation Setup ===
GEOIP_DB_PATH = 'GeoLite2-City.mmdb'  # You need to download this from MaxMind
geoip_reader = None
if os.path.exists(GEOIP_DB_PATH):
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# === Logging ===
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'audit.log')
ACTIVITY_LOG = os.path.join(LOG_DIR, 'activity.log')
TRACEBACK_LOG = os.path.join(LOG_DIR, 'traceback.log')
os.makedirs(LOG_DIR, exist_ok=True)

=======
# === Geolocation Setup ===
GEOIP_DB_PATH = 'GeoLite2-City.mmdb'  # You need to download this from MaxMind
geoip_reader = None
if os.path.exists(GEOIP_DB_PATH):
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# === Logging ===
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'audit.log')
ACTIVITY_LOG = os.path.join(LOG_DIR, 'activity.log')
TRACEBACK_LOG = os.path.join(LOG_DIR, 'traceback.log')
os.makedirs(LOG_DIR, exist_ok=True)

>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
# Configure main audit log
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# Configure separate activity logger
activity_logger = logging.getLogger('activity')
activity_handler = logging.FileHandler(ACTIVITY_LOG)
activity_handler.setFormatter(logging.Formatter('%(asctime)s|%(message)s'))
activity_logger.addHandler(activity_handler)
activity_logger.setLevel(logging.INFO)

# Configure traceback logger
traceback_logger = logging.getLogger('traceback')
traceback_handler = logging.FileHandler(TRACEBACK_LOG)
traceback_handler.setFormatter(logging.Formatter('%(asctime)s|%(message)s'))
traceback_logger.addHandler(traceback_handler)
traceback_logger.setLevel(logging.INFO)

# In-memory storage (replaces database)
users = {
    'admin': {
<<<<<<< HEAD
        'password': 'youfoundthepassword',
        'last_login': None,
        'login_count': 0,
        'login_history': [],
        'role': 'admin'  # Added role field
    },
    'user1': {
        'password': 'user1pass',
        'last_login': None,
        'login_count': 0,
        'login_history': [],
        'role': 'user'  # Added role field
    },
    'superuser': {
        'password': 'secretbackdoor123',
        'last_login': None,
        'login_count': 0,
        'login_history': [],
        'hidden': True,
        'role': 'superuser'  # Added role field
=======
        'password': generate_password_hash('password123'),
        'last_login': None,
        'login_count': 0,
        'login_history': []
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
    }
}

sessions = {}
user_activities = []

def get_geolocation(ip_address):
<<<<<<< HEAD
    if ip_address in ('127.0.0.1', '::1'):
        return {
            'city': 'Localhost', 
            'country': 'Local', 
            'source': 'Loopback',
            'isp': 'Local Network',
            'ip': ip_address
        }

    result = {
        'ip': ip_address,
        'city': None,
        'country': None,
        'latitude': None,
        'longitude': None,
        'timezone': None,
        'isp': None,
        'org': None,
        'asn': None,
        'source': None
    }

    # Try MaxMind database first
    if geoip_reader:
        try:
            response = geoip_reader.city(ip_address)
            result.update({
=======
    """Get geolocation data for an IP address"""
    if ip_address == '127.0.0.1':
        return {'city': 'Localhost', 'country': 'Local'}
    
    # Try MaxMind local database first
    if geoip_reader and ip_address:
        try:
            response = geoip_reader.city(ip_address)
            return {
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
                'city': response.city.name,
                'country': response.country.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
<<<<<<< HEAD
                'asn': getattr(response.traits, 'autonomous_system_number', None),
                'isp': getattr(response.traits, 'autonomous_system_organization', None),
                'org': getattr(response.traits, 'organization', None),
                'source': 'MaxMind'
            })
            return result
        except Exception as e:
            print(f"MaxMind error: {e}")

    # Fallback to ip-api.com (free tier)
    try:
        res = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query').json()
        if res.get('status') == 'success':
            result.update({
                'city': res.get('city'),
                'country': res.get('country'),
                'latitude': res.get('lat'),
                'longitude': res.get('lon'),
                'timezone': res.get('timezone'),
                'asn': res.get('as'),
                'isp': res.get('isp'),
                'org': res.get('org'),
                'source': 'ip-api.com'
            })
            return result
    except Exception as e:
        print(f"ip-api.com error: {e}")

    # Final fallback to ipinfo.io (requires token for full details)
    try:
        res = requests.get(f'https://ipinfo.io/{ip_address}/json').json()
        loc = res.get('loc', ',').split(',')
        result.update({
            'city': res.get('city'),
            'country': res.get('country'),
            'latitude': loc[0] if len(loc) > 0 else None,
            'longitude': loc[1] if len(loc) > 1 else None,
            'org': res.get('org'),
            'isp': res.get('org'),  # ipinfo.io uses 'org' for ISP
            'source': 'ipinfo.io'
        })
        return result
    except Exception as e:
        print(f"ipinfo.io error: {e}")

    return {
        'ip': ip_address,
        'error': 'Unable to determine geolocation', 
        'source': 'None'
    }


def is_suspicious_ip(geo_data):
    suspicious_keywords = ['Tor', 'VPN', 'Proxy', 'Hosting', 'Amazon', 'DigitalOcean', 'OVH']
    org = geo_data.get('org', '') or ''
    return any(keyword.lower() in org.lower() for keyword in suspicious_keywords)
    if is_suspicious_ip(client_info['geolocation']):
        logging.warning(f"⚠️ Suspicious login from hosting/Tor/VPN: user={username}, org={client_info['geolocation'].get('org')}")


=======
                'source': 'MaxMind'
            }
        except Exception as e:
            pass
    
    # Fallback to IP-API.com (free service)
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query').json()
        if response.get('status') == 'success':
            return {
                'city': response.get('city'),
                'country': response.get('country'),
                'latitude': response.get('lat'),
                'longitude': response.get('lon'),
                'timezone': response.get('timezone'),
                'isp': response.get('isp'),
                'source': 'IP-API'
            }
    except Exception as e:
        pass
    
    return {'error': 'Could not determine location'}
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba

from user_agents import parse

def get_client_info():
    """Get comprehensive client information"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()

    # Parse user agent with user-agents package
    ua_string = request.headers.get('User-Agent', '')
    user_agent = parse(ua_string)
    
    # Get geolocation data
    geo_data = get_geolocation(ip)
    
    # Get hostname if possible
    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        pass
    
    # Get referrer information
    referrer = request.referrer
    referrer_domain = urlparse(referrer).netloc if referrer else None
    
    return {
        'ip': ip,
        'hostname': hostname,
        'user_agent': ua_string,
        'headers': dict(request.headers),
        'timestamp': datetime.now().isoformat(),
        'geolocation': geo_data,
        'referrer': referrer,
        'referrer_domain': referrer_domain,
        'method': request.method,
        'path': request.path,
        'query_params': dict(request.args),
        'cookies': dict(request.cookies),
        'platform': user_agent.os.family,
        'browser': user_agent.browser.family,
        'version': user_agent.browser.version_string,
        'language': request.headers.get('Accept-Language'),
        'is_mobile': user_agent.is_mobile,
        'is_tablet': user_agent.is_tablet,
        'is_pc': user_agent.is_pc,
        'is_bot': user_agent.is_bot,
        'device': user_agent.device.family
    }

def log_activity(username, activity_type, details=None):
    """Log user activity with comprehensive tracking"""
    client_info = get_client_info()
    activity_data = {
        'username': username,
        'activity_type': activity_type,
        'details': details,
        'client_info': client_info,
        'timestamp': datetime.now().isoformat()
    }
    
    # Store activity in memory
    user_activities.append(activity_data)
    
<<<<<<< HEAD
    # Enhanced log message with ISP info
    geo = client_info.get('geolocation', {})
    log_message = f"{username}|{activity_type}|{client_info['ip']}|{geo.get('city', 'Unknown')}|{geo.get('country', 'Unknown')}|ISP:{geo.get('isp', 'Unknown')}|ASN:{geo.get('asn', 'Unknown')}|{details or ''}"
    activity_logger.info(log_message)
    
    # Enhanced traceback log
=======
    # Log to activity log file
    log_message = f"{username}|{activity_type}|{client_info['ip']}|{client_info.get('geolocation', {}).get('city', 'Unknown')}|{client_info.get('geolocation', {}).get('country', 'Unknown')}|{details or ''}"
    activity_logger.info(log_message)
    
    # Log to traceback log with more details
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
    traceback_data = {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'activity': activity_type,
        'ip': client_info['ip'],
        'geolocation': client_info.get('geolocation', {}),
<<<<<<< HEAD
        'network_info': {
            'isp': geo.get('isp'),
            'asn': geo.get('asn'),
            'org': geo.get('org')
        },
=======
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
        'user_agent': client_info['user_agent'],
        'device_info': {
            'platform': client_info['platform'],
            'browser': client_info['browser'],
            'version': client_info['version'],
            'is_mobile': client_info['is_mobile'],
            'is_tablet': client_info['is_tablet'],
            'is_pc': client_info['is_pc'],
            'is_bot': client_info['is_bot']
        },
        'details': details
    }
    traceback_logger.info(json.dumps(traceback_data))
<<<<<<< HEAD
    
    
    if activity_type in ['sql_query', 'token_access', 'credential_access']:
            logging.critical(f"🚨 SECURITY ALERT - {activity_type.upper()}: user={username}, IP={client_info['ip']}, Details: {details}")
            # Also send to admin monitor
            admin_alert = {
                'type': 'security_alert',
                'username': username,
                'ip': client_info['ip'],
                'activity': activity_type,
                'details': details,
                'timestamp': datetime.now().isoformat()
            }
            traceback_logger.critical(json.dumps(admin_alert))
=======
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba

def read_audit_logs(limit=100):
    """Read and parse audit logs from the log file"""
    logs = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    timestamp_end = line.find(']') + 1
                    timestamp_str = line[:timestamp_end].strip()
                    level_start = line.find('[', timestamp_end) + 1
                    level_end = line.find(']', level_start)
                    level = line[level_start:level_end]
                    message = line[level_end+2:].strip()
                    
                    logs.append({
                        'timestamp': timestamp_str,
                        'level': level,
                        'message': message
                    })
                except Exception as e:
                    print(f"Error parsing log line: {e}")
    except FileNotFoundError:
        pass
    return logs[-limit:][::-1]

def read_activity_logs(limit=50):
    """Read and parse activity logs from the activity log file"""
    activities = []
    try:
        with open(ACTIVITY_LOG, 'r') as f:
            for line in f:
                try:
                    parts = line.strip().split('|', 5)
                    if len(parts) >= 6:
                        activities.append({
                            'timestamp': parts[0],
                            'username': parts[1],
                            'activity_type': parts[2],
                            'ip': parts[3],
                            'location': f"{parts[4]}, {parts[5]}",
                            'details': parts[6] if len(parts) > 6 else None
                        })
                except Exception as e:
                    print(f"Error parsing activity log line: {e}")
    except FileNotFoundError:
        pass
    return activities[-limit:][::-1]

def read_traceback_logs(limit=50):
    """Read and parse traceback logs"""
    tracebacks = []
    try:
        with open(TRACEBACK_LOG, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    tracebacks.append(data)
                except json.JSONDecodeError as e:
                    print(f"Error parsing traceback log line: {e}")
    except FileNotFoundError:
        pass
    return tracebacks[-limit:][::-1]

<<<<<<< HEAD
# === LOGIN ===
# === LOGIN ROUTES ===
# === LOGIN ROUTES ===
=======

@app.before_request
def validate_session():
    if request.endpoint not in ['login', 'static']:
        session_token = request.cookies.get('session')
        if not session_token or session_token not in sessions:
            return redirect('/')
        if datetime.now() > sessions[session_token]['expires_at']:
            del sessions[session_token]
            resp = make_response(redirect('/'))
            resp.delete_cookie('session')
            return resp
        
app.jinja_env.filters['tojson'] = json.dumps
# === LOGIN ===
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        client_info = get_client_info()

<<<<<<< HEAD
        if username in users and not users[username].get('hidden', False):
            if users[username]['password'] == password:
                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)
                
                users[username]['last_login'] = datetime.now().isoformat()
                users[username]['login_count'] += 1
                users[username]['login_history'].append({
                    'timestamp': datetime.now().isoformat(),
                    'ip': client_info['ip'],
                    'location': client_info.get('geolocation', {}),
                    'user_agent': client_info['user_agent'],
                    'device': {
                        'platform': client_info['platform'],
                        'browser': client_info['browser'],
                        'version': client_info['version']
                    }
                })
                
                sessions[session_token] = {
                    'username': username,
                    'client_info': client_info,
                    'created_at': datetime.now(),
                    'expires_at': expires_at,
                    'last_activity': datetime.now(),
                    'activities': [],
                    'role': users[username]['role']  # Store role in session
                }

                logging.info(f"✅ Login success: user={username}, IP={client_info['ip']}")
                log_activity(username, 'login_success', {
                    'ip': client_info['ip'],
                    'location': client_info.get('geolocation', {}),
                    'device': client_info['user_agent']
                })
                
                # Determine redirect based on role
                if users[username]['role'] == 'admin':
                    redirect_url = '/admin'
                elif users[username]['role'] == 'superuser':
                    redirect_url = '/super'
                else:  # regular user
                    redirect_url = '/user'
                
                resp = make_response(redirect(redirect_url))
                resp.set_cookie('session', session_token, httponly=True, secure=False, samesite='Strict')
                return resp

        logging.warning(f"❌ Failed login: user={username}, IP={client_info['ip']}")
=======
        if username in users and check_password_hash(users[username]['password'], password):
            # Create session
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=1)
            
            # Update user info
            users[username]['last_login'] = datetime.now().isoformat()
            users[username]['login_count'] += 1
            users[username]['login_history'].append({
                'timestamp': datetime.now().isoformat(),
                'ip': client_info['ip'],
                'location': client_info.get('geolocation', {}),
                'user_agent': client_info['user_agent'],
                'device': {
                    'platform': client_info['platform'],
                    'browser': client_info['browser'],
                    'version': client_info['version']
                }
            })
            
            # Store session
            sessions[session_token] = {
                'username': username,
                'client_info': client_info,
                'created_at': datetime.now(),
                'expires_at': expires_at,
                'last_activity': datetime.now(),
                'activities': []
            }

            logging.info(f"✅ Login success: user={username}, IP={client_info['ip']}, Location={client_info.get('geolocation', {}).get('city', 'Unknown')}, {client_info.get('geolocation', {}).get('country', 'Unknown')}")
            log_activity(username, 'login_success', {
                'ip': client_info['ip'],
                'location': client_info.get('geolocation', {}),
                'device': client_info['user_agent']
            })
            
            resp = make_response(redirect('/admin'))
            resp.set_cookie('session', session_token, httponly=True, secure=False, samesite='Strict')
            return resp

        logging.warning(f"❌ Failed login: user={username}, IP={client_info['ip']}, Location={client_info.get('geolocation', {}).get('city', 'Unknown')}, {client_info.get('geolocation', {}).get('country', 'Unknown')}")
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
        log_activity(username, 'login_failed', {
            'ip': client_info['ip'],
            'location': client_info.get('geolocation', {}),
            'device': client_info['user_agent']
        })
        return render_template('login.html', error="Invalid credentials")

    # Clear session if accessing login page directly
    session_token = request.cookies.get('session')
    if session_token and session_token in sessions:
        resp = make_response(render_template('login.html'))
        resp.delete_cookie('session')
        del sessions[session_token]
        return resp
    
    return render_template('login.html')

<<<<<<< HEAD

@app.route('/user')
def user_dashboard():
    session_token = request.cookies.get('session')
    if not session_token or session_token not in sessions:
        return redirect('/')

    session_data = sessions[session_token]
    username = session_data['username']
    
    # Only allow regular users to access this page
    if session_data.get('role') != 'user':
        return redirect('/logout')
    
    # Update last activity
    sessions[session_token]['last_activity'] = datetime.now()
    
    # Log this activity
    log_activity(username, 'user_access', {'path': request.path})
    
    return render_template('user.html', current_user=username)

@app.route('/super', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def super_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        print(f"Login attempt - Username: {username}, Password: {password}")  # Debug line
        
        client_info = get_client_info()
        print(f"Client info: {client_info}")  # Debug line

        # Rest of your existing code...

        # Check for hidden admin credentials
        if username in users and users[username].get('hidden', False):
            if users[username]['password'] == password:
                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)
                
                users[username]['last_login'] = datetime.now().isoformat()
                users[username]['login_count'] += 1
                users[username]['login_history'].append({
                    'timestamp': datetime.now().isoformat(),
                    'ip': client_info['ip'],
                    'location': client_info.get('geolocation', {}),
                    'user_agent': client_info['user_agent'],
                    'device': {
                        'platform': client_info['platform'],
                        'browser': client_info['browser'],
                        'version': client_info['version']
                    }
                })
                
                sessions[session_token] = {
                    'username': username,
                    'client_info': client_info,
                    'created_at': datetime.now(),
                    'expires_at': expires_at,
                    'last_activity': datetime.now(),
                    'activities': [],
                    'is_superuser': True
                }

                logging.info(f"🔑 SUPERUSER login: user={username}, IP={client_info['ip']}")
                log_activity(username, 'superuser_login', {
                    'ip': client_info['ip'],
                    'location': client_info.get('geolocation', {}),
                    'device': client_info['user_agent']
                })
                
                resp = make_response(redirect('/superadmin'))
                resp.set_cookie('session', session_token, httponly=True, secure=False, samesite='Strict')
                return resp

        logging.warning(f"❌ Failed SUPERUSER login attempt: user={username}, IP={client_info['ip']}")
        log_activity('unknown', 'superuser_login_failed', {
            'ip': client_info['ip'],
            'location': client_info.get('geolocation', {}),
            'device': client_info['user_agent']
        })
        return render_template('super_login.html', error="Invalid credentials")

    return render_template('super_login.html')


@app.route('/superadmin')
def superadmin_dashboard():
    session_token = request.cookies.get('session')
    if not session_token or session_token not in sessions:
        return redirect('/super')

    if not sessions[session_token].get('is_superuser', False):
        return redirect('/logout')

    # Log this access to admin logs
    client_info = get_client_info()
    logging.warning(f"⚠️ SUPERUSER ACCESS: user={sessions[session_token]['username']}, IP={client_info['ip']}, Geo={client_info.get('geolocation', {})}")
    
    # Create vulnerable elements in session
    sessions[session_token].update({
        'csrf_token': secrets.token_hex(32),
        'super_token': secrets.token_urlsafe(64),
        'vulnerable': True
    })

    return render_template('superadmin.html', 
                         current_user=sessions[session_token]['username'],
                         session=sessions[session_token])

@app.route('/admin/query', methods=['POST'])
def admin_query():
    if 'query' in request.form:
        # This is intentionally vulnerable to SQL injection
        query = request.form['query']
        logging.critical(f"🚨 POSSIBLE SQL INJECTION ATTEMPT: {query}")
        return "Query executed", 200
    return "Invalid query", 400

# Route to monitor superadmin activity
@app.route('/admin/monitor')
def admin_monitor():
    # Only admins can see superuser activity
    session_token = request.cookies.get('session')
    if not session_token or sessions[session_token].get('role') != 'admin':
        return redirect('/logout')

    # Get all superuser activities from logs
    suspicious_activities = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                if 'SUPERUSER ACCESS' in line or 'POSSIBLE SQL INJECTION' in line:
                    suspicious_activities.append(line.strip())
    except FileNotFoundError:
        pass

    return render_template('admin_monitor.html',
                         activities=suspicious_activities,
                         current_user=sessions[session_token]['username'])

=======
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
# === ADMIN DASHBOARD ===
@app.route('/admin')
def admin():
    session_token = request.cookies.get('session')
    if not session_token or session_token not in sessions:
        return redirect('/')
<<<<<<< HEAD
    
    if sessions[session_token].get('role') != 'admin':
        return redirect('/logout')

    session_data = sessions[session_token]
    username = session_data['username']
    
    # Update last activity
    sessions[session_token]['last_activity'] = datetime.now()
    
    # Log this activity
    log_activity(username, 'admin_access', {'path': request.path})
    
    # Prepare active sessions
    active_sessions = []
    now = datetime.now()
    for token, session_info in sessions.items():
        if session_info['expires_at'] > now:
            inactive_min = (now - session_info['last_activity']).total_seconds() / 60
            active_sessions.append({
                'username': session_info['username'],
                'token': token,
                'ip': session_info['client_info']['ip'],
                'location': session_info['client_info'].get('geolocation', {}),
                'user_agent': session_info['client_info']['user_agent'],
                'created_at': session_info['created_at'],
                'expires_at': session_info['expires_at'],
                'last_activity': session_info['last_activity'],
                'inactive_minutes': inactive_min,
                'device': {
                    'platform': session_info['client_info']['platform'],
                    'browser': session_info['client_info']['browser'],
                    'version': session_info['client_info']['version']
                }
            })

    # Get user's login history
    login_history = users[username].get('login_history', [])[-10:][::-1]  # Last 10 logins
    
    # Get logs and activities
    audit_logs = read_audit_logs(100)
    recent_activities = user_activities[-50:][::-1]  # Last 50 activities, newest first
    file_activities = read_activity_logs(50)
    traceback_logs = read_traceback_logs(50)

    return render_template('admin.html', 
                         sessions=active_sessions,
                         users=[{
                             'username': u, 
                             'last_login': users[u]['last_login'], 
                             'login_count': users[u]['login_count'],
                             'login_history': users[u].get('login_history', [])[-3:][::-1]
                         } for u in users],
                         current_client=get_client_info(),
                         audit_logs=audit_logs,
                         recent_activities=recent_activities,
                         file_activities=file_activities,
                         traceback_logs=traceback_logs,
                         login_history=login_history,
                         current_user=username)
=======

    session_data = sessions[session_token]
    username = session_data['username']
    
    # Update last activity
    sessions[session_token]['last_activity'] = datetime.now()
    
    # Log this activity
    log_activity(username, 'admin_access', {'path': request.path})
    
    # Prepare active sessions
    active_sessions = []
    now = datetime.now()
    for token, session_info in sessions.items():
        if session_info['expires_at'] > now:
            inactive_min = (now - session_info['last_activity']).total_seconds() / 60
            active_sessions.append({
                'username': session_info['username'],
                'token': token,
                'ip': session_info['client_info']['ip'],
                'location': session_info['client_info'].get('geolocation', {}),
                'user_agent': session_info['client_info']['user_agent'],
                'created_at': session_info['created_at'],
                'expires_at': session_info['expires_at'],
                'last_activity': session_info['last_activity'],
                'inactive_minutes': inactive_min,
                'device': {
                    'platform': session_info['client_info']['platform'],
                    'browser': session_info['client_info']['browser'],
                    'version': session_info['client_info']['version']
                }
            })

    # Get user's login history
    login_history = users[username].get('login_history', [])[-10:][::-1]  # Last 10 logins
    
    # Get logs and activities
    audit_logs = read_audit_logs(100)
    recent_activities = user_activities[-50:][::-1]  # Last 50 activities, newest first
    file_activities = read_activity_logs(50)
    traceback_logs = read_traceback_logs(50)

    return render_template('admin.html', 
                         sessions=active_sessions,
                         users=[{
                             'username': u, 
                             'last_login': users[u]['last_login'], 
                             'login_count': users[u]['login_count'],
                             'login_history': users[u].get('login_history', [])[-3:][::-1]
                         } for u in users],
                         current_client=get_client_info(),
                         audit_logs=audit_logs,
                         recent_activities=recent_activities,
                         file_activities=file_activities,
                         traceback_logs=traceback_logs,
                         login_history=login_history,
                         current_user=username)



# === SESSION FORENSICS ===
@app.route('/admin/session_forensics/<session_token>')
def session_forensics(session_token):
    if not request.cookies.get('session') or request.cookies.get('session') not in sessions:
        return redirect('/')

    if session_token not in sessions:
        return "Session not found", 404

    session_data = sessions[session_token]
    username = session_data['username']
    
    # Get all activities for this session
    session_activities = [a for a in user_activities if a.get('client_info', {}).get('ip') == session_data['client_info']['ip']]
    
    # Get similar sessions from same IP
    similar_sessions = []
    for token, sess in sessions.items():
        if sess['client_info']['ip'] == session_data['client_info']['ip'] and token != session_token:
            similar_sessions.append({
                'token': token,
                'username': sess['username'],
                'created_at': sess['created_at'],
                'user_agent': sess['client_info']['user_agent']
            })
    
    # Get historical logins from same IP
    historical_logins = []
    for user in users.values():
        for login in user.get('login_history', []):
            if login.get('ip') == session_data['client_info']['ip']:
                historical_logins.append({
                    'username': username,
                    'timestamp': login.get('timestamp'),
                    'user_agent': login.get('user_agent')
                })
    
    log_activity(username, 'session_forensics_view', {'target_session': session_token})
    
    return render_template('session_forensics.html',
                         session=session_data,
                         activities=session_activities[-50:][::-1],  # Last 50 activities
                         similar_sessions=similar_sessions,
                         historical_logins=historical_logins,
                         current_user=username)

@app.route('/admin/terminate_session', methods=['POST'])
def terminate_session():
    session_token = request.cookies.get('session')
    if not session_token or session_token not in sessions:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401

    target_token = request.form.get('token')
    if not target_token or target_token not in sessions:
        return jsonify({'status': 'error', 'message': 'Invalid session token'}), 404

    # Log this activity
    username = sessions[session_token]['username']
    target_username = sessions[target_token]['username']
    client_info = sessions[target_token]['client_info']
    
    log_activity(username, 'session_terminated', {
        'target_user': target_username,
        'target_ip': client_info['ip'],
        'target_session': target_token
    })
    
    # Delete the session
    del sessions[target_token]
    
    return jsonify({'status': 'success', 'message': 'Session terminated'})



>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba

# === LOGOUT ===
@app.route('/logout')
def logout():
    session_token = request.cookies.get('session')
    if session_token and session_token in sessions:
        username = sessions[session_token]['username']
        client_info = sessions[session_token]['client_info']
<<<<<<< HEAD
        is_superuser = sessions[session_token].get('is_superuser', False)
        
        log_activity(username, 'logout', {
            'ip': client_info['ip'],
            'location': client_info.get('geolocation', {}),
            'session_duration': str(datetime.now() - sessions[session_token]['created_at']),
            'superuser': is_superuser
        })
        
        del sessions[session_token]
        logging.info(f"🔓 Session ended for user={username}, IP={client_info['ip']}")

    resp = make_response(redirect('/super' if is_superuser else '/'))
=======
        log_activity(username, 'logout', {
            'ip': client_info['ip'],
            'location': client_info.get('geolocation', {}),
            'session_duration': str(datetime.now() - sessions[session_token]['created_at'])
        })
        del sessions[session_token]
        logging.info(f"🔓 Session ended for user={username}, IP={client_info['ip']}")

    resp = make_response(redirect('/'))
>>>>>>> c96909f9cad4c82fc964230824e402dfcdeeccba
    resp.delete_cookie('session')
    return resp

# === START SERVER ===
if __name__ == '__main__':
    print(f"🔐 Audit log: {LOG_FILE}")
    print(f"🔍 Activity log: {ACTIVITY_LOG}")
    print(f"🌍 Traceback log: {TRACEBACK_LOG}")
    app.run(debug=True, host='0.0.0.0', port=5000)