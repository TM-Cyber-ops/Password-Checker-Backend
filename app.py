#Thomas.D.M built, UTSA Freshman summer 2026 

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
import zxcvbn
from flask import request
import hashlib
import requests 
import logging
from logging.handlers import RotatingFileHandler
import math
import sys
import os
import base64
import gc

app = Flask(__name__)
CORS(app)
#NOTE:Log File Rotation, total max 5MB
log_handler = RotatingFileHandler(   
   'security_audit.log',
   maxBytes=1024*1024,
   backupCount= 5
)
log_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.ERROR)
def announce_rotation():
   sys.stderr.write("\n [SYSTEM NOTICE] security_audit.log limit reached. Rolling log files.\n\n")
   sys.stderr.flush()
log_handler.doRollover = lambda old_rollover=log_handler.doRollover: (old_rollover(), announce_rotation())
#NOTE: Log file, *No passwords logged*
logging.basicConfig( 
   level=logging.INFO,
   format='%(asctime)s - %(levelname)s - %(message)s',
   handlers=[log_handler, console_handler]
)
debounce_timer = None
#NOTE:Banned Password - local txt list (kinda redudent but its ok)
try:
   with open('banned.txt', 'r') as f:
       banned_memory_set = set(
         hashlib.sha1(line.strip().lower().encode('utf-8')).hexdigest().upper()
         for line in f if line.strip()
       )
except FileNotFoundError:
   backup_list = ["12345678", "password", "admin", "123456", "1234", "qwerty"]
   banned_memory_set = set(
      hashlib.sha1(word.encode('utf-8')).hexdigest().upper()
      for word in backup_list
   )
   logging.error(f"ERROR: banned.txt file was not found! Server starting with basic backup list.")
   print("ERROR: banned.txt file was not found! Server starting with basic backup list")
   
#NOTE:API Connection Thingamabober - complicated work, dont touch
def check_pwned_api(user_password_bytes):
   prefix = hashlib.sha1(user_password_bytes).hexdigest().upper()[:5]
   suffix = hashlib.sha1(user_password_bytes).hexdigest().upper()[5:]
   url = f"https://api.pwnedpasswords.com/range/{prefix}"
   try:
      response = requests.get(url, timeout=5)
      if response.status_code != 200:
        return 0
   except requests.exceptions.RequestException:
      return 0
   for line in response.text.splitlines():
      api_suffix, count = line.split(':')
      if api_suffix == suffix:
         return int(count) #Not so fun Times Leaked  
   return 0

#NOTE:added to stop Dos, every decvice has its own limit, added REDIS for scalability
def get_true_client_ip():
   forwarded = request.headers.getlist("X-Forwarded-For")
   if forwarded:
      return forwarded[0]
   return request.remote_addr
REDIS_URL = os.environ.get("REDIS_URL", "memory://")
limiter = Limiter(
   app=app, 
   key_func=get_true_client_ip, 
   storage_uri=REDIS_URL
)
@app.route('/analyze', methods=['POST'])
@limiter.limit("100 per minute")

#NOTE:checks passwords, this is core code for program, see how passwords are treated below
def analyze_password():
    data = request.get_json()
    incoming_payload = data.get('password', '')
    try: 
       user_password_bytes = bytearray(base64.b64decode(incoming_payload.encode('utf-8')))
    except Exception:
       user_password_bytes = bytearray(incoming_payload.encode('utf-8'))
    del data 
    del incoming_payload
    password_length = len(user_password_bytes)
    if not user_password_bytes:
      return jsonify({"status": "empty", "message": "Enter a password above to begin analysis."})

    #NOTE:Level 0 rule set - Variables for allowed inputs
    has_upper = any(65 <= b <= 90 for b in user_password_bytes) #A-Z
    has_lower = any(97 <= b <= 122 for b in user_password_bytes) #a-z
    has_digit = any(48 <= b <= 57 for b in user_password_bytes) #0-9
    has_symbol = any((33<= b <= 47) or (58 <= b <= 64) or (91 <= b <= 96) or (123 <= b <= 126) for b in user_password_bytes)
    for b in user_password_bytes:
       if any(b < 32 or b > 126 for b in user_password_bytes):
          logging.warning(f"Check failed. Reason: Illegal Character usage.")
          bad_character = chr(b)
          return jsonify({
             "status": "rejected", "message": f"REJECTED: Character '{bad_character}' is not allowed! Use letters, numbers, or: SPACE ! \" # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ \ ] ^ _ ` {{ | }} ~ "
          }),
    
    ###NOTE: Hard Stop - Ban Checks here
    #FIX: Issue was here, now only matches at 100% for ban list, Had it trying to stop if more than 60% of the password was in the ban list but that failed.
    if hashlib.sha1(user_password_bytes.decode('utf-8').encode('utf-8')).hexdigest().upper() in banned_memory_set:
        local_ban_count = check_pwned_api(user_password_bytes)
        if local_ban_count > 0:
            logging.warning(f"Check failed. Reason: Local ban list match")
            return jsonify({ 
                "status": "pwned", "message": f"REJECTED: Common banned word or phrase match! Exposed {local_ban_count:,} times online!"
            })
        else:
            return jsonify({ 
                "status": "pwned", "message": "REJECTED: Common banned word or phrase match."
            })
    #NOTE: Stops Further Checks If Leaked
    leak_count = check_pwned_api(user_password_bytes)
    if leak_count > 0:
     logging.warning(f"Check failed. Reason: Leaked password database match. Count: {leak_count}")
     return jsonify({
        "status": "pwned", "message": f"REJECTED: Exposed {leak_count:,} times online!"
     })
    
    #NOTE:Math heavy part - Be careful touching, A lot of work if it breaks
    pool_size = 0
    pool_descriptions = []
    if has_lower:
        pool_size +=26
        pool_descriptions.append("Lowercase (26)")
    if has_upper:
        pool_size +=26
        pool_descriptions.append("Uppercase (26)")
    if has_digit:
        pool_size += 10
        pool_descriptions.append("Numbers (10)")
    if has_symbol:
        pool_size += 33
        pool_descriptions.append("Symbols (33)")
    z_eval = zxcvbn.zxcvbn(user_password_bytes.decode('utf-8'))
    pattern_logs = []
    raw_entropy = password_length * math.log2(pool_size) if pool_size > 0 else 0
    working_entropy = raw_entropy
    for match in z_eval.get('sequence',[]):
        p_type = match.get('pattern')
        token = match.get('token')
        if p_type == 'spatial':
            working_entropy *= 0.85
            pattern_logs.append(f"Log: Keyboard Spatial Walk [{token}] (-15% Bits)")
        elif p_type == 'repeat':
            working_entropy *= 0.80
            pattern_logs.append(f"Log: Heavy Character Repetition [{token}] (-20% Bits)")
        elif p_type == 'sequence':
            working_entropy *= 0.85
            pattern_logs.append(f"Log: Sequential Run [{token}] (-15% Bits)")
        elif p_type == 'dictionary':
           working_entropy *= 0.70
           pattern_logs.append(f"Log: Dictionary Word [{token}] (-30% Bits)")
    entropy_bits = round(max(0,working_entropy), 1)
    #NOTE:Unique Combo's
    try:
       total_combinations_raw = pool_size ** password_length if pool_size > 0 else 0
       combinations_string = f"{total_combinations_raw:.2e}"
    except (ValueError, OverflowError):
       combinations_string = "infinity"
    display_times = z_eval['crack_times_display']
    #NOTE:Different speed settings and colors based on time to crack
    time_offline_fast = display_times['offline_fast_hashing_1e10_per_second']
    time_offline_slow = display_times['offline_slow_hashing_1e4_per_second']
    time_online_unthrottled = display_times['online_no_throttling_10_per_second']
    time_online_throttled = display_times['online_throttling_100_per_hour']
    if "century" in time_offline_fast.lower() or "centuries" in time_offline_fast.lower():
        color = "green"
    elif "year" in time_offline_fast.lower() or "month" in time_offline_fast.lower():
        color = "darkgreen"
    elif "day" in time_offline_fast.lower() or "week" in time_offline_fast.lower():
        color = "blue"
    elif "hour" in time_offline_fast.lower() or "minute" in time_offline_fast.lower():
        color = "orange"
    else:
        color = "red"
    logging.info(f"Hard Math Completed. Entropy: {entropy_bits} bits")
    #NOTE:this wipes passwords from the ram
    for i in range(len(user_password_bytes)): 
        user_password_bytes[i] = 0
    del user_password_bytes
    gc.collect()
    return jsonify({
       "status": "safe",
       "color": color,
       "entropy_bits": entropy_bits,
       "length": password_length,
       "pool_size": pool_size,
       "pool_used": " + ".join(pool_descriptions),
       "patterns_flagged": " | ".join(pattern_logs) if pattern_logs else "None Detected",
       "combinations": combinations_string,
       "crack_time": time_offline_fast,
       "time_offline_slow": time_offline_slow,
       "time_online_unthrottled": time_online_unthrottled,
       "time_online_throttled": time_online_throttled
    })
@app.after_request
def security_settings(response):
   response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
   response.headers['X-Frame-Options'] = 'DENY'
   response.headers['X-Content-Type-Options'] = 'nosniff'
   return response
if __name__ == '__main__':
    print("=" * 70)
    print("   🛡️  CRYPTOGRAPHIC EVALUATION ENGINE V1.8 ACTIVATED  🛡️")
    print("   🚀 Built & Engineered by: Thomas D. Manning (2026)")
    print("   🔒 Infrastructure Status: Zero-Trust Security Perimeter Live")
    print("=" * 70)
    sys.stdout.flush()
    blind_port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=blind_port)


    ###IMPORTANT: Always end on a line divisible by 5 
