#Thomas.D.M built, UTSA Freshman summer 2026 

#import
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import zxcvbn
from flask import request
from difflib import SequenceMatcher
# SHA-1 
import hashlib
# API connect
import requests 
#Logging imports
import datetime
import logging
from logging.handlers import RotatingFileHandler
import math
import sys
import threading
import os


app = Flask(__name__)
CORS(app)
#Log File Rotation, total max 5MB
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
#Log file, *No passwords logged*
logging.basicConfig(
   level=logging.INFO,
   format='%(asctime)s - %(levelname)s - %(message)s',
   handlers=[log_handler, console_handler]
)
debounce_timer = None
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
   

#API Connection Thingamabober - complicated work, dont touch
def check_pwned_api(password):
   sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

   prefix = sha1_hash[:5]
   suffix = sha1_hash[5:]
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
      
   return 0 #no match

#added to stop Dos
def get_true_client_ip():
   
   if request.headers.getlist("X-Forwarded-For"):
      return request.headers.getlist("X-Forwarded-For")[0]
   return request.remote_addr

limiter = Limiter(
   app=app, 
   key_func=get_true_client_ip, 
   storage_uri="memory://"
)

@app.route('/analyze', methods=['POST'])
@limiter.limit("240 per minute")

#checks passwords
def analyze_password():
    data = request.get_json()
    user_password = data.get('password', '')
    password_length = len(user_password)

    if not user_password:
      return jsonify({"status": "empty", "message": "Enter a password above to begin analysis."})

    #Level 0 rule set - Variables
    special_symbols = "!@#$%&*?_"
    allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" + special_symbols
    has_upper = any(c.isupper() for c in user_password)
    has_lower = any(c.islower() for c in user_password)
    has_digit = any(c.isdigit() for c in user_password)
    has_symbol = any(c in special_symbols for c in user_password)
    

    for char in user_password:
       if char not in allowed_characters:
          logging.warning(f"Check failed. Reason: Illegal Character usage.")
          return jsonify({
             "status": "rejected",
             "message": f"REJECTED: Character '{char}' is not allowed! Use letters, numbers, or: {special_symbols}"
          })

    #Banned Password - local txt list (kinda redudent but its ok)
    banned_passwords = []

    ### Hard Stop - Ban Check
    user_pass_lower = user_password.lower()
    user_pass_hash = hashlib.sha1(user_pass_lower.encode('utf-8')).hexdigest().upper()
   ##Issue was here, now only matches at 100% for ban lsit
   #Had it trying to stop if more than 60% of the password was in the ban list but that failed
    if user_pass_hash in banned_memory_set:
        local_leak_count = check_pwned_api(user_password)
        if local_leak_count > 0:
            logging.warning(f"Check failed. Reason: Local ban list match")
            return jsonify({ 
                "status": "pwned", 
                "message": f"REJECTED: Common banned word or phrase match! Exposed {local_leak_count:,} times online!"
            })
        else:
            return jsonify({ 
                "status": "pwned", 
                "message": "REJECTED: Common banned word or phrase match."
            })

    # Stops Further Checks If Banned
    leak_count = check_pwned_api(user_password)
    if leak_count > 0:
     logging.warning(f"Check failed. Reason: Leaked password database match. Count: {leak_count}")
     return jsonify({
        "status": "pwned",
        "message": f"REJECTED: Exposed {leak_count:,} times online!"
     })
    
    #Math heavy part - Be careful touching, A lot of work if it breaks
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
        pool_size += 9
        pool_descriptions.append("Symbols (9)")

    z_eval = zxcvbn.zxcvbn(user_password)
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
    #Unique Combo's
    try:
       total_combinations_raw = pool_size ** password_length if pool_size > 0 else 0
       combinations_string = f"{total_combinations_raw:.2e}"
    except (ValueError, OverflowError):
       combinations_string = "infinity"

    #GPU guess speed
    time_text = z_eval['crack_times_display']['offline_fast_hashing_1e10_per_second']
    #Strength tiers
    if "century" in time_text.lower() or "centuries" in time_text.lower():
        color = "green"
    elif "year" in time_text.lower() or "month" in time_text.lower():
        color = "darkgreen"
    elif "day" in time_text.lower() or "week" in time_text.lower():
        color = "blue"
    elif "hour" in time_text.lower() or "minute" in time_text.lower():
        color = "orange"
    else:
        color = "red"

    logging.info(f"Hard Math Completed. Entropy: {entropy_bits} bits")

    user_password = "0" * len(user_password)
    del user_password

    return jsonify({
       "status": "safe",
       "color": color,
       "entropy_bits": entropy_bits,
       "length": password_length,
       "pool_size": pool_size,
       "pool_used": " + ".join(pool_descriptions),
       "patterns_flagged": " | ".join(pattern_logs) if pattern_logs else "None Detected",
       "combinations": combinations_string,
       "crack_time": time_text
    })

if __name__ == '__main__':
   blind_port = int(os.environ.get("PORT", 5000))
   app.run(host="0.0.0.0", port=blind_port)
