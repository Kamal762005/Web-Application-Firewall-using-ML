import requests
import smtplib
import os
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib import request, error
import urllib.parse
import numpy as np
import pandas as pd
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

badwords = ['sleep', 'uid', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by', 'admin', 'drop',
            'script']

LOG_FILE = "waf_intrusion_log.txt"
def write_log(attacker_ip, method, payload, action="BLOCKED"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] | IP: {attacker_ip} | Method: {method} | Payload: {payload} | Action: {action}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(log_entry)

def ExtractFeatures(path, body):
    path = str(path)
    body = str(body)
    combined_raw = path + body
    raw_percentages = combined_raw.count("%")
    raw_spaces = combined_raw.count(" ")

    raw_percentages_count = raw_percentages if raw_percentages > 3 else 0
    raw_spaces_count = raw_spaces if raw_spaces > 3 else 0
    
    path_decoded = urllib.parse.unquote_plus(path)
    body_decoded = urllib.parse.unquote_plus(body)

    single_q = path_decoded.count("'") + body_decoded.count("'")
    double_q = path_decoded.count("\"") + body_decoded.count("\"")
    dashes = path_decoded.count("--") + body_decoded.count("--")
    braces = path_decoded.count("(") + body_decoded.count("(")
    spaces = path_decoded.count(" ") + body_decoded.count(" ")
    semicolons = path_decoded.count(";") + body_decoded.count(";")
    angle_brackets = path_decoded.count("<") + path_decoded.count(">") + body_decoded.count("<") + body_decoded.count(
        ">")
    special_chars = sum(path_decoded.count(c) + body_decoded.count(c) for c in '$&|')

    badwords_count = sum(path_decoded.lower().count(word) + body_decoded.lower().count(word) for word in badwords)

    path_length = len(path_decoded)
    body_length = len(body_decoded)

    return [single_q, double_q, dashes, braces, spaces, raw_percentages_count, semicolons, angle_brackets,
            special_chars, path_length, body_length, badwords_count]

def send_intrusion_alert(attacker_ip, attack_data):
    sender_email = "saikamal831@gmail.com"
    receiver_email = "saikama l831@gmail.com"
    app_password = "cuqp fpwz qxbs enpp"

    subject = "WAF ALERT: Intrusion Detected"
    body = f"""
Intrusion detected by Web Application Firewall

Time: {datetime.now()}

Attacker IP: {attacker_ip}
Payload: {attack_data}

Action Taken: Request Blocked
"""

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, app_password)
            server.send_message(msg)
            print("📧 Alert email sent successfully")
    except Exception as e:
        print("Email error:", e)


'''def detect_sql_injection(payload):
    features = ExtractFeatures("", payload)
    features = np.array(features).reshape(1, -1)
    with open('training_model.pkl', 'rb') as file:
        model = pickle.load(file)
    return model.predict(features)[0] == 1
'''

# SimpleHTTPProxy class
class SimpleHTTPProxy(SimpleHTTPRequestHandler):
    proxy_routes = {}

    @classmethod
    def set_routes(cls, proxy_routes):
        cls.proxy_routes = proxy_routes

    def do_GET(self):
        parts = self.path.split('/')
        print(parts)
        if len(parts) > 3:
            path_part = parts[3]
            body = ""  # GET requests
            live_data = ExtractFeatures(path_part, body)
            live_data = np.array(live_data).reshape(1, -1)  
            # Load model inside of a request handler
            with open('training_model.pkl', 'rb') as file:
                model = pickle.load(file)
            result = model.predict(live_data)  # prediction
            print(result[0])
            if result[0] == 1:
                print('Intrusion Detected')
                send_intrusion_alert(
                    attacker_ip=self.client_address[0],
                    attack_data=path_part
                )
                write_log(
                    attacker_ip=self.client_address[0],
                    method="GET",
                    payload=path_part,
                    action="BLOCKED"
                )
            else:
                write_log(
                    attacker_ip=self.client_address[0],
                    method="GET",
                    payload=path_part,
                    action="ALLOWED"
                )
        if len(parts) >= 2:
            self.proxy_request('http://' + parts[2] + '/')
            #url = "http://" + self.headers["Host"] + self.path
            #self.proxy_request(url)

        else:
            super().do_GET()

    def proxy_request(self, url):
        try:
            response = request.urlopen(url)
            #req = request.Request(url, headers=self.headers)
            #response = request.urlopen(req)

        except error.HTTPError as e:
            print('err')
            self.send_response_only(e.code)
            self.end_headers()
            return
        self.send_response_only(response.status)
        for n, val in response.headers.items():
            self.send_header(n, val)
        self.end_headers()
        self.copyfile(response, self.wfile)
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        # Forward POST request
        url = self.path
        response = requests.post(url, data=post_data, headers=self.headers, verify=False)

        self.send_response(response.status_code)
        for header, value in response.headers.items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(response.content)
        
        
        # 🔍 Inspect POST data
        '''if detect_sql_injection(post_data):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked by WAF")
            print("Intrusion Detected (POST)")
            return'''
        send_intrusion_alert(
            attacker_ip=self.client_address[0],
            attack_data=post_data
        )
        write_log(
            attacker_ip=self.client_address[0],
            method="POST",
            payload=post_data
        )


SimpleHTTPProxy.set_routes({'proxy_route': 'http://demo.testfire.net/'})
with HTTPServer(('127.0.0.1', 8080), SimpleHTTPProxy) as httpd:  
    host, port = httpd.socket.getsockname()
    print(f'Listening on http://{host}:{port}')
    try:
        httpd.serve_forever() 
    except KeyboardInterrupt: 
        print("\nKeyboard interrupt received, exiting.")