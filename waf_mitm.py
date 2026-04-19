# waf_mitm.py
from mitmproxy import http
import pickle

model = pickle.load(open("model.pkl", "rb"))

def request(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    if model.predict([len(url)])[0] == 1:
        flow.response = http.Response.make(
            403,
            b"Blocked by WAF",
            {"Content-Type": "text/plain"}
        )
