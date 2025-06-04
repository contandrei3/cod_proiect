from flask import Flask, request, jsonify
from urllib.parse import urlparse
import socket
import ssl
import whois
from datetime import datetime
import os

app = Flask(__name__)

def analyze_url(url: str) -> dict:
    reasons = []
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Reguli simple (exemplu)
    if '@' in url:
        score += 20
        reasons.append("Conține '@'")
    if domain.count('.') > 3:
        score += 10
        reasons.append("Multe subdomenii")

    # Verifică WHOIS
    try:
        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        if (datetime.now() - creation_date).days < 30:
            score += 20
            reasons.append("Domeniu nou (<30 zile)")
    except:
        reasons.append("WHOIS indisponibil")

    return {
        "url": url,
        "score": min(score, 100),
        "reasons": reasons
    }

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Trimite un URL în JSON"}), 400
    try:
        result = analyze_url(data["url"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
