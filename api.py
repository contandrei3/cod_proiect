from flask import Flask, request, jsonify
from flask_cors import CORS
from url_analyzer import analyze_url
import os
import re

app = Flask(__name__)
CORS(app)

URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'
    r'\d{1,3}(\.\d{1,3}){3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if data is None:
        return jsonify({"error": "Corpul cererii trebuie să fie JSON valid."}), 400

    if "url" not in data:
        return jsonify({"error": "Trebuie să trimiți un câmp 'url' în corpul cererii."}), 400

    url = data["url"]

    if not isinstance(url, str):
        return jsonify({"error": "Câmpul 'url' trebuie să fie un string."}), 400

    if not url.strip():
        return jsonify({"error": "Câmpul 'url' nu poate fi gol."}), 400

    if not URL_REGEX.match(url):
        return jsonify({"error": "Formatul URL-ului este invalid. Asigură-te că include 'http://' sau 'https://://' și este un URL valid."}), 400

    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        print(f"Eroare internă la analiza URL-ului '{url}': {e}")
        return jsonify({"error": "A apărut o eroare internă la analizarea URL-ului. Te rugăm să încerci din nou mai târziu."}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
