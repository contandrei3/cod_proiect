from flask import Flask, request, jsonify
from flask_cors import CORS
from url_analyzer import analyze_url
import os
import re # Importăm modulul re pentru expresii regulate

app = Flask(__name__)
CORS(app)

# O expresie regulată simplă pentru a valida un URL.
# Aceasta nu este perfectă, dar acoperă majoritatea cazurilor simple și necesită http:// sau https://.
# Pentru o validare mai strictă, ai putea folosi biblioteci dedicate (ex: 'validators' din pip).
URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https:// or ftp:// or ftps://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
    r'localhost|' # localhost...
    r'\d{1,3}(\.\d{1,3}){3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

@app.route("/analyze", methods=["POST"])
def analyze():
    # Încercăm să obținem corpul JSON din cerere
    data = request.get_json()

    # 1. Verificăm dacă corpul cererii este JSON valid
    if data is None:
        return jsonify({"error": "Corpul cererii trebuie să fie JSON valid."}), 400

    # 2. Verificăm dacă câmpul 'url' există în JSON
    if "url" not in data:
        return jsonify({"error": "Trebuie să trimiți un câmp 'url' în corpul cererii."}), 400

    url = data["url"]

    # 3. Verificăm dacă 'url' este un string
    if not isinstance(url, str):
        return jsonify({"error": "Câmpul 'url' trebuie să fie un string."}), 400

    # 4. Verificăm dacă 'url' nu este gol (doar spații albe)
    if not url.strip():
        return jsonify({"error": "Câmpul 'url' nu poate fi gol."}), 400

    # 5. Verificăm formatul URL-ului cu expresia regulată
    # Aceasta va asigura că input-ul arată ca un URL real.
    if not URL_REGEX.match(url):
        return jsonify({"error": "Formatul URL-ului este invalid. Asigură-te că include 'http://' sau 'https://' și este un URL valid."}), 400

    try:
        # Aici apelăm funcția de analiză din url_analyzer.py
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        # Dacă apare o eroare în timpul analizei, o înregistrăm (pentru debug)
        # și returnăm un mesaj de eroare generic clientului.
        print(f"Eroare internă la analiza URL-ului '{url}': {e}")
        return jsonify({"error": "A apărut o eroare internă la analizarea URL-ului. Te rugăm să încerci din nou mai târziu."}), 500

if __name__ == "__main__":
    # Setează portul. Railway va injecta variabila de mediu 'PORT'.
    # Folosim 8080 ca fallback pentru rularea locală.
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
