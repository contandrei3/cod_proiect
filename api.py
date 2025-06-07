from flask import Flask, request, jsonify
from flask_cors import CORS
from url_analyzer import analyze_url
import os
import re
import idna # Reintroducem modulul idna

app = Flask(__name__)
CORS(app)

# O expresie regulată simplă pentru a valida un URL.
# Am relaxat puțin regex-ul pentru a permite caractere non-ASCII,
# deoarece vom folosi idna.encode pentru a le converti la Punycode.
# Reține că URL_REGEX este încă util pentru a verifica structura generală (scheme, TLD, etc.)
# dar nu mai este singura sursă de adevăr pentru validarea caracterelor în domeniu.
URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https:// or ftp:// or ftps://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
    r'localhost|' # localhost...
    r'\d{1,3}(\.\d{1,3}){3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S*)$', re.IGNORECASE) # S* în loc de \S+ pentru a permite '/' ca ultim caracter și alte caractere în calea url-ului

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

    # --- NOU: Preprocesare URL pentru caractere internaționale (IDN) ---
    original_url = url # Păstrăm URL-ul original pentru afișare în răspuns
    processed_url = url
    try:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc

        # Încercăm să convertim domeniul la Punycode dacă este necesar
        # Acest lucru va genera o eroare dacă conține caractere invalide
        encoded_netloc = idna.encode(netloc).decode('ascii')
        
        # Reconstruim URL-ul cu domeniul codificat în Punycode
        processed_url = parsed_url._replace(netloc=encoded_netloc).geturl()
        
        # Dacă domeniul original conținea caractere non-ASCII, dar a fost codat cu succes,
        # ar trebui să apară ca Punycode.
        # În url_analyzer, vom decoda la loc pentru verificări de homografi.

    except idna.IDNAError as e:
        return jsonify({"error": f"Domeniul URL-ului conține caractere invalide sau este un IDN formatat greșit: {e}"}), 400
    except Exception as e:
        # Prinde alte erori de parsare/codare
        return jsonify({"error": f"Eroare la preprocesarea URL-ului: {e}"}), 400

    # --- Validare cu URL_REGEX pe URL-ul procesat (cu Punycode) ---
    if not URL_REGEX.match(processed_url):
        return jsonify({"error": "Formatul URL-ului este invalid după preprocesare. Asigură-te că include 'http://' sau 'https://' și este un URL valid."}), 400

    try:
        # Trimitem URL-ul original (cu caractere non-ASCII, dacă este cazul)
        # funcției de analiză, care se va ocupa de decodarea IDNA pentru verificări.
        result = analyze_url(original_url)
        return jsonify(result)
    except Exception as e:
        print(f"Eroare internă la analiza URL-ului '{original_url}': {e}")
        return jsonify({"error": "A apărut o eroare internă la analizarea URL-ului. Te rugăm să încerci din nou mai târziu."}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
