# Importăm Flask și funcțiile necesare pentru API
from flask import Flask, request, jsonify

# Importăm CORS — permite ca aplicația noastră să fie apelată din alte surse (ex: Thunkable)
from flask_cors import CORS

# Importăm funcția noastră de analiză a URL-urilor
from url_analyzer import analyze_url

# Importăm modulul os ca să citim variabila de mediu PORT de pe Railway
import os

# Creăm o aplicație Flask
app = Flask(__name__)

# Activăm CORS — adică permitem apeluri de la orice client (altă aplicație, browser, Thunkable etc.)
CORS(app)

# Definim un endpoint: /analyze
# Când cineva face un POST la /analyze, se va apela această funcție
@app.route("/analyze", methods=["POST"])
def analyze():
    # Luăm datele trimise de client, sub formă de JSON
    data = request.get_json()

    # Verificăm că am primit un câmp "url"
    if not data or "url" not in data:
        # Dacă nu am primit URL, returnăm un mesaj de eroare și codul 400 (bad request)
        return jsonify({"error": "Trebuie să trimiți un câmp 'url'"}), 400

    # Extragem URL-ul primit
    url = data["url"]

    try:
        # Apelăm funcția care face analiza URL-ului
        result = analyze_url(url)

        # Returnăm rezultatul sub formă de JSON
        return jsonify(result)
    except Exception as e:
        # Dacă apare o eroare, returnăm eroarea + cod 500 (server error)
        return jsonify({"error": str(e)}), 500

# Dacă rulăm acest fișier direct (nu îl importăm în alt fișier), pornim serverul
if __name__ == "__main__":
    # Pe Railway, PORT-ul este oferit printr-o variabilă de mediu
    port = int(os.environ.get("PORT", 5000))  # dacă nu există, folosim 5000 local
    # Pornim serverul pe 0.0.0.0 ca să fie vizibil din exterior
    app.run(host="0.0.0.0", port=port)
