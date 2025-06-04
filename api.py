from flask import Flask, request, jsonify
from flask_cors import CORS
from url_analyzer import analyze_url
import os

app = Flask(__name__)
CORS(app)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Trebuie să trimiți un câmp 'url'"}), 400

    url = data["url"]

    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # Railway setează PORT
    app.run(host="0.0.0.0", port=port)
