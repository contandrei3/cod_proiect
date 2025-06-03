import re
from urllib.parse import urlparse
import socket
import ssl
import whois
from datetime import datetime

def analyze_url(url: str) -> dict:
    reasons = []
    score = 0

    # Parsăm URL-ul
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    # Heuristici simple

    # Dacă URL-ul conține '@'
    if '@' in full_url:
        score += 20
        reasons.append("Conține '@'.")

    # Dacă are multe subdomenii
    if full_url.count('.') > 5:
        score += 10
        reasons.append("Multe subdomenii.")

    # Dacă domeniul conține '-'
    if '-' in domain:
        score += 10
        reasons.append("Cratimă în domeniu.")

    # Cuvinte cheie suspicioase
    keywords = ['login', 'secure', 'update', 'verify', 'account', 'bank']
    for kw in keywords:
        if kw in full_url:
            score += 10
            reasons.append(f"Cuvânt suspicios: '{kw}'.")

    # TLD-uri gratuite
    tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    if any(domain.endswith(tld) for tld in tlds):
        score += 25
        reasons.append(f"TLD gratuit: {domain.split('.')[-1]}.")

    # IP în loc de domeniu
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        score += 30
        reasons.append("IP în loc de domeniu.")

    # DNS Lookup
    try:
        ip = socket.gethostbyname(domain)
        reasons.append(f"IP: {ip}")
    except:
        score += 15
        reasons.append("DNS Fail.")

    # SSL Check
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_common = issuer.get('commonName', '')
                reasons.append(f"SSL emis de: {issuer_common}")
    except:
        score += 20
        reasons.append("SSL invalid.")

    # WHOIS
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and (datetime.now() - creation_date).days < 60:
            score += 20
            reasons.append("Domeniu creat recent.")
    except:
        score += 10
        reasons.append("WHOIS indisponibil.")

    # Scor final
    final_score = min(score, 100)

    risk_level = (
        "Scăzut" if final_score < 30 else
        "Mediu" if final_score < 60 else
        "Ridicat"
    )

    return {
        "url": url,
        "scor": final_score,
        "nivel_risc": risk_level,
        "detalii": reasons
    }
