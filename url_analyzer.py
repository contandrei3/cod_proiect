import re
from urllib.parse import urlparse
import socket
import ssl
# import whois # Păstrăm comentat conform discuției anterioare
from datetime import datetime
import idna
from Levenshtein import distance as levenshtein_distance
import requests

def analyze_url(url: str) -> dict:
    """
    Analizează o URL pentru potențiale semne de phishing.

    Args:
        url (str): URL-ul de analizat.

    Returns:
        dict: Un dicționar cu scorul de risc, nivelul de risc și detalii.
    """
    reasons = []
    score = 0

    # Constante pentru scoruri
    SCORE_AT = 20
    SCORE_MANY_SUBDOMAINS = 10
    SCORE_HYPHEN = 10
    SCORE_SUSPICIOUS_KEYWORD = 10
    SCORE_FREE_TLD = 25
    SCORE_IP_ADDRESS = 30
    SCORE_DNS_FAIL = 15
    SCORE_INVALID_SSL = 20 # Acest scor va fi aplicat doar pentru erori de conexiune/certificat invalid
    SCORE_RECENT_DOMAIN = 20
    SCORE_WHOIS_UNAVAILABLE = 10
    SCORE_CYRILLIC_HOMOGRAPH = 40
    SCORE_TYPOSQUATTING = 30
    SCORE_DOMAIN_SIMILARITY = 40

    # Liste predefinite
    FREE_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}
    SUSPICIOUS_KEYWORDS = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'confirm', 'reset', 'password', 'webmail', 'support', 'admin']
    COMMON_TYPOS = {
        'rn': 'm', 'cl': 'd', 'll': 'l', 'o0': 'oo', 'pa': 'pp',
        'i': 'l', '1': 'l', '0': 'o', 'gooogle': 'google', 'go0gle': 'google',
        'yah0o': 'yahoo', 'amzon': 'amazon', 'appple': 'apple'
    }

    POPULAR_DOMAINS = [
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'paypal.com', 'ebay.com', 'netflix.com', 'wikipedia.org',
        'twitter.com', 'linkedin.com', 'instagram.com', 'bing.com', 'yahoo.com',
        'reddit.com', 'twitch.tv', 'cloudflare.com', 'github.com', 'adobe.com',
        'ro.wikipedia.org', 'emag.ro', 'olx.ro', 'bancatransilvania.ro', 'brd.ro',
        'ing.ro', 'bcrc.ro', 'cec.ro', 'bt.ro', 'digi.ro', 'orange.ro', 'vodafone.ro',
        'telekom.ro', 'anpc.ro', 'anaf.ro', 'gov.ro', 'mail.google.com', 'drive.google.com',
        'outlook.live.com', 'mail.yahoo.com'
    ]

    # Parsăm URL-ul inițial
    parsed = urlparse(url.lower())
    original_domain = parsed.netloc
    original_scheme = parsed.scheme
    full_url = url.lower()

    # --- Verificări de bază ---
    if '@' in full_url:
        score += SCORE_AT
        reasons.append(f"Scor +{SCORE_AT}: Conține '@' (posibilă ofuscare).")
    
    if original_domain.count('.') > 3:
        score += SCORE_MANY_SUBDOMAINS
        reasons.append(f"Scor +{SCORE_MANY_SUBDOMAINS}: Multe subdomenii.")
    
    if '-' in original_domain:
        score += SCORE_HYPHEN
        reasons.append(f"Scor +{SCORE_HYPHEN}: Cratimă în domeniu.")
    
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full_url:
            score += SCORE_SUSPICIOUS_KEYWORD
            reasons.append(f"Scor +{SCORE_SUSPICIOUS_KEYWORD}: Cuvânt suspicios în URL: '{kw}'.")
    
    if any(original_domain.endswith(tld) for tld in FREE_TLDS):
        score += SCORE_FREE_TLD
        reasons.append(f"Scor +{SCORE_FREE_TLD}: TLD gratuit: {original_domain.split('.')[-1]}.")
    
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', original_domain):
        score += SCORE_IP_ADDRESS
        reasons.append(f"Scor +{SCORE_IP_ADDRESS}: IP în loc de domeniu.")

    # --- Verificări avansate ---
    try:
        decoded_domain = idna.decode(original_domain)
        if decoded_domain != original_domain:
            score += SCORE_CYRILLIC_HOMOGRAPH
            reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniu cu caractere chirilice/internaționale (IDN homograph).")
            for pop_dom in POPULAR_DOMAINS:
                if levenshtein_distance(decoded_domain, pop_dom) <= 2:
                    score += SCORE_DOMAIN_SIMILARITY
                    reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY}: Domeniul decodat seamănă foarte bine cu '{pop_dom}'.")
                    break
    except idna.IDNAError:
        pass

    domain_parts = original_domain.split('.')
    root_domain = domain_parts[-2] if len(domain_parts) >= 2 else original_domain

    for typo, correction in COMMON_TYPOS.items():
        if typo in root_domain:
            temp_domain = root_domain.replace(typo, correction)
            for pop_dom in POPULAR_DOMAINS:
                if levenshtein_distance(temp_domain, pop_dom.split('.')[-2]) <= 1:
                    score += SCORE_TYPOSQUATTING
                    reasons.append(f"Scor +{SCORE_TYPOSQUATTING}: Posibil typosquatting: '{typo}' în '{root_domain}' ar putea fi '{correction}' (similar cu '{pop_dom}').")
                    break
            if SCORE_TYPOSQUATTING in [r.split(': ')[0].replace('Scor +', '') for r in reasons]:
                break

    for pop_dom in POPULAR_DOMAINS:
        pop_root = pop_dom.split('.')[-2] if len(pop_dom.split('.')) >= 2 else pop_dom
        if levenshtein_distance(root_domain, pop_root) <= 2 and root_domain != pop_root:
            score += SCORE_DOMAIN_SIMILARITY
            reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY}: Domeniul '{root_domain}' seamănă foarte bine cu '{pop_root}'.")
            break

    # --- Verificări de conectivitate și certificat ---

    # DNS Lookup
    try:
        ip = socket.gethostbyname(original_domain)
        reasons.append(f"DNS Rezolvat la IP: {ip}")
    except socket.gaierror:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare DNS (domeniu inexistent sau inaccesibil).")
    except Exception as e:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare la rezolvarea DNS: {e}.")

    # Gestionarea redirecționărilor și apoi verificarea SSL
    final_url = url
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        final_parsed = urlparse(final_url.lower())
        final_domain = final_parsed.netloc
        final_scheme = final_parsed.scheme

        if original_scheme == 'http' and final_scheme == 'https':
            reasons.append("Redirecționat de la HTTP la HTTPS.")
        elif original_scheme == 'http' and final_scheme == 'http':
            score += SCORE_INVALID_SSL # Scorem pentru că nu a redirecționat la HTTPS
            reasons.append(f"Scor +{SCORE_INVALID_SSL}: URL HTTP nu a redirecționat la HTTPS.")

    except requests.exceptions.RequestException as e:
        score += SCORE_INVALID_SSL
        reasons.append(f"Scor +{SCORE_INVALID_SSL}: Conexiune HTTP/HTTPS eșuată sau eroare la redirecționare: {e}.")
        final_domain = original_domain

    # Verificarea SSL se face ACUM doar dacă URL-ul final este HTTPS
    if 'https' == final_scheme:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((final_domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=final_domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    issuer_common = issuer.get('commonName', '')
                    reasons.append(f"SSL emis de: {issuer_common}")

                    # --- Această condiție a fost eliminată/comentată ---
                    # if not ssl.match_hostname(cert, final_domain):
                    #     score += SCORE_INVALID_SSL
                    #     reasons.append(f"Scor +{SCORE_INVALID_SSL}: Numele de domeniu din certificatul SSL nu se potrivește cu URL-ul final.")
                    # --------------------------------------------------

        except (socket.gaierror, ConnectionRefusedError, socket.timeout, ssl.SSLError) as e:
            score += SCORE_INVALID_SSL
            reasons.append(f"Scor +{SCORE_INVALID_SSL}: SSL invalid sau conexiune HTTPS eșuată pentru {final_domain}: {e}.")
        except Exception as e:
            score += SCORE_INVALID_SSL
            reasons.append(f"Scor +{SCORE_INVALID_SSL}: Eroare la verificarea SSL: {e}.")
    elif 'http' == final_scheme:
        reasons.append("URL-ul final este HTTP (nesecurizat).")

    # SECȚIUNEA WHOIS (COMENATĂ TEMPORAR) - Rămâne comentată
    # ... (blocul WHOIS comentat) ...

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

# Exemplu de utilizare:
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://phishing-site.example.com@bad.com/login",
        "https://www.sub.sub.sub.sub.sub.sub.bank.com",
        "http://faceb0ok-login.com",
        "https://аpple.com",
        "https://paypal.com",
        "http://192.168.1.1/admin",
        "https://www.facebook.com/login.php?next=https://www.facebook.com/",
        "https://accounts.google.com/signin/v2/sl/pwd?flowName=GlifWebSignIn&flowEntry=ServiceLogin",
        "http://amazon.tk/login.php",
        "https://appIe.com",
        "https://microsoft.support.login.com",
        "https://www.rnicrosoft.com"
    ]

    print("--- Analiza URL-urilor ---")
    for u in test_urls:
        result = analyze_url(u)
        print(f"\nURL: {result['url']}")
        print(f"Scor: {result['scor']}")
        print(f"Nivel de risc: {result['nivel_risc']}")
        for detail in result['detalii']:
            print(f"  - {detail}")
