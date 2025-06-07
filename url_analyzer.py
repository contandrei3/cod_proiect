import re
from urllib.parse import urlparse
import socket
import ssl
import whois
from datetime import datetime
import idna # Pentru caracterele chirilice, necesită pip install idna
from Levenshtein import distance as levenshtein_distance # Pentru similaritate, necesită pip install python-Levenshtein

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
    SCORE_INVALID_SSL = 20
    SCORE_RECENT_DOMAIN = 20
    SCORE_WHOIS_UNAVAILABLE = 10
    SCORE_CYRILLIC_HOMOGRAPH = 40 # Scor mare pentru homografe chirilice
    SCORE_TYPOSQUATTING = 30 # Scor mare pentru typosquatting
    SCORE_DOMAIN_SIMILARITY = 40 # Scor mare pentru similitudine cu domenii populare

    # Liste predefinite
    FREE_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}
    SUSPICIOUS_KEYWORDS = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'confirm', 'reset', 'password', 'webmail', 'support', 'admin']
    COMMON_TYPOS = {
        'rn': 'm',
        'cl': 'd',
        'll': 'l',
        'o0': 'oo', # Ex: goog0le.com
        'pa': 'pp', # Ex: paypa1.com (unde 1 e l)
        'i': 'l',
        '1': 'l',
        '0': 'o',
        'gooogle': 'google', # Repetari de litere
        'go0gle': 'google',
        'yah0o': 'yahoo',
        'amzon': 'amazon',
        'appple': 'apple'
    }

    # Lista de domenii populare (exemplu - ajustați după nevoi)
    # Acestea ar trebui să fie domeniile REAL LEGITIME
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

    # Parsăm URL-ul
    parsed = urlparse(url.lower())
    domain = parsed.netloc
    path = parsed.path
    full_url = url.lower()

    # --- Verificări de bază ---

    # Dacă URL-ul conține '@' (obfuscation)
    if '@' in full_url:
        score += SCORE_AT
        reasons.append(f"Scor +{SCORE_AT}: Conține '@' (posibilă ofuscare).")

    # Dacă are multe subdomenii
    # Numărăm punctele din domeniu, excluzând TLD-ul
    if domain.count('.') > 3: # Mai mult de 3 puncte (ex: www.sub.domeniu.com)
        score += SCORE_MANY_SUBDOMAINS
        reasons.append(f"Scor +{SCORE_MANY_SUBDOMAINS}: Multe subdomenii.")

    # Dacă domeniul conține '-' (semn de phishing sau domenii noi)
    if '-' in domain:
        score += SCORE_HYPHEN
        reasons.append(f"Scor +{SCORE_HYPHEN}: Cratimă în domeniu.")

    # Cuvinte cheie suspicioase (verificate în întreg URL-ul, nu doar în path)
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full_url:
            score += SCORE_SUSPICIOUS_KEYWORD
            reasons.append(f"Scor +{SCORE_SUSPICIOUS_KEYWORD}: Cuvânt suspicios în URL: '{kw}'.")

    # TLD-uri gratuite
    if any(domain.endswith(tld) for tld in FREE_TLDS):
        score += SCORE_FREE_TLD
        reasons.append(f"Scor +{SCORE_FREE_TLD}: TLD gratuit: {domain.split('.')[-1]}.")

    # IP în loc de domeniu
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        score += SCORE_IP_ADDRESS
        reasons.append(f"Scor +{SCORE_IP_ADDRESS}: IP în loc de domeniu.")

    # --- Verificări avansate ---

    # 1. Analiza caracterelor chirilice (IDN Homograph Attack)
    try:
        # Încercăm să decodăm domeniul ca IDNA. Dacă reușește, înseamnă că are caractere non-ASCII
        # care ar putea fi homografe.
        decoded_domain = idna.decode(domain)
        if decoded_domain != domain:
            # Înseamnă că domeniul a fost codificat Punycode și a conținut caractere non-ASCII
            score += SCORE_CYRILLIC_HOMOGRAPH
            reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniu cu caractere chirilice/internaționale (IDN homograph).")
            # Putem adăuga aici o verificare suplimentară dacă domeniul decodat seamănă cu unul popular
            for pop_dom in POPULAR_DOMAINS:
                if levenshtein_distance(decoded_domain, pop_dom) <= 2: # Toleranță mică
                    score += SCORE_DOMAIN_SIMILARITY
                    reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY}: Domeniul decodat seamănă foarte bine cu '{pop_dom}'.")
                    break # Ieșim după prima potrivire

    except idna.IDNAError:
        # Nu este un domeniu IDNA valid sau nu conține caractere chirilice
        pass

    # 2. Tiposquatting (alăturări de genul "rn" în loc de "m", etc.)
    # Extragem doar numele de domeniu fără subdomenii și TLD pentru această verificare
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        root_domain = domain_parts[-2] # Ex: pentru www.google.com, root_domain este google
    else:
        root_domain = domain

    # Verificăm typosquatting pentru root_domain
    for typo, correction in COMMON_TYPOS.items():
        if typo in root_domain:
            temp_domain = root_domain.replace(typo, correction)
            for pop_dom in POPULAR_DOMAINS:
                # Verificăm dacă corecția îl aduce aproape de un domeniu popular
                if levenshtein_distance(temp_domain, pop_dom.split('.')[-2]) <= 1: # Prag foarte mic
                    score += SCORE_TYPOSQUATTING
                    reasons.append(f"Scor +{SCORE_TYPOSQUATTING}: Posibil typosquatting: '{typo}' în '{root_domain}' ar putea fi '{correction}' (similar cu '{pop_dom}').")
                    break # Ieșim după prima potrivire pentru acest typo
            if SCORE_TYPOSQUATTING in [r.split(': ')[0].replace('Scor +', '') for r in reasons]: # Dacă am adăugat deja, nu mai verificăm
                break


    # 3. Similitudinea cu o listă scurtă de site-uri foarte populare (fără typosquatting)
    # Comparăm domeniul curent (ou root_domain) cu cele populare
    for pop_dom in POPULAR_DOMAINS:
        # Folosim doar partea principală a domeniului popular pentru comparație
        pop_root = pop_dom.split('.')[-2] if len(pop_dom.split('.')) >= 2 else pop_dom

        # Comparăm domeniul analizat cu domeniul popular
        # Un prag de 2 sau 3 pentru Levenshtein este un bun început
        # Pentru domenii scurte, chiar și 1 poate fi un semn puternic
        if levenshtein_distance(root_domain, pop_root) <= 2 and root_domain != pop_root:
            score += SCORE_DOMAIN_SIMILARITY
            reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY}: Domeniul '{root_domain}' seamănă foarte bine cu '{pop_root}'.")
            break # Ieșim după prima potrivire semnificativă

    # --- Verificări de conectivitate și certificat ---

    # DNS Lookup
    try:
        ip = socket.gethostbyname(domain)
        reasons.append(f"DNS Rezolvat la IP: {ip}")
    except socket.gaierror:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare DNS (domeniu inexistent sau inaccesibil).")
    except Exception as e:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare la rezolvarea DNS: {e}.")

    # SSL Check
    # Această verificare poate fi costisitoare și ar putea încetini analiza pentru un număr mare de URL-uri.
    # Se poate adăuga o verificare a numelui de domeniu din certificat.
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_common = issuer.get('commonName', '')
                reasons.append(f"SSL emis de: {issuer_common}")

                # Verificăm dacă numele de domeniu din certificat se potrivește cu cel al site-ului
                # Aceasta e o verificare crucială pentru phishing
                if not ssl.match_hostname(cert, domain):
                    score += SCORE_INVALID_SSL
                    reasons.append(f"Scor +{SCORE_INVALID_SSL}: Numele de domeniu din certificat nu se potrivește cu URL-ul.")

    except (socket.gaierror, ConnectionRefusedError, socket.timeout, ssl.SSLError):
        score += SCORE_INVALID_SSL
        reasons.append(f"Scor +{SCORE_INVALID_SSL}: SSL invalid sau conexiune HTTPS eșuată.")
    except Exception as e:
        score += SCORE_INVALID_SSL
        reasons.append(f"Scor +{SCORE_INVALID_SSL}: Eroare la verificarea SSL: {e}.")

    # WHOIS
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and (datetime.now() - creation_date).days < 90: # Extindem la 90 de zile
            score += SCORE_RECENT_DOMAIN
            reasons.append(f"Scor +{SCORE_RECENT_DOMAIN}: Domeniu creat recent ({creation_date.strftime('%Y-%m-%d')}).")
    except whois.parser.PywhoisError:
        score += SCORE_WHOIS_UNAVAILABLE
        reasons.append(f"Scor +{SCORE_WHOIS_UNAVAILABLE}: WHOIS indisponibil (posibil ascuns/nou).")
    except Exception as e:
        score += SCORE_WHOIS_UNAVAILABLE
        reasons.append(f"Scor +{SCORE_WHOIS_UNAVAILABLE}: Eroare la interogarea WHOIS: {e}.")

    # Scor final
    final_score = min(score, 100) # Maximizăm scorul la 100

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
        "http://phishing-site.example.com@bad.com/login", # Cu @
        "https://www.sub.sub.sub.sub.sub.sub.bank.com", # Multe subdomenii
        "http://faceb0ok-login.com", # Typosquatting
        "https://аpple.com", # Chirilice (а seamănă cu a latin)
        "https://paypal.com", # Legit
        "http://192.168.1.1/admin", # IP
        "https://www.facebook.com/login.php?next=https://www.facebook.com/", # Legit, dar cu login
        "https://accounts.google.com/signin/v2/sl/pwd?flowName=GlifWebSignIn&flowEntry=ServiceLogin", # Legit
        "http://amazon.tk/login.php", # TLD gratuit
        "https://appIe.com", # l mare in loc de L mic
        "https://microsoft.support.login.com", # Subdomeniu inversat/cheie
        "https://www.rnicrosoft.com" # rn in loc de m
    ]

    print("--- Analiza URL-urilor ---")
    for u in test_urls:
        result = analyze_url(u)
        print(f"\nURL: {result['url']}")
        print(f"Scor: {result['scor']}")
        print(f"Nivel de risc: {result['nivel_risc']}")
        for detail in result['detalii']:
            print(f"  - {detail}")
