import re
from urllib.parse import urlparse
import socket
import ssl
# import whois # Păstrăm comentat conform discuției anterioare
from datetime import datetime
import idna # Reintroducem idna
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
    SCORE_CYRILLIC_HOMOGRAPH = 40 # Reintroducem scorul pentru homograf chirilic/IDN
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
        'emag.ro', 'olx.ro', 'bancatransilvania.ro', 'brd.ro',
        'ing.ro', 'cec.ro', 'bt.ro', 'digi.ro', 'orange.ro', 'vodafone.ro',
        'telekom.ro', 'anpc.ro', 'anaf.ro', 'gov.ro', 'mail.google.com',
        'drive.google.com', 'outlook.live.com', 'mail.yahoo.com', 'ro.wikipedia.org'
    ]

    # Parsăm URL-ul inițial
    parsed = urlparse(url.lower())
    original_domain = parsed.netloc
    original_scheme = parsed.scheme
    full_url = url.lower()

    # Extragem domeniul rădăcină al URL-ului analizat (fără Punycode inițial)
    domain_parts = original_domain.split('.')
    if len(domain_parts) >= 2:
        root_domain = '.'.join(domain_parts[-2:])
    else:
        root_domain = original_domain

    # --- VERIFICARE CRITICĂ: URL-ul este un domeniu popular și cunoscut? ---
    # Convertim domeniile populare în formatul root_domain pentru comparație
    # și adăugăm și original_domain pentru potriviri exacte, inclusiv subdomenii specifice
    popular_root_domains_set = set()
    for pd in POPULAR_DOMAINS:
        pd_parts = pd.split('.')
        if len(pd_parts) >= 2:
            popular_root_domains_set.add('.'.join(pd_parts[-2:]))
        popular_root_domains_set.add(pd) # Adăugăm și varianta completă pentru potriviri exacte de subdomeniu

    is_known_popular_domain = False
    # Verificăm potrivirea exactă a domeniului original (nu decodat încă)
    if original_domain in popular_root_domains_set or root_domain in popular_root_domains_set:
        is_known_popular_domain = True
        reasons.append("Acesta este un domeniu cunoscut și popular. Nu se aplică penalizări de scor direct.")

    # --- Verificări de bază (se aplică doar dacă NU este un domeniu popular cunoscut) ---
    if not is_known_popular_domain:
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

        # --- NOU: Verificarea caracterelor chirilice/internaționale folosind IDNA decode ---
        decoded_domain_for_check = original_domain
        try:
            # Încercăm să decodăm numele de domeniu. Dacă e Punycode, se va decoda.
            # Dacă sunt caractere non-ASCII directe (ex: "аpple.com"), idna.decode le va lăsa așa.
            decoded_domain_for_check = idna.decode(original_domain)
            
            # Verificăm dacă domeniul decodat conține caractere non-ASCII (e.g., chirilice)
            # Aceasta e noua logică pentru a prinde direct homografele vizuale
            if any(ord(c) > 127 for c in decoded_domain_for_check):
                score += SCORE_CYRILLIC_HOMOGRAPH
                reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniul conține caractere non-ASCII/internaționale (posibil homograf).")

                # Acum comparăm domeniul decodat cu domenii populare
                for pop_dom_full in POPULAR_DOMAINS:
                    pop_root_for_comparison = pop_dom_full.split('.')[-2] if len(pop_dom_full.split('.')) >= 2 else pop_dom_full
                    # Comparăm cu root_domain-ul popular, dar și cu domeniul complet popular
                    if levenshtein_distance(decoded_domain_for_check, pop_root_for_comparison) <= 2 or \
                       levenshtein_distance(decoded_domain_for_check, pop_dom_full) <= 2:
                        score += SCORE_DOMAIN_SIMILARITY
                        reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY}: Domeniul decodat ('{decoded_domain_for_check}') seamănă foarte bine cu '{pop_dom_full}'.")
                        break # O singură potrivire este suficientă

        except idna.IDNAError:
            # Aceasta înseamnă că domeniul este Punycode, dar nu este un IDN valid.
            # Sau conține caractere non-ASCII care nu pot fi interpretate ca IDN.
            # Îl tratăm ca suspect.
            score += SCORE_CYRILLIC_HOMOGRAPH # Sau un scor dedicat pentru IDNA invalid
            reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniu cu format IDN invalid sau caractere non-ASCII ce nu pot fi decodate.")
        except Exception as e:
            # Alte erori la decodare, le logăm/raportăm
            reasons.append(f"Atenție: Eroare la decodarea IDN: {e}. Continuăm analiza.")


        # Verificări Typosquatting și similaritate Levenshtein
        # Acestea se fac pe domeniul rădăcină, care ar trebui să fie ASCII (sau Punycode decodat)
        current_root_domain = domain_parts[-2] if len(domain_parts) >= 2 else original_domain
        
        for typo, correction in COMMON_TYPOS.items():
            if typo in current_root_domain:
                temp_domain = current_root_domain.replace(typo, correction)
                for pop_dom_full in POPULAR_DOMAINS:
                    pop_root = pop_dom_full.split('.')[-2] if len(pop_dom_full.split('.')) >= 2 else pop_dom_full
                    if levenshtein_distance(temp_domain, pop_root) <= 1:
                        score += SCORE_TYPOSQUATTING
                        reasons.append(f"Scor +{SCORE_TYPOSQUATTING}: Posibil typosquatting: '{typo}' în '{current_root_domain}' ar putea fi '{correction}' (similar cu '{pop_root}').")
                        break
                if any("typosquatting" in r for r in reasons):
                    break

        # Această verificare Levenshtein se aplică pe `current_root_domain` (care e de obicei Punycode sau ASCII)
        # Comparatia cu `decoded_domain_for_check` se face deja mai sus
        for pop_dom_full in POPULAR_DOMAINS:
            pop_root = pop_dom_full.split('.')[-2] if len(pop_dom_full.split('.')) >= 2 else pop_dom_full
            if levenshtein_distance(current_root_domain, pop_root) <= 2 and current_root_domain != pop_root:
                score += SCORE_DOMAIN_SIMILARITY
                reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY}: Domeniul '{current_root_domain}' seamănă foarte bine cu '{pop_root}'.")
                break

    # --- Verificări de conectivitate și certificat (se aplică întotdeauna) ---
    # Notă: Aici se folosește 'original_domain' pentru lookup DNS și SSL,
    # deoarece acestea funcționează de obicei cu numele de domeniu așa cum este (chiar și Punycode).
    # Sistemele DNS și SSL sunt concepute pentru a gestiona IDN-uri convertite în Punycode.

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
        # Folosim URL-ul original pentru request, deoarece requests va gestiona Punycode intern
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        final_parsed = urlparse(final_url.lower())
        final_domain = final_parsed.netloc # Acesta poate fi deja Punycode dacă așa a fost redirecționat
        final_scheme = final_parsed.scheme

        if original_scheme == 'http' and final_scheme == 'https':
            reasons.append("Redirecționat de la HTTP la HTTPS.")
        elif original_scheme == 'http' and final_scheme == 'http':
            if not is_known_popular_domain:
                score += SCORE_INVALID_SSL
                reasons.append(f"Scor +{SCORE_INVALID_SSL}: URL HTTP nu a redirecționat la HTTPS.")

    except requests.exceptions.RequestException as e:
        score += SCORE_INVALID_SSL
        reasons.append(f"Scor +{SCORE_INVALID_SSL}: Conexiune HTTP/HTTPS eșuată sau eroare la redirecționare: {e}.")
        final_domain = original_domain # Folosim domeniul original dacă redirecționarea a eșuat

    # Verificarea SSL se face ACUM doar dacă URL-ul final este HTTPS
    if 'https' == final_scheme:
        try:
            context = ssl.create_default_context()
            # Conexiunea SSL ar trebui să folosească domeniul exact (Punycode dacă e cazul)
            with socket.create_connection((final_domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=final_domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    issuer_common = issuer.get('commonName', '')
                    reasons.append(f"SSL emis de: {issuer_common}")

        except (socket.gaierror, ConnectionRefusedError, socket.timeout, ssl.SSLError) as e:
            if not is_known_popular_domain:
                score += SCORE_INVALID_SSL
                reasons.append(f"Scor +{SCORE_INVALID_SSL}: SSL invalid sau conexiune HTTPS eșuată pentru {final_domain}: {e}.")
        except Exception as e:
            if not is_known_popular_domain:
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
        "url": url, # Returnăm URL-ul original
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
        "https://аpple.com",                      # URL cu caracter chirilic (a mic)
        "https://paypal.com",
        "http://192.168.1.1/admin",
        "https://www.facebook.com/login.php?next=https://www.facebook.com/",
        "https://accounts.google.com/signin/v2/sl/pwd?flowName=GlifWebSignIn&flowEntry=ServiceLogin",
        "http://amazon.tk/login.php",
        "https://appIe.com",
        "https://microsoft.support.login.com",
        "https://www.rnicrosoft.com",
        "http://valid-site.com",
        "https://google.com/login",
        "https://xn--pple-43da.com",              # Punycode pentru аpple.com
        "https://www.bank-of-america.com"         # Exemplu de domeniu legitim cu cratimă
    ]

    print("--- Analiza URL-urilor ---")
    for u in test_urls:
        result = analyze_url(u)
        print(f"\nURL: {result['url']}")
        print(f"Scor: {result['scor']}")
        print(f"Nivel de risc: {result['nivel_risc']}")
        for detail in result['detalii']:
            print(f"  - {detail}")
