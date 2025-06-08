import re
from urllib.parse import urlparse
import socket
import ssl
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
    SCORE_CYRILLIC_HOMOGRAPH = 40 # Reintroducem scorul pentru homograf chirilic/IDN
    SCORE_TYPOSQUATTING_GENERAL = 30 # Schimbat pentru a diferentia de similaritatea TLD
    SCORE_DOMAIN_SIMILARITY_TLD_MISMATCH = 50 # Scor mai mare pentru diferențe de TLD pe nume identice

    # Liste predefinite
    FREE_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}
    SUSPICIOUS_KEYWORDS = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'confirm', 'reset', 'password', 'webmail', 'support', 'admin', 'client', 'serviciu', 'asistenta', 'card', 'tranzactie', 'plateste']
    COMMON_TYPOS = {
        'rn': 'm', 'cl': 'd', 'll': 'l', 'o0': 'oo', 'pa': 'pp',
        'i': 'l', '1': 'l', '0': 'o', 'gooogle': 'google', 'go0gle': 'google',
        'yah0o': 'yahoo', 'amzon': 'amazon', 'appple': 'apple',
        'facebok': 'facebook', 'twiter': 'twitter', 'youtub': 'youtube',
        'instgram': 'instagram', 'amaz0n': 'amazon', 'microsft': 'microsoft',
        'paypai': 'paypal', 'revoIut': 'revolut', 'roblox': 'roblox',
        'stean': 'steam', 'epigames': 'epicgames', 'blizzardd': 'blizzard',
        'disc0rd': 'discord', 'telegramm': 'telegram', 'whatsap': 'whatsapp',
        'snapcht': 'snapchat', 'tiktokk': 'tiktok', 'gmaiI': 'gmail',
        'outIook': 'outlook', 'bcrr': 'bcr', 'brdd': 'brd',
        'ingg': 'ing', 'btbank': 'bancatransilvania', 'cecbanc': 'cec.ro',
        'emagg': 'emag', 'altexx': 'altex'
    }

    # LISTA EXTINSĂ DE POPULAR_DOMAINS
    POPULAR_DOMAINS = [
        # Motoare de căutare / General
        'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'yandex.com',

        # Social Media
        'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
        'reddit.com', 'tiktok.com', 'snapchat.com', 'pinterest.com', 'tumblr.com',
        'discord.com', 'telegram.org', 'whatsapp.com', 'wechat.com', 'vk.com',
        'threads.net',

        # E-mail
        'gmail.com', 'outlook.live.com', 'mail.yahoo.com', 'aol.com', 'protonmail.com',
        'icloud.com', 'mail.ru',

        # Servicii Cloud / Productivitate
        'microsoft.com', 'office.com', 'onedrive.live.com', 'sharepoint.com',
        'apple.com', 'icloud.com', 'drive.google.com', 'docs.google.com',
        'dropbox.com', 'drive.google.com', 'mega.nz', 'wetransfer.com',
        'zoom.us', 'webex.com', 'slack.com', 'teams.microsoft.com',

        # Bănci România
        'bancatransilvania.ro', 'bt.ro', 'brd.ro', 'ing.ro', 'bcr.ro', 'raiffeisen.ro',
        'cec.ro', 'unicredit.ro', 'otpbank.ro', 'firstbank.ro', 'alpha.ro',
        'libra.ro', 'patria.ro', 'garantibank.ro', 'eximbank.ro', 'idea-bank.ro',

        # Bănci Internaționale / Fintech
        'paypal.com', 'revolut.com', 'wise.com', 'n26.com', 'monzo.com',
        'jp morgan.com', 'bankofamerica.com', 'citibank.com', 'wellsfargo.com',
        'hsbc.com', 'deutsche-bank.com', 'barclays.com', 'credit-agricole.com',

        # E-commerce / Retail
        'amazon.com', 'ebay.com', 'aliexpress.com', 'alibaba.com', 'etsy.com',
        'olx.ro', 'emag.ro', 'altex.ro', 'flanco.ro', 'dedeman.ro', 'leroymerlin.ro',
        'lidl.ro', 'kaufland.ro', 'carrefour.ro', 'auchan.ro',

        # Jocuri / Divertisment
        'youtube.com', 'netflix.com', 'hbo.com', 'disneyplus.com', 'spotify.com',
        'steam.com', 'steampowered.com', 'epicgames.com', 'roblox.com', 'riotgames.com',
        'blizzard.com', 'ea.com', 'ubisoft.com', 'nintendo.com', 'playstation.com',
        'xbox.com', 'twitch.tv', 'discordapp.com', 'minecraft.net',

        # Telecom România
        'digi.ro', 'orange.ro', 'vodafone.ro', 'telekom.ro',

        # Instituții Publice România
        'anaf.ro', 'anpc.ro', 'gov.ro', 'politiaromana.ro', 'just.ro', 'mfinante.gov.ro',
        'cnas.ro',

        # Altele, inclusiv companii mari unde se fură conturi
        'googleusercontent.com', # Foarte important pentru phishing cu documente/imagini găzduite
        'drive.google.com', # pentru fișiere google
        'cloudflare.com', 'github.com', 'adobe.com', 'valvesoftware.com',
        'booking.com', 'airbnb.com', 'tripadvisor.com', 'ryanair.com', 'wizzair.com',
        'cezar.ro', 'betano.ro', 'superbet.ro', # Site-uri de pariuri, frecvent țintite
        'okx.com', 'binance.com', 'coinbase.com', 'kraken.com', # Exchange-uri crypto, frecvent țintite
        'metamask.io', 'trustwallet.com', # Portofele crypto, frecvent țintite
        'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', # Extindere Amazon pe TLD-uri populare
        'microsoftonline.com', 'live.com', 'azurewebsites.net', # Extindere Microsoft
        'docs.microsoft.com', 'support.microsoft.com',
        'account.microsoft.com', 'id.apple.com', 'accounts.google.com', 'myaccount.google.com'
    ]

    # Parsăm URL-ul inițial
    parsed = urlparse(url.lower())
    original_domain = parsed.netloc
    original_scheme = parsed.scheme
    full_url = url.lower()

    # Extragem domeniul rădăcină al URL-ului analizat (fără Punycode inițial)
    domain_parts = original_domain.split('.')
    # Asigurăm că obținem domeniul rădăcină corect (ex: pentru "www.example.com" -> "example.com")
    # și tratăm cazurile în care TLD-ul este compus (ex: ".co.uk")
    if len(domain_parts) >= 3 and domain_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(domain_parts[-1]) == 2: # heuristic for 2-part TLDs
        root_domain = '.'.join(domain_parts[-3:])
        main_domain_part = domain_parts[-3] # ex: for "example.co.uk", this is "example"
    elif len(domain_parts) >= 2:
        root_domain = '.'.join(domain_parts[-2:])
        main_domain_part = domain_parts[-2] # ex: for "example.com", this is "example"
    else:
        root_domain = original_domain
        main_domain_part = original_domain

    # --- VERIFICARE CRITICĂ: URL-ul este un domeniu popular și cunoscut? ---
    popular_root_domains_set = set()
    for pd in POPULAR_DOMAINS:
        pd_parts = pd.split('.')
        popular_root_domains_set.add(pd) # Adăugăm domeniul complet
        if len(pd_parts) >= 3 and pd_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pd_parts[-1]) == 2:
            popular_root_domains_set.add('.'.join(pd_parts[-3:]))
        elif len(pd_parts) >= 2:
            popular_root_domains_set.add('.'.join(pd_parts[-2:]))

    is_known_popular_domain = False
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

        # --- Verificarea caracterelor chirilice/internaționale folosind IDNA decode ---
        decoded_domain_for_check = original_domain
        try:
            decoded_domain_for_check = idna.decode(original_domain)
            
            if any(ord(c) > 127 for c in decoded_domain_for_check):
                score += SCORE_CYRILLIC_HOMOGRAPH
                reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniul conține caractere non-ASCII/internaționale (posibil homograf).")

                # Acum comparăm domeniul decodat cu domenii populare
                for pop_dom_full in POPULAR_DOMAINS:
                    # Extragem main_domain_part pentru comparație și pentru a exclude cazurile scurte
                    pop_dom_parts = pop_dom_full.split('.')
                    if len(pop_dom_parts) >= 3 and pop_dom_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pop_dom_parts[-1]) == 2:
                        pop_main_part = pop_dom_parts[-3]
                    elif len(pop_dom_parts) >= 2:
                        pop_main_part = pop_dom_parts[-2]
                    else:
                        pop_main_part = pop_dom_full # Fallback pentru TLD-uri simple sau domenii fără puncte

                    if decoded_domain_for_check != pop_dom_full and \
                       len(pop_main_part) > 3 and \
                       levenshtein_distance(decoded_domain_for_check, pop_main_part) <= 1:
                        score += SCORE_TYPOSQUATTING_GENERAL
                        reasons.append(f"Scor +{SCORE_TYPOSQUATTING_GENERAL}: Domeniul decodat ('{decoded_domain_for_check}') seamănă foarte bine cu '{pop_dom_full}'.")
                        break # O singură potrivire este suficientă

        except idna.IDNAError:
            score += SCORE_CYRILLIC_HOMOGRAPH
            reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniu cu format IDN invalid sau caractere non-ASCII ce nu pot fi decodate.")
        except Exception as e:
            reasons.append(f"Atenție: Eroare la decodarea IDN: {e}. Continuăm analiza.")


        # Verificări Typosquatting și similaritate Levenshtein pe domeniul (posibil) Punycode
        current_root_domain_parts = original_domain.split('.')
        if len(current_root_domain_parts) >= 3 and current_root_domain_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(current_root_domain_parts[-1]) == 2:
            current_root_domain = '.'.join(current_root_domain_parts[-3:])
            current_main_domain_part = current_root_domain_parts[-3]
        elif len(current_root_domain_parts) >= 2:
            current_root_domain = '.'.join(current_root_domain_parts[-2:])
            current_main_domain_part = current_root_domain_parts[-2]
        else:
            current_root_domain = original_domain
            current_main_domain_part = original_domain
        
        # NOUA LOGICĂ pentru Typosquatting
        # Verificăm typosquatting doar dacă main_domain_part are mai mult de 3 litere
        if len(current_main_domain_part) > 3:
            for typo, correction in COMMON_TYPOS.items():
                # Aplicăm corecția pe main_domain_part pentru o comparație mai precisă
                if typo in current_main_domain_part:
                    temp_main_domain = current_main_domain_part.replace(typo, correction)
                    for pop_dom_full in POPULAR_DOMAINS:
                        pop_main_parts = pop_dom_full.split('.')
                        if len(pop_main_parts) >= 3 and pop_main_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pop_main_parts[-1]) == 2:
                            pop_main_domain = pop_main_parts[-3]
                        elif len(pop_main_parts) >= 2:
                            pop_main_domain = pop_main_parts[-2]
                        else:
                            pop_main_domain = pop_dom_full # Fallback
                        
                        if temp_main_domain != pop_main_domain and \
                           levenshtein_distance(temp_main_domain, pop_main_domain) <= 1:
                            score += SCORE_TYPOSQUATTING_GENERAL
                            reasons.append(f"Scor +{SCORE_TYPOSQUATTING_GENERAL}: Posibil typosquatting: '{typo}' în '{current_main_domain_part}' ar putea fi '{correction}' (similar cu '{pop_dom_full}').")
                            break # O singură potrivire este suficientă
                    if any("typosquatting" in r for r in reasons):
                        break

        # NOUA LOGICĂ pentru Similaritate Levenshtein (pentru domenii fără homograf IDN)
        # Această verificare se aplică pe `current_main_domain_part` (care e de obicei Punycode sau ASCII)
        # Verificăm similaritatea doar dacă main_domain_part are mai mult de 3 litere
        if len(current_main_domain_part) > 3:
            for pop_dom_full in POPULAR_DOMAINS:
                pop_main_parts = pop_dom_full.split('.')
                # Asigurăm că extragem corect root_domain și main_domain_part pentru domeniul popular
                if len(pop_main_parts) >= 3 and pop_main_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pop_main_parts[-1]) == 2:
                    pop_root_domain = '.'.join(pop_main_parts[-3:])
                    pop_main_domain = pop_main_parts[-3]
                elif len(pop_main_parts) >= 2:
                    pop_root_domain = '.'.join(pop_main_parts[-2:])
                    pop_main_domain = pop_main_parts[-2]
                else:
                    pop_root_domain = pop_dom_full
                    pop_main_domain = pop_dom_full

                # 1. Penalizare pentru nume de domeniu principale identice cu TLD diferit
                if current_main_domain_part == pop_main_domain and current_root_domain != pop_root_domain:
                    # ex: emag.com vs emag.ro, bcr.com vs bcr.ro
                    score += SCORE_DOMAIN_SIMILARITY_TLD_MISMATCH # Scor mai mare, deoarece e foarte înșelător
                    reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY_TLD_MISMATCH}: Nume de domeniu '{current_main_domain_part}' identic, dar TLD diferit de '{pop_root_domain}' (comparativ cu '{current_root_domain}'). Foarte suspect!")
                    # Nu punem break aici, pentru că vrem să prindem și alte similarități dacă există

                # 2. Penalizare pentru typosquatting general (diferență Levenshtein > 0)
                # Acesta ar trebui să prindă "instagrarn" vs "instagram"
                if current_main_domain_part != pop_main_domain and \
                   levenshtein_distance(current_main_domain_part, pop_main_domain) <= 2: # Am crescut pragul la 2
                    score += SCORE_TYPOSQUATTING_GENERAL
                    reasons.append(f"Scor +{SCORE_TYPOSQUATTING_GENERAL}: Domeniul '{current_main_domain_part}' seamănă foarte bine cu '{pop_main_domain}' (ex: '{pop_dom_full}'). Posibil typosquatting.")
                    # Punem break aici, o singură potrivire de acest tip e suficientă
                    break


    # --- Verificări de conectivitate și certificat (se aplică întotdeauna) ---
    try:
        ip = socket.gethostbyname(original_domain)
        reasons.append(f"DNS Rezolvat la IP: {ip}")
    except socket.gaierror:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare DNS (domeniu inexistent sau inaccesibil).")
    except Exception as e:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare la rezolvarea DNS: {e}.")

    # Inițializăm final_scheme cu original_scheme pentru a evita "referenced before assignment"
    final_scheme = original_scheme 
    final_url = url
    final_domain = original_domain # Inițializăm și final_domain

    try:
        # Adăugăm un User-Agent pentru a preveni blocarea de către servere mari
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.head(url, allow_redirects=True, timeout=5, headers=headers)
        final_url = response.url
        final_parsed = urlparse(final_url.lower())
        final_domain = final_parsed.netloc
        final_scheme = final_parsed.scheme

        if original_scheme == 'http' and final_scheme == 'https':
            reasons.append("Redirecționat de la HTTP la HTTPS.")
        elif original_scheme == 'http' and final_scheme == 'http':
            # Aplicăm penalizarea doar dacă nu este un domeniu popular și a rămas pe HTTP
            if not is_known_popular_domain:
                score += SCORE_INVALID_SSL
                reasons.append(f"Scor +{SCORE_INVALID_SSL}: URL HTTP nu a redirecționat la HTTPS.")

    except requests.exceptions.RequestException as e:
        # Dacă requests.head() eșuează, schemele și domeniile rămân la valorile inițiale
        score += SCORE_INVALID_SSL
        reasons.append(f"Scor +{SCORE_INVALID_SSL}: Conexiune HTTP/HTTPS eșuată sau eroare la redirecționare: {e}.")
        # final_domain și final_scheme rămân la original_domain/original_scheme, ceea ce e corect aici.

    # Verificarea SSL se face ACUM doar dacă URL-ul final este HTTPS
    # final_scheme este acum garantat să aibă o valoare
    if 'https' == final_scheme:
        try:
            context = ssl.create_default_context()
            # Conexiunea SSL ar trebui să folosească domeniul exact (Punycode dacă e cazul)
            # Folosim final_domain pentru că URL-ul ar fi putut fi redirecționat
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
        # Această adăugare de motiv este utilă chiar și pentru domenii populare care rămân HTTP
        reasons.append("URL-ul final este HTTP (nesecurizat).")

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
