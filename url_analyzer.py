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
    SCORE_CYRILLIC_HOMOGRAPH = 40
    SCORE_TYPOSQUATTING_GENERAL = 30
    SCORE_DOMAIN_SIMILARITY_TLD_MISMATCH = 50

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

    POPULAR_DOMAINS = [
        'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'yandex.com',

        'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
        'reddit.com', 'tiktok.com', 'snapchat.com', 'pinterest.com', 'tumblr.com',
        'discord.com', 'telegram.org', 'whatsapp.com', 'wechat.com', 'vk.com',
        'threads.net',

        'gmail.com', 'outlook.live.com', 'mail.yahoo.com', 'aol.com', 'protonmail.com',
        'icloud.com', 'mail.ru',

        'microsoft.com', 'office.com', 'onedrive.live.com', 'sharepoint.com',
        'apple.com', 'icloud.com', 'drive.google.com', 'docs.google.com',
        'dropbox.com', 'drive.google.com', 'mega.nz', 'wetransfer.com',
        'zoom.us', 'webex.com', 'slack.com', 'teams.microsoft.com',

        'bancatransilvania.ro', 'bt.ro', 'brd.ro', 'ing.ro', 'bcr.ro', 'raiffeisen.ro',
        'cec.ro', 'unicredit.ro', 'otpbank.ro', 'firstbank.ro', 'alpha.ro',
        'libra.ro', 'patria.ro', 'garantibank.ro', 'eximbank.ro', 'idea-bank.ro',

        'paypal.com', 'revolut.com', 'wise.com', 'n26.com', 'monzo.com',
        'jp morgan.com', 'bankofamerica.com', 'citibank.com', 'wellsfargo.com',
        'hsbc.com', 'deutsche-bank.com', 'barclays.com', 'credit-agricole.com',

        'amazon.com', 'ebay.com', 'aliexpress.com', 'alibaba.com', 'etsy.com',
        'olx.ro', 'emag.ro', 'altex.ro', 'flanco.ro', 'dedeman.ro', 'leroymerlin.ro',
        'lidl.ro', 'kaufland.ro', 'carrefour.ro', 'auchan.ro',

        'youtube.com', 'netflix.com', 'hbo.com', 'disneyplus.com', 'spotify.com',
        'steam.com', 'steampowered.com', 'epicgames.com', 'roblox.com', 'riotgames.com',
        'blizzard.com', 'ea.com', 'ubisoft.com', 'nintendo.com', 'playstation.com',
        'xbox.com', 'twitch.tv', 'discordapp.com', 'minecraft.net',

        'digi.ro', 'orange.ro', 'vodafone.ro', 'telekom.ro',

        'anaf.ro', 'anpc.ro', 'gov.ro', 'politiaromana.ro', 'just.ro', 'mfinante.gov.ro',
        'cnas.ro',

        'googleusercontent.com',
        'drive.google.com',
        'cloudflare.com', 'github.com', 'adobe.com', 'valvesoftware.com',
        'booking.com', 'airbnb.com', 'tripadvisor.com', 'ryanair.com', 'wizzair.com',
        'cezar.ro', 'betano.ro', 'superbet.ro',
        'okx.com', 'binance.com', 'coinbase.com', 'kraken.com',
        'metamask.io', 'trustwallet.com',
        'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es',
        'microsoftonline.com', 'live.com', 'azurewebsites.net',
        'docs.microsoft.com', 'support.microsoft.com',
        'account.microsoft.com', 'id.apple.com', 'accounts.google.com', 'myaccount.google.com'
    ]

    parsed = urlparse(url.lower())
    original_domain = parsed.netloc
    original_scheme = parsed.scheme
    full_url = url.lower()

    domain_parts = original_domain.split('.')
    if len(domain_parts) >= 3 and domain_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(domain_parts[-1]) == 2:
        root_domain = '.'.join(domain_parts[-3:])
        main_domain_part = domain_parts[-3]
    elif len(domain_parts) >= 2:
        root_domain = '.'.join(domain_parts[-2:])
        main_domain_part = domain_parts[-2]
    else:
        root_domain = original_domain
        main_domain_part = original_domain

    popular_root_domains_set = set()
    for pd in POPULAR_DOMAINS:
        pd_parts = pd.split('.')
        popular_root_domains_set.add(pd)
        if len(pd_parts) >= 3 and pd_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pd_parts[-1]) == 2:
            popular_root_domains_set.add('.'.join(pd_parts[-3:]))
        elif len(pd_parts) >= 2:
            popular_root_domains_set.add('.'.join(pd_parts[-2:]))

    is_known_popular_domain = False
    if original_domain in popular_root_domains_set or root_domain in popular_root_domains_set:
        is_known_popular_domain = True
        reasons.append("Acesta este un domeniu cunoscut și popular. Nu se aplică penalizări de scor direct.")

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

        decoded_domain_for_check = original_domain
        try:
            decoded_domain_for_check = idna.decode(original_domain)

            if any(ord(c) > 127 for c in decoded_domain_for_check):
                score += SCORE_CYRILLIC_HOMOGRAPH
                reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniul conține caractere non-ASCII/internaționale (posibil homograf).")

                for pop_dom_full in POPULAR_DOMAINS:
                    pop_dom_parts = pop_dom_full.split('.')
                    if len(pop_dom_parts) >= 3 and pop_dom_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pop_dom_parts[-1]) == 2:
                        pop_main_part = pop_dom_parts[-3]
                    elif len(pop_dom_parts) >= 2:
                        pop_main_part = pop_dom_parts[-2]
                    else:
                        pop_main_part = pop_dom_full

                    if decoded_domain_for_check != pop_dom_full and \
                       len(pop_main_part) > 3 and \
                       levenshtein_distance(decoded_domain_for_check, pop_main_part) <= 1:
                        score += SCORE_TYPOSQUATTING_GENERAL
                        reasons.append(f"Scor +{SCORE_TYPOSQUATTING_GENERAL}: Domeniul decodat ('{decoded_domain_for_check}') seamănă foarte bine cu '{pop_dom_full}'.")
                        break

        except idna.IDNAError:
            score += SCORE_CYRILLIC_HOMOGRAPH
            reasons.append(f"Scor +{SCORE_CYRILLIC_HOMOGRAPH}: Domeniu cu format IDN invalid sau caractere non-ASCII ce nu pot fi decodate.")
        except Exception as e:
            reasons.append(f"Atenție: Eroare la decodarea IDN: {e}. Continuăm analiza.")

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

        if len(current_main_domain_part) > 3:
            for typo, correction in COMMON_TYPOS.items():
                if typo in current_main_domain_part:
                    temp_main_domain = current_main_domain_part.replace(typo, correction)
                    for pop_dom_full in POPULAR_DOMAINS:
                        pop_main_parts = pop_dom_full.split('.')
                        if len(pop_main_parts) >= 3 and pop_main_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pop_main_parts[-1]) == 2:
                            pop_main_domain = pop_main_parts[-3]
                        elif len(pop_main_parts) >= 2:
                            pop_main_domain = pop_main_parts[-2]
                        else:
                            pop_main_domain = pop_dom_full

                        if temp_main_domain != pop_main_domain and \
                           levenshtein_distance(temp_main_domain, pop_main_domain) <= 1:
                            score += SCORE_TYPOSQUATTING_GENERAL
                            reasons.append(f"Scor +{SCORE_TYPOSQUATTING_GENERAL}: Posibil typosquatting: '{typo}' în '{current_main_domain_part}' ar putea fi '{correction}' (similar cu '{pop_dom_full}').")
                            break
                    if any("typosquatting" in r for r in reasons):
                        break

        if len(current_main_domain_part) > 3:
            for pop_dom_full in POPULAR_DOMAINS:
                pop_main_parts = pop_dom_full.split('.')
                if len(pop_main_parts) >= 3 and pop_main_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil'] and len(pop_main_parts[-1]) == 2:
                    pop_root_domain = '.'.join(pop_main_parts[-3:])
                    pop_main_domain = pop_main_parts[-3]
                elif len(pop_main_parts) >= 2:
                    pop_root_domain = '.'.join(pop_main_parts[-2:])
                    pop_main_domain = pop_main_parts[-2]
                else:
                    pop_root_domain = pop_dom_full
                    pop_main_domain = pop_dom_full

                if current_main_domain_part == pop_main_domain and current_root_domain != pop_root_domain:
                    score += SCORE_DOMAIN_SIMILARITY_TLD_MISMATCH
                    reasons.append(f"Scor +{SCORE_DOMAIN_SIMILARITY_TLD_MISMATCH}: Nume de domeniu '{current_main_domain_part}' identic, dar TLD diferit de '{pop_root_domain}' (comparativ cu '{current_root_domain}'). Foarte suspect!")

                if current_main_domain_part != pop_main_domain and \
                   levenshtein_distance(current_main_domain_part, pop_main_domain) <= 2:
                    score += SCORE_TYPOSQUATTING_GENERAL
                    reasons.append(f"Scor +{SCORE_TYPOSQUATTING_GENERAL}: Domeniul '{current_main_domain_part}' seamănă foarte bine cu '{pop_main_domain}' (ex: '{pop_dom_full}'). Posibil typosquatting.")
                    break

    try:
        ip = socket.gethostbyname(original_domain)
        reasons.append(f"DNS Rezolvat la IP: {ip}")
    except socket.gaierror:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare DNS (domeniu inexistent sau inaccesibil).")
    except Exception as e:
        score += SCORE_DNS_FAIL
        reasons.append(f"Scor +{SCORE_DNS_FAIL}: Eroare la rezolvarea DNS: {e}.")

    final_scheme = original_scheme
    final_url = url
    final_domain = original_domain

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.head(url, allow_redirects=True, timeout=5, headers=headers)
        final_url = response.url
        final_parsed = urlparse(final_url.lower())
        final_domain = final_parsed.netloc
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

    if 'https' == final_scheme:
        try:
            context = ssl.create_default_context()
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
