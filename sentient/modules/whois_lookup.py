import whois

def whois_lookup_cli(domain):
    try:
        w = whois.whois(domain)
        result = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "status": w.status
        }
        return result
    except Exception as e:
        return {"error": str(e)}