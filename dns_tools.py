import dns.resolver
def dns_lookup(domain, record_type="A"):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception as e:
        return {f"Error: {e}"}
