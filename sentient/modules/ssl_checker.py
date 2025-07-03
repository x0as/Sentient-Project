import ssl
import socket

def check_ssl(domain):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "subject": dict(x[0] for x in cert['subject']),
                "issuer": dict(x[0] for x in cert['issuer']),
                "valid_from": cert['notBefore'],
                "valid_to": cert['notAfter'],
                "serial_number": cert['serialNumber'],
            }
    except Exception as e:
        return {"error": str(e)}
