import base64
import json

def decode_jwt(token):
    try:
        header, payload, signature = token.split('.')
        header = json.loads(base64.urlsafe_b64decode(header + '=='))
        payload = json.loads(base64.urlsafe_b64decode(payload + '=='))
        return {"header": header, "payload": payload, "signature": signature}
    except Exception as e:
        return {"error": str(e)}
    
    # Example usage:
    # print(decode_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))