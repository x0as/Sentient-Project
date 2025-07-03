import smtplib

def test_email_spoofing(target_email, from_email="spoof@test.com"):
    try:
        domain = target_email.split("@")[-1]
        server = smtplib.SMTP(f"mail.{domain}", 25, timeout=5)
        code, resp = server.mail(from_email)
        if code == 250:
            return "Server may accept spoofed Emails"
        else:
            return "Server rejected spoofed sender"
    except Exception as e:
        return f"Could not test: {e}"