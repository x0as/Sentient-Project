import re

def check_password_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"\d", password): score += 1
    if re.search(r"\W", password): score += 1
    if score >= 4:
        return "Strong"
    elif score == 3:
        return "Medium"
    else:
        return "Weak"

# Example usage:
# print(check_password_strength("MyP@ssw0rd!"))