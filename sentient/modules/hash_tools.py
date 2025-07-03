import hashlib

def identify_hash(hash_str):
    hash_types = {
        32: "MD5",
        40: "SHA1",
        56: "SHA224",
        64: "SHA256",
        96: "SHA384",
        128: "SHA512"
    }
    return hash_types.get(len(hash_str), "Unknown")

def crack_hash(hash_str, wordlist=None):
    if wordlist is None:
        wordlist = ["password", "123456", "admin", "letmein", "qwerty", "sentient"]
    hash_type = identify_hash(hash_str)
    for word in wordlist:
        if hash_type == "MD5":
            if hashlib.md5(word.encode()).hexdigest() == hash_str:
                return word
        elif hash_type == "SHA1":
            if hashlib.sha1(word.encode()).hexdigest() == hash_str:
                return word
        elif hash_type == "SHA256":
            if hashlib.sha256(word.encode()).hexdigest() == hash_str:
                return word
        elif hash_type == "SHA512":
            if hashlib.sha512(word.encode()).hexdigest() == hash_str:
                return word
    return None