import os
import hashlib

def analyze_file(filepath, include_content=False, max_bytes=4096):
    """
    Analyzes a file: returns size, type, hashes, and optionally content (up to max_bytes).
    """
    if not os.path.isfile(filepath):
        return f"File not found: {filepath}"

    size = os.path.getsize(filepath)
    filetype = os.path.splitext(filepath)[1] or "Unknown"
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
    except Exception as e:
        return f"Error reading file: {e}"

    result = (
        f"File: {filepath}\n"
        f"Type: {filetype}\n"
        f"Size: {size} bytes\n"
        f"MD5: {md5_hash.hexdigest()}\n"
        f"SHA256: {sha256_hash.hexdigest()}"
    )

    if include_content:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(max_bytes)
            result += f"\n\n--- File Content (first {max_bytes} bytes) ---\n{content}"
        except Exception as e:
            result += f"\n\nCould not read file content as text: {e}"

    return result