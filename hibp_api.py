import hashlib
import requests

def check_pwned(password):
    # Hash password using SHA1
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    # Query HIBP API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return None, "Error contacting HIBP"

    hashes = (line.split(":") for line in response.text.splitlines())

    for h, count in hashes:
        if h == suffix:
            return int(count), None  # Number of times password has been leaked

    return 0, None  # Not found in leaks
