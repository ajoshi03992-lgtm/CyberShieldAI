import requests
import re

API_KEY = "YOUR_GOOGLE_API_KEY"

def extract_url(msg):

    pattern = r"(https?://\S+|www\.\S+|\S+\.(com|in|org|net))"

    match = re.search(pattern, msg)

    if match:
        return match.group(0)

    return None


def check_url_safety(url):

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "cybershieldai",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:

        response = requests.post(endpoint, json=payload)

        result = response.json()

        if "matches" in result:
            return "dangerous"

        return "safe"

    except:
        return "unknown"