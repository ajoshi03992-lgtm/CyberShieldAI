import re

phishing_keywords = [
"verify your account",
"update your account",
"login immediately",
"suspended account",
"click here to verify",
"security alert",
"unusual activity",
"confirm your identity",
"reset password now"
]

def detect_phishing(msg):

    msg = msg.lower()

    for word in phishing_keywords:
        if word in msg:
            return True

    suspicious_domains = [
    ".ru",".tk",".xyz",".top",".gq"
    ]

    for d in suspicious_domains:
        if d in msg:
            return True

    return False