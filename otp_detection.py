import re

def detect_otp_scam(msg):

    msg_lower = msg.lower()

    otp_pattern = r"\b\d{4,6}\b"

    if re.search(otp_pattern, msg):

        if "otp" in msg_lower:

            if "do not share" in msg_lower:
                return "legitimate"

            if "share otp" in msg_lower or "send otp" in msg_lower:
                return "scam"

    return None