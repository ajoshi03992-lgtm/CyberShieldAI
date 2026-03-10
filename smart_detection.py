import re

from phishing_detection import detect_phishing
from otp_detection import detect_otp_scam
from job_scam_detection import detect_job_scam

from safe_browsing import extract_url, check_url_safety


# ================= TRUSTED DOMAINS =================

trusted_domains = [
"google.com",
"amazon.in",
"amazon.com",
"flipkart.com",
"paytm.com",
"phonepe.com",
"airtel.in",
"jio.com",
"sbi.co.in"
]


# ================= EDUCATIONAL / GOV DOMAINS =================

trusted_tlds = [
".ac.in",
".edu",
".edu.in",
".gov",
".gov.in",
".nic.in"
]


# ================= TELECOM BRANDS =================

telecom_brands = [
"airtel",
"jio",
"vodafone",
"vi",
"bsnl"
]


# ================= SHORT URL SERVICES =================

short_urls = [
"bit.ly",
"tinyurl",
"t.co",
"shorturl",
"goo.gl"
]


# ================= MASKED NUMBER DETECTION =================

def detect_masked_number(msg):

    pattern = r"\d{2,4}X{2,5}\d{2,4}"

    if re.search(pattern, msg):
        return True

    return False


# ================= SENDER ID DETECTION =================

def detect_sender_id(msg):

    pattern = r"[A-Z]{2}-[A-Z]{6}-[A-Z]"

    if re.search(pattern, msg):
        return True

    return False


# ================= LINK DETECTION =================

def detect_links(msg):

    pattern = r"(https?://\S+|www\.\S+|\S+\.(com|in|org|net|co))"

    if re.search(pattern, msg):
        return True

    return False


# ================= MAIN RULE ENGINE =================

def rule_based_analysis(msg):

    msg = msg.strip()
    msg_lower = msg.lower()

    result = {
        "override": False,
        "result": None,
        "confidence": None,
        "reason": None,
        "questions": []
    }

    # ================= PHISHING DETECTION =================

    if detect_phishing(msg):

        result["override"] = True
        result["result"] = "SPAM"
        result["confidence"] = 92
        result["reason"] = "Phishing pattern detected"

        return result


    # ================= OTP DETECTION =================

    otp = detect_otp_scam(msg)

    if otp == "scam":

        result["override"] = True
        result["result"] = "SPAM"
        result["confidence"] = 95
        result["reason"] = "OTP scam detected"

        return result

    if otp == "legitimate":

        result["override"] = True
        result["result"] = "SAFE"
        result["confidence"] = 90
        result["reason"] = "Legitimate OTP message"

        return result


    # ================= JOB SCAM =================

    if detect_job_scam(msg):

        result["override"] = True
        result["result"] = "SPAM"
        result["confidence"] = 93
        result["reason"] = "Fake job scam detected"

        return result


    # ================= MASKED NUMBER =================

    if detect_masked_number(msg):

        result["override"] = True
        result["result"] = "SAFE"
        result["confidence"] = 95
        result["reason"] = "Masked number detected (Bank/Telecom message)"

        return result


    # ================= TELECOM PROMOTIONAL =================

    if any(brand in msg_lower for brand in telecom_brands):

        result["override"] = True
        result["result"] = "SAFE"
        result["confidence"] = 92
        result["reason"] = "Telecom promotional message detected"

        return result


    # ================= SENDER ID DETECTION =================

    if detect_sender_id(msg):

        result["override"] = True
        result["result"] = "SAFE"
        result["confidence"] = 90
        result["reason"] = "Official sender ID detected"

        return result


    # ================= LINK DETECTION =================

    url = extract_url(msg)

    if url:

        status = check_url_safety(url)

        # Google Safe Browsing result

        if status == "dangerous":

            result["override"] = True
            result["result"] = "SPAM"
            result["confidence"] = 98
            result["reason"] = "Google Safe Browsing flagged this URL as dangerous"

            return result


        # Educational / Government domains

        if any(tld in msg_lower for tld in trusted_tlds):

            result["override"] = True
            result["result"] = "SAFE"
            result["confidence"] = 95
            result["reason"] = "Educational/Government domain detected"

            return result


        # Trusted domains

        elif any(domain in msg_lower for domain in trusted_domains):

            result["override"] = True
            result["result"] = "SAFE"
            result["confidence"] = 92
            result["reason"] = "Trusted domain detected"

            return result


        # Short URL detection

        elif any(short in msg_lower for short in short_urls):

            result["override"] = True
            result["result"] = "SPAM"
            result["confidence"] = 90
            result["reason"] = "Shortened URL detected (possible phishing)"

            return result


        # Unknown domain

        else:

            result["override"] = True
            result["result"] = "SPAM"
            result["confidence"] = 85
            result["reason"] = "Unknown domain detected"

            result["questions"] = [
                "Did you request this message?",
                "Do you trust this sender?",
                "Are you expecting this link?"
            ]

            return result


    return result