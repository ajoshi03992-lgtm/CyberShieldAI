job_keywords = [
"earn money fast",
"work from home",
"earn 5000 per day",
"earn 50000 per month",
"no experience required",
"instant job offer",
"part time job",
"whatsapp job"
]

def detect_job_scam(msg):

    msg = msg.lower()

    for word in job_keywords:
        if word in msg:
            return True

    return False