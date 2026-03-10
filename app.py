from flask import Flask, render_template, request, redirect, url_for, session
import pickle
import os
import csv
from datetime import datetime

# custom modules
from smart_detection import rule_based_analysis
from auto_learning import save_message

app = Flask(__name__)
app.secret_key = "cybershield_secret_key"

# ================= LOAD ML MODEL =================
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

USERS_FILE = "users.txt"
LOG_FILE = "user_activity.csv"

# ================= INIT LOG FILE =================
if not os.path.exists(LOG_FILE):

    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:

        writer = csv.writer(f)

        writer.writerow([
            "Username",
            "Action",
            "Message",
            "Result",
            "Probability",
            "DateTime"
        ])


# ================= LOG ACTIVITY =================
def log_activity(username, action, message="", result="", probability=""):

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:

        writer = csv.writer(f)

        writer.writerow([
            username,
            action,
            message,
            result,
            probability,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ])


# ================= USER CHECK =================
def check_user(username, password):

    if not os.path.exists(USERS_FILE):
        return False

    with open(USERS_FILE, "r", encoding="utf-8") as f:

        for line in f:

            u, p = line.strip().split(",")

            if u == username and p == password:
                return True

    return False


# ================= LANDING PAGE =================
@app.route("/")
def landing():

    return render_template("landing.html")


# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        with open(USERS_FILE, "a", encoding="utf-8") as f:

            f.write(f"{username},{password}\n")

        return redirect(url_for("login"))

    return render_template("register.html")


# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if check_user(username, password):

            session["user"] = username

            log_activity(username, "LOGIN")

            return redirect(url_for("index"))

        else:

            return render_template(
                "login.html",
                error="Invalid username or password"
            )

    return render_template("login.html")


# ================= LOGOUT =================
@app.route("/logout")
def logout():

    if "user" in session:

        log_activity(session["user"], "LOGOUT")

    session.clear()

    return redirect(url_for("landing"))


# ================= MAIN DETECTION =================
@app.route("/index", methods=["GET", "POST"])
def index():

    if "user" not in session:
        return redirect(url_for("login"))

    result = None
    probability = None
    description = None
    message = ""

    rule_reason = None
    ask_user = []

    if request.method == "POST":

        message = request.form["message"]

        # ================= ML PREDICTION =================
        X = vectorizer.transform([message])

        prediction = model.predict(X)[0]

        probs = model.predict_proba(X)[0]

        spam_prob = round(probs[1] * 100, 2)

        safe_prob = round(probs[0] * 100, 2)

        if prediction == 1:

            result = "SPAM"
            probability = spam_prob

        else:

            result = "SAFE"
            probability = safe_prob


        # ================= RULE BASED ANALYSIS =================
        rule_result = rule_based_analysis(message)

        if rule_result["override"]:

            result = rule_result["result"]

            probability = rule_result["confidence"]

            rule_reason = rule_result["reason"]

            ask_user = rule_result["questions"]


        # ================= DESCRIPTION =================
        if result == "SPAM":

            if probability >= 90:
                description = "High Risk Scam Message"

            elif probability >= 70:
                description = "Likely Spam Message"

            else:
                description = "Suspicious Message"

        else:

            if probability >= 90:
                description = "Very Safe Message"

            elif probability >= 70:
                description = "Mostly Safe Message"

            else:
                description = "Uncertain Message"


        # ================= AUTO DATASET LEARNING =================
        save_message(message, result)


        # ================= LOG ACTIVITY =================
        log_activity(
            session["user"],
            "CHECK_MESSAGE",
            message,
            result,
            f"{probability}%"
        )


    return render_template(
        "index.html",
        result=result,
        probability=probability,
        description=description,
        message=message,
        rule_reason=rule_reason,
        ask_user=ask_user
    )


# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin():

    if "user" not in session:
        return redirect(url_for("login"))

    if session["user"] != "admin":

        return "Access Denied: Admins Only", 403


    logs = []

    if os.path.exists(LOG_FILE):

        with open(LOG_FILE, "r", encoding="utf-8") as f:

            reader = csv.reader(f)

            next(reader)

            logs = list(reader)

    return render_template("admin.html", logs=logs)


# ================= RUN APP =================
if __name__ == "__main__":

    app.run(debug=True)
