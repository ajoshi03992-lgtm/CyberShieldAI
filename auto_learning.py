import csv
import os

DATA_FILE = "auto_dataset.csv"

def save_message(msg,label):

    file_exists = os.path.exists(DATA_FILE)

    with open(DATA_FILE,"a",newline="",encoding="utf-8") as f:

        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["message","label"])

        writer.writerow([msg,label])