import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle

# Load dataset
data = pd.read_csv("sms.tsv", sep="\t", header=None, names=["label", "message"])

# Convert labels
data["label"] = data["label"].map({"ham": 0, "spam": 1})

X = data["message"]
y = data["label"]

# Convert text into numbers
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(X)

# Train model
model = MultinomialNB()
model.fit(X, y)

# Save model
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model trained successfully!")