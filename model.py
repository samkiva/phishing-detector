import pandas as pd
import numpy as np
import re
import tldextract
import joblib
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# ── 1. GENERATE DATASET LOCALLY ───────────────────────────────────────────────
random.seed(42)
np.random.seed(42)

legit_urls = [
    "https://www.google.com/search?q=python",
    "https://github.com/login",
    "https://stackoverflow.com/questions/12345",
    "https://www.youtube.com/watch?v=abc123",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://docs.python.org/3/library/os.html",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://mail.google.com/mail/u/0/",
    "https://www.linkedin.com/in/username",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone",
    "https://www.bbc.com/news/world",
    "https://www.twitter.com/home",
    "https://www.facebook.com/login",
    "https://www.instagram.com/explore",
    "https://stripe.com/docs/payments",
    "https://www.dropbox.com/home",
    "https://accounts.google.com/signin",
    "https://www.netflix.com/browse",
    "https://www.reddit.com/r/Python",
]

phishing_urls = [
    "http://secure-login.paypa1.com/verify?user=sam&token=xyz",
    "http://192.168.1.105/bank/login.php?ref=1234",
    "http://update-your-account.info/gmail/signin",
    "http://free-gift-claim.tk/win?id=99999",
    "http://login-verify.net/facebook/confirm?user=admin",
    "http://paypal-secure.ru/account/login",
    "http://secure.bankofamerica.verify-info.com/login",
    "http://apple-id.update-required.net/verify",
    "http://bit.ly/3xyz123/amazon-reward-claim",
    "http://netflix-verify.gq/update-billing.php",
    "http://amaz0n.free-offer.win/deals?r=abc&t=xyz",
    "http://microsoft-alert.cf/security-check?id=12345",
    "http://verify-your-details.co/login?redirect=bank",
    "http://support-ticket-12345.ru/resolve?token=asd",
    "http://click-here-win.info/prize?user=victim&ref=99",
    "http://account-suspended.ml/restore-access?id=78",
    "http://bank-notification.gq/transaction?amount=5000",
    "http://confirm-identity.tk/step1?ssn=required",
    "http://update-required.cf/credentials?acct=suspend",
    "http://free-iphone.win/claim?promo=abc&src=email",
]

# Expand to 5000 samples with augmentation
def augment_url(url, is_phishing):
    if is_phishing:
        mods = [
            lambda u: u.replace('http://', 'http://').replace('.com', '.secure-' + str(random.randint(1,99)) + '.net'),
            lambda u: u + '&session=' + str(random.randint(10000, 99999)),
            lambda u: 'http://' + str(random.randint(100,255)) + '.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255)) + '.' + str(random.randint(1,254)) + '/login.php',
            lambda u: u.replace('.com', '.com-verify.info'),
        ]
    else:
        mods = [
            lambda u: u + '/page/' + str(random.randint(1, 100)),
            lambda u: u.replace('//', '//www.').rstrip('/') + '/help',
            lambda u: u + '?lang=en&ref=' + str(random.randint(1, 999)),
            lambda u: u,
        ]
    return random.choice(mods)(url)

urls, labels = [], []
for _ in range(2500):
    urls.append(augment_url(random.choice(legit_urls), False))
    labels.append(0)
    urls.append(augment_url(random.choice(phishing_urls), True))
    labels.append(1)

df = pd.DataFrame({'URL': urls, 'label': labels})
print(f" Dataset generated: {df.shape}")
print(df['label'].value_counts())

# ── 2. FEATURE ENGINEERING ────────────────────────────────────────────────────
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['domain_length'] = len(tldextract.extract(url).domain)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at'] = url.count('@')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_params'] = url.count('?') + url.count('&')
    features['num_percent'] = url.count('%')
    features['has_https'] = int(url.startswith('https'))
    features['has_ip'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    sus_words = ['login','verify','secure','update','bank',
                 'paypal','account','confirm','click','free',
                 'win','prize','claim','suspend','restore']
    features['sus_word_count'] = sum(w in url.lower() for w in sus_words)
    ext = tldextract.extract(url)
    features['subdomain_depth'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.info', '.win', '.net']
    features['suspicious_tld'] = int(any(url.endswith(t) or t + '/' in url for t in suspicious_tlds))
    return features

print("Extracting features...")
feature_df = pd.DataFrame([extract_features(u) for u in df['URL']])

# ── 3. TRAIN ─────────────────────────────────────────────────────────────────
X = feature_df
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training model...")
model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# ── 4. EVALUATE ───────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
print(f"\n Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

# ── 5. SAVE ───────────────────────────────────────────────────────────────────
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(list(X.columns), 'feature_names.pkl')
print("\n Model saved! Ready for second deployment.")