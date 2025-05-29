from flask import Blueprint, request, jsonify
from joblib import load
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
import tldextract

phishing_predict_bp = Blueprint('phishing_predict', __name__)
model = load("model.joblib")

def contains_sensitive_words(text):
    sensitive_words = ['login', 'password', 'admin', 'secure', 'signin', 'account', 'user']
    return sum(1 for word in sensitive_words if word in text.lower())

def is_external_url(url, domain):
    return domain not in url

def analyze_url(url):
    features = []

    num_dots = url.count('.')
    features.append(num_dots)

    ext = tldextract.extract(url)
    subdomain_level = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features.append(subdomain_level)

    path_level = len(urlparse(url).path.strip('/').split('/')) if urlparse(url).path else 0
    features.append(path_level)

    features.append(len(url))  # url_length
    features.append(url.count('-'))

    hostname = urlparse(url).hostname
    features.append(hostname.count('-') if hostname else 0)

    features.append(url.count('_'))
    features.append(url.count('%'))

    query = urlparse(url).query
    features.append(len(parse_qs(query)) if query else 0)
    features.append(url.count('&'))
    features.append(len(re.findall(r'\d', url)))
    features.append(1 if len(url) > 50 else 0)

    path = urlparse(url).path
    features.append(1 if ext.domain in path else 0)

    features.append(len(hostname) if hostname else 0)
    features.append(len(path))
    features.append(len(query))

    sensitive_words_count = contains_sensitive_words(url) + contains_sensitive_words(path)
    features.append(sensitive_words_count)

    features += [
        0, 0,  # pct_ext_hyperlinks, pct_ext_resource_urls
        1 if "favicon" in url else 0,
        0,  # insecure_forms
        1 if 'action' in url else 0,
        1 if is_external_url(urlparse(url).geturl(), ext.domain) else 0,
        0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ]

    return features

@phishing_predict_bp.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'Missing URL'}), 400

    features = analyze_url(url)
    input_array = np.array(features).reshape(1, -1)
    prediction = model.predict(input_array)
    return jsonify({'prediction': prediction.tolist()})
