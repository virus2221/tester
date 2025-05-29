from flask import Blueprint, request, jsonify
from joblib import load
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
import tldextract
import requests
import base64
import time

urlcheck_bp = Blueprint('urlcheck', __name__)

# تحميل النموذج مرة واحدة عند استيراد الـ blueprint
model = load("features/model.joblib")

API_KEY = "80622f5e7e38f3b81381aec0be8aa528bf6186411b8dfa92fe9d8084a89b3ddd"

def contains_sensitive_words(text):
    sensitive_words = ['login', 'password', 'admin', 'secure', 'signin', 'account', 'user']
    return sum(1 for word in sensitive_words if word in text.lower())

def is_external_url(url, domain):
    return domain not in url

def analyze_url_features(url):
    features = []

    num_dots = url.count('.')
    features.append(num_dots)

    ext = tldextract.extract(url)
    subdomain_level = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features.append(subdomain_level)

    path_level = len(urlparse(url).path.strip('/').split('/')) if urlparse(url).path else 0
    features.append(path_level)

    url_length = len(url)
    features.append(url_length)

    num_dash = url.count('-')
    features.append(num_dash)

    hostname = urlparse(url).hostname
    num_dash_in_hostname = hostname.count('-') if hostname else 0
    features.append(num_dash_in_hostname)

    num_underscore = url.count('_')
    features.append(num_underscore)

    num_percent = url.count('%')
    features.append(num_percent)

    query = urlparse(url).query
    num_query_components = len(parse_qs(query)) if query else 0
    features.append(num_query_components)

    num_ampersand = url.count('&')
    features.append(num_ampersand)

    num_numeric_chars = len(re.findall(r'\d', url))
    features.append(num_numeric_chars)

    random_string = 1 if len(url) > 50 else 0
    features.append(random_string)

    path = urlparse(url).path
    domain_in_paths = 1 if ext.domain in path else 0
    features.append(domain_in_paths)

    hostname_length = len(hostname) if hostname else 0
    features.append(hostname_length)

    path_length = len(path)
    features.append(path_length)

    query_length = len(query)
    features.append(query_length)

    sensitive_words_count = contains_sensitive_words(url) + contains_sensitive_words(path)
    features.append(sensitive_words_count)

    # خصائص غير مفعلة - مؤقتة بقيمة 0
    features += [0] * 17

    return features

def extract_url_info(url):
    parsed = urlparse(url)
    return {
        "Domain": parsed.netloc,
        "Path": parsed.path,
        "Query": parsed.query,
        "Scheme": parsed.scheme.upper(),
        "Port": parsed.port if parsed.port else ("80" if parsed.scheme == "http" else "443")
    }

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")

def check_virustotal(api_key, url):
    base_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Step 1: Submit the URL
    data = f"url={url}"
    submit_response = requests.post(base_url, headers=headers, data=data)
    if submit_response.status_code != 200:
        return {"error": f"Submission failed: {submit_response.status_code}"}

    # Step 2: Fetch analysis result
    encoded_url = encode_url(url)
    get_url = f"{base_url}/{encoded_url}"
    for _ in range(5):
        get_response = requests.get(get_url, headers=headers)
        if get_response.status_code == 200:
            result = get_response.json()
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats")
            if stats:
                return result
        time.sleep(5)

    return {"error": "Timeout waiting for VirusTotal analysis"}

@urlcheck_bp.route('/urlcheck', methods=['POST'])
def urlcheck_route():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data['url']

    # استخراج ميزات وتحليل النموذج
    features = analyze_url_features(url)
    input_array = np.array(features).reshape(1, -1)
    prediction = model.predict(input_array)[0]  # انتبه هنا للتعامل مع النتيجة حسب موديلك

    # استخراج معلومات URL
    url_info = extract_url_info(url)

    # فحص VirusTotal
    vt_result = check_virustotal(API_KEY, url)
    if "error" in vt_result:
        return jsonify({"error": vt_result["error"]}), 400

    return jsonify({
        "prediction": prediction,
        "url_info": url_info,
        "virustotal_result": vt_result
    })
