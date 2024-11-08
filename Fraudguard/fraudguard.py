import os
import requests
import tldextract
import re
import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load your Google Safe Browsing API key from an environment variable
api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

def check_virustotal(url):
    vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {
        'apikey': vt_api_key,
        'resource': url,
        'allinfo': False
    }
    
    try:
        response = requests.get(vt_url, params=params)
        response.raise_for_status()
        data = response.json()
        if data['response_code'] == 1:
            positives = data['positives']
            total = data['total']
            if positives > 0:
                return f"URL detected as malicious by {positives} out of {total} scanners."
            else:
                return "URL is clean according to VirusTotal."
        else:
            return "No report available for this URL."
    except requests.RequestException as e:
        logging.error(f"Error checking VirusTotal: {e}")
        return "Error checking VirusTotal."

# Load phishing sites from file
def load_phishing_sites():
    file_path = "C:/Users/91878/Desktop/virus/phishing_sites.txt"
    try:
        with open(file_path, 'r') as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        logging.error(f"Error loading phishing sites: {e}")
        return set()

phishing_sites = load_phishing_sites()

def analyze_email_content(email_content):
    spam_keywords = ["win", "free", "urgent", "limited time", "act now", "click here", "special promotion"]
    found_keywords = [keyword for keyword in spam_keywords if keyword in email_content.lower()]
    return found_keywords 
def analyze_url(url):
    parsed_url = urlparse(url)
    domain = tldextract.extract(parsed_url.netloc).domain

    feedback_messages = []
    scraped_content = {}
    links_analysis = []

    # Check against the phishing sites list
    if url in phishing_sites:
        feedback_messages.append("Malicious URL detected (known phishing site).")
    if is_blacklisted(url):
        feedback_messages.append("Malicious URL detected (blacklisted).")
    if check_phishing_indicators(parsed_url):
        feedback_messages.append("Potential phishing attempt detected.")

    vt_feedback = check_virustotal(url)
    feedback_messages.append(vt_feedback)    

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        title = soup.title.string if soup.title else 'No title found'
        meta_description = soup.find("meta", attrs={"name": "description"})
        meta_description_content = meta_description["content"] if meta_description else 'No description found'
        scraped_content = {'title': title, 'description': meta_description_content}

        if check_content_for_suspicious_elements(soup):
            feedback_messages.append("Suspicious content detected.")

        links_analysis = [link.get('href') for link in soup.find_all('a', href=True)]

    except requests.Timeout:
        feedback_messages.append("Request timed out. Please check the URL.")
    except requests.RequestException as e:
        logging.error(f"Error fetching content: {e}")
        feedback_messages.append("Error fetching content.")

    if check_redirects(url):
        feedback_messages.append("URL redirects to another site.")
    if is_new_domain(domain):
        feedback_messages.append("Suspicious domain age detected.")

    if feedback_messages:
        return "Issues detected", "; ".join(feedback_messages), scraped_content, links_analysis

    return "URL appears safe", "No issues detected", scraped_content, []

def is_blacklisted(url):
    if api_key is None:
        logging.error("Google Safe Browsing API key is not set.")
        return False

    sb_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "your_client_id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "PHISHING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {"key": api_key}

    try:
        response = requests.post(sb_url, json=payload, params=params)
        response.raise_for_status()
        data = response.json()
        return "matches" in data and len(data["matches"]) > 0
    except requests.RequestException as e:
        logging.error(f"Error checking blacklist status: {e}")
        return False

def check_phishing_indicators(parsed_url):
    suspicious_tlds = [".ru", ".cn", ".cc", ".top", ".xyz"]
    return (parsed_url.netloc.endswith(tuple(suspicious_tlds)) or 
            re.search(r"[^a-zA-Z0-9\.\-]", parsed_url.netloc) or
            parsed_url.scheme != "https" or
            len(parsed_url.netloc) < 5)

def check_redirects(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return len(response.history) > 0
    except requests.RequestException as e:
        logging.error(f"Error checking redirects: {e}")
        return False

def is_new_domain(domain):
    # Placeholder implementation: assume any domain with fewer than 6 characters is new
    return len(domain) < 6

def check_content_for_suspicious_elements(soup):
    return soup.find("form", action="http://") is not None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email_content = request.form.get('email_content', '')
        url = request.form.get('url', '')
        uploaded_file = request.files.get('file')
        result = None
        feedback = ""
        scraped_content = {}
        links_analysis = []
        analysis_type = ""
        found_keywords = []

        if email_content:
            found_keywords = analyze_email_content(email_content)
            if found_keywords:
                result = "The email content indicates spam."
                feedback = f"Keywords found: {', '.join(found_keywords)}."
            else:
                result = "Email content appears safe."
                feedback = "No spam indicators found."
        elif url:
            result, feedback, scraped_content, links_analysis = analyze_url(url)

        if "indicates spam" in feedback or any(keyword in feedback for keyword in found_keywords):
            feedback = "Spam indicators detected."
            
        return render_template('results.html', result=result, feedback=feedback, scraped_content=scraped_content, links_analysis=links_analysis, analysis_type=analysis_type)

    return render_template('index.html', result=None)
@app.route('/result', methods=['GET'])
def result():
    result_message = "This email may be harmful."
    feedback_message = "Potential phishing attempt detected."
    scraped_content = {"title": "Example Title", "description": "Example description of the scraped content."}
    links_analysis = ["http://maliciouslink.com", "http://example.com"]
    
    return render_template(
        'result.html',
        result=result_message,
        feedback=feedback_message,
        scraped_content=scraped_content,
        links_analysis=links_analysis,
        analysis_type="email"  # Example analysis type
    )

@app.route('/education')
def education():
    return render_template('education.html')

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    feedback_content = request.form.get('feedback_content')
    analysis_type = request.form.get('analysis_type')
    
    # Process the feedback (e.g., save to a database or a file)
    with open('feedback.txt', 'a') as f:
        f.write(f'Feedback for {analysis_type}: {feedback_content}\n')
    
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)