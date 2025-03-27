# Import necessary libraries
import requests
import whois
import re
import time
from bs4 import BeautifulSoup

# Suspicious Keywords Check
def check_suspicious_keywords(url):
    suspicious_keywords = ["secure", "banking", "login", "update", "verify", "account", "paypal", "free", "offer"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return True
    return False

# Domain Age Check
def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        # Handle cases where creation_date may be a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        return creation_date
    except Exception as e:
        print(f"[Error] Unable to fetch domain age: {e}")
        return None

# Check if URL uses HTTPS
def check_https(url):
    return url.startswith("https")

# Extract Links from Website
def extract_links(url):
    try:
        response = requests.get(url, timeout=10)  # Add timeout for reliability
        response.raise_for_status()  # Raise error for failed requests
        soup = BeautifulSoup(response.text, "html.parser")
        links = [a['href'] for a in soup.find_all('a', href=True)]
        return links
    except requests.RequestException as e:
        print(f"[Error] Unable to fetch links: {e}")
        return []

# Check URL with VirusTotal
def check_virustotal(url, api_key):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key
    }
    data = {"url": url}

    try:
        # Submit the URL for scanning
        response = requests.post(vt_url, headers=headers, data=data)
        if response.status_code != 200:
            print("[Error] VirusTotal request failed. Check API key or quota.")
            return None
        
        result = response.json()
        analysis_id = result.get("data", {}).get("id")
        if not analysis_id:
            print("[Error] Invalid VirusTotal response format.")
            return None

        # Wait before fetching the report (allows VirusTotal to analyze)
        time.sleep(10)  # Adjust if necessary

        # Get the scan results
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code == 200:
            report_data = report_response.json()
            stats = report_data.get("data", {}).get("attributes", {}).get("stats", {})

            malicious_count = stats.get("malicious", 0)
            return malicious_count > 0  # Returns True if malicious, False if safe

    except requests.RequestException as e:
        print(f"[Error] VirusTotal API request failed: {e}")

    return None  # Unable to determine

# Main function for URL Analysis
def analyze_url(url, api_key):
    url = url.strip()  # Remove leading/trailing spaces
    print(f"\n🔍 Analyzing URL: {url}\n")

    # Check HTTPS
    if not check_https(url):
        print("[Warning] The URL does not use HTTPS! 🚨")

    # Check Suspicious Keywords
    if check_suspicious_keywords(url):
        print("[Warning] The URL contains suspicious keywords! ⚠️")

    # Extract Domain Name
    try:
        domain = re.sub(r"https?://", "", url).split("/")[0]  # Extract domain name
    except Exception:
        print("[Error] Invalid URL format!")
        return

    # Check Domain Age
    age = get_domain_age(domain)
    if age:
        print(f"🗓️ Domain Creation Date: {age}")
    else:
        print("[Warning] Unable to fetch domain age. It may be newly registered! 🚨")

    # Extract Links
    links = extract_links(url)
    print(f"🔗 Total links found on the page: {len(links)}")

    # Check VirusTotal
    vt_result = check_virustotal(url, api_key)
    
    if vt_result is None:
        print("\n[Error] Could not retrieve VirusTotal data.")
    elif vt_result:
        print("\n🚨 Link is **Suspicious!** ⚠️")
    else:
        print("\n✅ Link is **Safe!**")

    print("\n✅ Analysis Complete!")

# Test the Program
if __name__ == "__main__":
    api_key = "655ef81c116b24717743107708df7f7d27879255e43b344d3d8c6249df2f51ab"  # Replace with your actual API key
    url = input("Enter a URL to check: ").strip()
    analyze_url(url, api_key)
