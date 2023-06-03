from email import message_from_string
from email.header import decode_header
import re
import whois
from geopy.geocoders import Nominatim
from geopy.geocoders import GeoNames
#from geopy.exc import GeocoderUnavailable
import urllib.parse


#geolocator = Nominatim(user_agent="email_header_analysis")
geolocator = GeoNames(username="emt.geo")


def parse_header(header_value):
    decoded_parts = decode_header(header_value)
    decoded_value = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            decoded_value += part.decode(encoding or "utf-8", errors="ignore")
        else:
            decoded_value += part
    return decoded_value.strip()


def get_geolocation(ip_address):
    try:
        location = geolocator.geocode(ip_address)
        if location:
            return location.address
    except GeocoderUnavailable:
        pass
    return "Geolocation information not available"


def perform_whois_lookup(domain):
    w = whois.whois(domain)
    return {
        "Registrar": w.registrar,
        "Creation Date": w.creation_date,
        "Expiration Date": w.expiration_date,
        "Name Servers": w.name_servers,
        "Registrant": w.registrant,
        "Registrar WHOIS Server": w.registrar_whois_server,
    }


def analyze_email_headers(email_headers):
    headers = message_from_string(email_headers)


    # Extract sender information
    #sender = headers.get("From")
    #sender_name = parse_header(sender) if sender else ""
    #sender_email = re.search('[^<]+@[^>]+', sender).group(0).strip() if sender else ""
    

    # Extract sender information
    sender = headers.get("From")

    # Extract sender name and email separately
    sender_name_match = re.search('(?:"?([^"<]+)"?\s)?(?:<?([^<>]+)>?)', sender)
    sender_name = sender_name_match.group(1).strip() if sender_name_match and sender_name_match.group(1) else ""
    sender_email = sender_name_match.group(2).strip() if sender_name_match and sender_name_match.group(2) else ""

        
    # Extract recipient information
    recipients = headers.get("To")
    recipient_list = re.findall('<([^>]+)>', recipients) if recipients else []
    recipient_emails = [recipient.strip() for recipient in recipient_list]


    # Extract subject
    subject = parse_header(headers.get("Subject", ""))

    # Check for known legitimate email domains
    legitimate_domains = ["example.com", "trusteddomain.com"]
    sender_domain = re.search('@([\w.-]+)', sender_email).group(1) if sender_email and re.search('@([\w.-]+)', sender_email) else ""
    is_legitimate = sender_domain in legitimate_domains if sender_domain else False
    

    # Check SPF and DKIM validation
    passed_spf = "pass" in headers.get("Authentication-Results", "")
    passed_dkim = "pass" in headers.get("DKIM-Signature", "")

    # Check for common signs of phishing or spam emails
    has_phishing_signs = False
    suspicious_links = []

    if "X-Spam-Flag" in headers:
        spam_flag = headers["X-Spam-Flag"]
        if spam_flag.lower() == "yes":
            has_phishing_signs = True

    if "Content-Type" in headers and headers["Content-Type"].startswith("text/html"):
        body = headers.get_payload()
        urls = re.findall('href=[\'"]?([^\'" >]+)', body)
        for url in urls:
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.scheme and parsed_url.netloc:
                suspicious_links.append(url)

    # Extract Received headers and geolocation information
    received_headers = headers.get_all("Received", [])
    ip_addresses = extract_ip_addresses(received_headers)
    received_locations = [get_geolocation(ip_address) for ip_address in ip_addresses]
    
    # Extract Received headers and geolocation information
    #received_headers = headers.get_all("Received", [])
    #ip_addresses = extract_ip_addresses(received_headers)
    #received_locations = [get_geolocation(ip_address) for ip_address in ip_addresses]


    # Extract sender domain WHOIS information
    whois_info = {}
    if sender_domain:
        whois_info = perform_whois_lookup(sender_domain)

    # Prepare breakdown of information
    breakdown = {
        "Sender Name": sender_name,
        "Sender Email": sender_email,
        "Recipients": recipient_emails,
        "Subject": subject,
        "Legitimate": is_legitimate,
        "SPF Passed": passed_spf,
        "DKIM Passed": passed_dkim,
        "Received Headers": received_headers,
        "IP Addresses": ip_addresses,
        "Received Locations": received_locations,
        "Sender Domain WHOIS Info": whois_info,
        "Has Phishing Signs": has_phishing_signs,
        "Suspicious Links": suspicious_links,
    }

    return breakdown


def extract_ip_addresses(headers):
    ip_addresses = []
    for header in headers:
        match = re.search(r'\[(.*?)\]', header)
        ip_address = match.group(1) if match else "Unknown"
        ip_addresses.append(ip_address)
    return ip_addresses

