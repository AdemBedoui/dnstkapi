from flask import Flask, request, jsonify
import socket
import re
import whois  # This is the python-whois library
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

def get_ip(domain):
    """Get IP address of the domain."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_reverse_dns(ip):
    """Get reverse DNS (PTR record) of an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def get_dns_records(domain, record_type):
    """Retrieve DNS records of a specific type."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        return []

def get_specific_record(domain, record_type, record_name):
    """Retrieve specific DNS record based on the provided name (e.g., DKIM, DMARC)."""
    try:
        import dns.resolver
        query = f"{record_name}.{domain}"
        answers = dns.resolver.resolve(query, record_type)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        return []

def get_whois_info(domain):
    """Extract WHOIS info: registration date, expiration date, registrant name, and registrar name using python-whois."""
    try:
        w = whois.whois(domain)
        
        # Registration Date
        reg_date = w.creation_date if isinstance(w.creation_date, str) else None
        
        # Expiration Date
        exp_date = w.expiration_date if isinstance(w.expiration_date, str) else None
        
        # Registrant Name
        registrant_name = w.registrant_name
        
        # Registrar Name
        registrar_name = w.registrar
        
        return {
            "registration_date": reg_date,
            "expiration_date": exp_date,
            "registrant_name": registrant_name,
            "registrar_name": registrar_name
        }
    except Exception as e:
        print(f"WHOIS lookup error: {e}")
    return None

@app.route('/api/check-domain', methods=['POST'])
def check_domain():
    """Check domain details and return DNS and WHOIS information."""
    data = request.get_json()
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    ip = get_ip(domain)
    reverse_dns = get_reverse_dns(ip) if ip else None
    whois_info = get_whois_info(domain)

    # Get the SPF, DKIM, and DMARC records separately
    spf = get_dns_records(domain, "TXT")  # We'll query all TXT records to capture SPF
    dkim = get_specific_record(domain, "TXT", "default._domainkey")  # DKIM with the default selector
    dmarc = get_specific_record(domain, "TXT", "_dmarc")  # DMARC record

    # Safely handle whois_info in case it is None
    registrant_name = whois_info.get("registrant_name").upper() if whois_info and whois_info.get("registrant_name") else None
    registrar_name = whois_info.get("registrar_name").upper() if whois_info and whois_info.get("registrar_name") else None
    registration_date = whois_info.get("registration_date") if whois_info else None
    expiration_date = whois_info.get("expiration_date") if whois_info else None

    response = {
        "domain": domain,
        "status": "Registered" if ip else "Available",
        "A": get_dns_records(domain, "A"),
        "MX": get_dns_records(domain, "MX"),
        "SPF": spf,
        "DKIM": dkim,
        "DMARC": dmarc,
        "reverse_dns": reverse_dns,
        "registration_date": registration_date,
        "expiration_date": expiration_date,
        "registrant_name": registrant_name,
        "registrar_name": registrar_name,
        "nameservers": get_dns_records(domain, "NS")
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
