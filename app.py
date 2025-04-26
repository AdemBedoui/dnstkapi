from flask import Flask, request, jsonify
import socket
import subprocess
import dns.resolver
import re
from flask_cors import CORS
#
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
        answers = dns.resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        return []

def get_whois_info(domain):
    """Extract WHOIS info: registration date, expiration date, registrant name (owner), and registrar name."""
    try:
        # Run the whois command
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        output = result.stdout
        # Debug: print WHOIS output (for development)
        print("WHOIS output:", output)
        
        # Registration Date
        reg_date = None
        reg_date_patterns = [
            r"creation date[^\d]*(\d{2}-\d{2}-\d{4})",
            r"created[^\d]*(\d{2}-\d{2}-\d{4})",
            r"registered on[^\d]*(\d{2}-\d{2}-\d{4})",
            r"domain registration date[^\d]*(\d{2}-\d{2}-\d{4})"
        ]
        for pat in reg_date_patterns:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                reg_date = m.group(1).strip()
                break
        
        # Expiration Date
        exp_date = None
        exp_date_patterns = [
            r"expiration date[^\d]*(\d{2}-\d{2}-\d{4})",
            r"expires[^\d]*(\d{2}-\d{2}-\d{4})"
        ]
        for pat in exp_date_patterns:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                exp_date = m.group(1).strip()
                break
        
        # Registrant Name:
        # Look for a line "Owner Contact" then on the next lines find "Name:" and "First name:"
        registrant_name = None
        owner_match = re.search(r"owner contact\s*\n\s*name\.*:\s*(.+)", output, re.IGNORECASE)
        first_match = re.search(r"first name\.*:\s*(.+)", output, re.IGNORECASE)
        if owner_match:
            registrant_name = owner_match.group(1).strip()
        if first_match:
            first_name = first_match.group(1).strip()
            if registrant_name:
                # Combine only if first name isn't already part of registrant_name
                if first_name.lower() not in registrant_name.lower():
                    registrant_name = f"{registrant_name} {first_name}"
            else:
                registrant_name = first_name
        
        # Registrar Name:
        registrar_match = re.search(r"registrar\.*:\s*(.+)", output, re.IGNORECASE)
        registrar_name = registrar_match.group(1).strip() if registrar_match else None

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

    response = {
        "domain": domain,
        "status": "Registered" if ip else "Available",
        "A": get_dns_records(domain, "A"),
        "MX": get_dns_records(domain, "MX"),
        "SPF": get_dns_records(domain, "TXT"),  # SPF records are stored in TXT
        "DKIM": get_dns_records(domain, "TXT"),  # DKIM also in TXT
        "reverse_dns": reverse_dns,
        "registration_date": whois_info.get("registration_date") if whois_info else None,
        "expiration_date": whois_info.get("expiration_date") if whois_info else None,
        "registrant_name": whois_info.get("registrant_name").upper() if whois_info.get("registrant_name") else None,
        "registrar_name": whois_info.get("registrar_name").upper() if whois_info.get("registrar_name") else None,
        "nameservers": get_dns_records(domain, "NS")
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
