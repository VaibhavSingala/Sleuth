import requests
from requests.exceptions import RequestException

def check_ssl_config(url: str):
    """
    Checks various SSL/TLS configuration aspects for a given URL, including 
    HTTPS usage, supported TLS versions, cipher suites, HSTS presence, and certificate details.
    """
    print(f"--- Starting SSL Configuration Check for: {url} ---")
    
    try:
        # Use HEAD request to be lightweight, but GET is safer if headers are tricky
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)

        print("\n[✅] Connection Successful!")
        print(f"  Status Code: {response.status_code}")
        print(f"  Protocol Used: {response.url.split('//')[-1].split('/')[0]} (Inferred from request)")

        # 1. Check for HTTPS usage (already mostly done, but good to confirm)
        if response.url.startswith("https://"):
            print("  [✅] Protocol: HTTPS is in use.")
        else:
            print("  [⚠️] Protocol: HTTP is in use. Consider enforcing HTTPS.")

        # 2. Check HSTS (Strict-Transport-Security) header
        hsts = response.headers.get('strict-transport-security')
        if hsts:
            print(f"  [✅] HSTS Present: {hsts}")
        else:
            print("  [❌] HSTS Missing: No Strict-Transport-Security header found.")

        # 3. Check Certificate Details
        cert = response.connection.get_extra_info('peercert')
        if cert:
            import ssl
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            try:
                cert_obj = x509.load_pem_x509_certificate(cert.encode('utf-8'), default_backend())
                
                # Issuer and Subject
                issuer = cert_obj.issuer.rfc4514_string()
                subject = cert_obj.subject.rfc4514_string()
                print("\n[📜] Certificate Details:")
                print(f"  Subject (Common Name): {cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}")
                print(f"  Issuer: {issuer}")
                print(f"  Valid From: {cert_obj.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  Valid Until: {cert_obj.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')}")

            except Exception as e:
                print(f"\n[⚠️] Certificate Parsing Error: Could not fully parse certificate details. ({e})")
        else:
            print("\n[❌] Certificate Details: No peer certificate information available.")


        # 4. Check TLS Versions and Cipher Suites (Requires deeper inspection, but we can get a good summary)
        ssl_socket = response.connection.sock
        if ssl_socket:
            # Get supported protocols/versions
            supported_protocols = [str(proto) for proto in ssl_socket.cipher()]
            print("\n[⚙️] TLS Configuration:")
            print(f"  Cipher Suite Used: {ssl_socket.cipher()}")
            print(f"  Supported Protocols (Negotiated): {', '.join(supported_protocols)}")

            # A quick check for modern protocols
            if 'TLSv1.3' in supported_protocols or 'TLSv1.2' in supported_protocols:
                print("  [✅] Modern TLS Supported: At least TLS 1.2 is active.")
            else:
                 print("  [⚠️] Modern TLS Warning: Only older protocols (e.g., SSLv3, TLSv1.0) might be active.")

    except requests.exceptions.HTTPError as e:
        print(f"\n[❌] HTTP Error Occurred: {e}")
        print(f"  Response URL: {response.url}")
    except RequestException as e:
        print(f"\n[❌] Connection/Request Error: Could not reach the site.")
        print(f"  Error Details: {e}")

# Example usage (will be called by the tool runner)
if __name__ == '__main__':
    check_ssl_config("https://www.google.com") # Test with a known good site
    # check_ssl_config("https://example.com/")

