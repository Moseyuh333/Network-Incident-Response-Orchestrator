import socket

def run(context):
    domain = context.get('domain')
    if not domain:
        return {"error": "Domain name is required"}
    
    try:
        # Resolve the domain to one or more IP addresses
        result = socket.getaddrinfo(domain, None)
        ips = [info[4][0] for info in result]
        # Remove duplicates
        unique_ips = list(set(ips))
        
        return {
            "status": "success",
            "domain": domain,
            "resolved_ips": unique_ips
        }
    except socket.gaierror:
        return {"status": "error", "message": "DNS resolution failed for domain: " + domain}
    except Exception as e:
        return {"status": "error", "message": str(e)}