from collections import defaultdict

def detect_threats(parsed_logs):
    threats = []
    
    ip_count = defaultdict(int)
    failed_logins = defaultdict(int)
    url_access = defaultdict(set)

    for log in parsed_logs:
        ip = log["ip"]
        ip_count[ip] += 1

        if log["status"] in [401, 403]:
            failed_logins[ip] += 1

        url_access[ip].add(log["endpoint"])

        # Sensitive access
        sensitive = ["/admin", ".env", ".git", "/config", "/backup"]
        if any(s in log["endpoint"] for s in sensitive):
            threats.append({
                "ip": ip,
                "attack": "Sensitive Access",
                "owasp": "A05: Security Misconfiguration",
                "count": 1
            })

    # Brute force
    for ip, count in failed_logins.items():
        if count > 5:
            threats.append({
                "ip": ip,
                "attack": "Brute Force",
                "owasp": "A07: Authentication Failure",
                "count": count
            })

    # Scanning
    for ip, urls in url_access.items():
        if len(urls) > 10:
            threats.append({
                "ip": ip,
                "attack": "Scanning Activity",
                "owasp": "A01: Broken Access Control",
                "count": len(urls)
            })

    # Rate limiting
    for ip, count in ip_count.items():
        if count > 50:
            threats.append({
                "ip": ip,
                "attack": "High Traffic",
                "owasp": "A10: Monitoring Failure",
                "count": count
            })

    return threats