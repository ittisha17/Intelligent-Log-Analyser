import re

def parse_logs(log_lines):
    parsed = []

    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+)'

    for line in log_lines:
        match = re.match(pattern, line)
        if match:
            ip, timestamp, request, status = match.groups()

            method = request.split()[0] if request else ""
            endpoint = request.split()[1] if len(request.split()) > 1 else ""

            parsed.append({
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "status": int(status)
            })

    return parsed