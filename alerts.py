from alert_system import AlertSystem

def send_alerts(threats):
    alert = AlertSystem(
        smtp_server="smtp.gmail.com",
        port=465,
        username="ittishaharpavat17@gmail.com",
        password="ittisi2005",
        sender_email="ittishaharpavat17@gmail.com",
        recipient_email="ittishaharpavat17@gmail.com"
    )

    for t in threats:
        if t["risk"] == "High":
            alert.send_alert(
                subject="🚨 High Risk Threat Detected",
                message_body=f"""
                <h3>Threat Detected</h3>
                <p>IP: {t['ip']}</p>
                <p>Type: {t['attack']}</p>
                <p>Risk: {t['risk']}</p>
                """
            )