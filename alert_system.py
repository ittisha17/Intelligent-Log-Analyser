import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertSystem:
    def __init__(self, smtp_server, port, username, password, sender_email, recipient_email):
        """Initialize the alert system with SMTP server details"""
        self.smtp_server = smtp_server
        self.port = port
        self.username = username
        self.password = password
        self.sender_email = sender_email
        self.recipient_email = recipient_email
        
    def send_alert(self, subject, message_body, html=True):
        """Send an email alert with the given subject and message"""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.sender_email
            msg["To"] = self.recipient_email
            
            # Create the message body
            if html:
                content = MIMEText(message_body, "html")
            else:
                content = MIMEText(message_body, "plain")
            
            msg.attach(content)
            
            # Connect to SMTP server and send email
            with smtplib.SMTP_SSL(self.smtp_server, self.port) as server:
                server.login(self.username, self.password)
                server.sendmail(
                    self.sender_email, self.recipient_email, msg.as_string()
                )
            return True
        except Exception as e:
            print(f"Error sending email alert: {e}")
            return False
            
    def send_brute_force_alert(self, ip, failed_attempts, timestamp):
        """Send alert for brute force attack"""
        subject = f"⚠️ SECURITY ALERT: Brute Force Attack Detected"
        message = f"""
        <html>
        <body>
            <h2>Security Alert: Brute Force Attack Detected</h2>
            <p>The system has detected a possible brute force attack:</p>
            <ul>
                <li><strong>IP Address:</strong> {ip}</li>
                <li><strong>Failed Attempts:</strong> {failed_attempts}</li>
                <li><strong>Timestamp:</strong> {timestamp}</li>
            </ul>
            <p>Please investigate this activity immediately.</p>
        </body>
        </html>
        """
        return self.send_alert(subject, message)
        
    def send_unauthorized_access_alert(self, ip, url, method, timestamp):
        """Send alert for unauthorized access attempt"""
        subject = f"⚠️ SECURITY ALERT: Unauthorized Access Attempt"
        message = f"""
        <html>
        <body>
            <h2>Security Alert: Unauthorized Access Attempt</h2>
            <p>The system has detected an unauthorized access attempt:</p>
            <ul>
                <li><strong>IP Address:</strong> {ip}</li>
                <li><strong>URL:</strong> {url}</li>
                <li><strong>Method:</strong> {method}</li>
                <li><strong>Timestamp:</strong> {timestamp}</li>
            </ul>
            <p>Please investigate this activity immediately.</p>
        </body>
        </html>
        """
        return self.send_alert(subject, message)