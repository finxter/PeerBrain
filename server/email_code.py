import os
from dotenv import load_dotenv
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

#---LOAD ENV VARS---#
load_dotenv()

#---MAIL VARS---#
SMTP_SERVER = "send.one.com"
SMTP_PORT = 465
SENDER = os.environ.get("EMAIL_SENDER")
PASSWORD = os.environ.get("EMAIL_PASS")
url = 'https://peerbrain.teckhawk.be/'
#url = 'http://127.0.0.1:8000/'
link_text = 'CONFIRM ACCOUNT'

#---FUNCTIONS---#
def html_mail(receiver:str, username:str, token:str):
        
    message = MIMEMultipart("alternative")
    message["Subject"] = f"Confirm your email for your Peerbrain account"
    message["From"] = SENDER
    message["To"] = receiver

    # Create the plain-text and HTML version of your message
    text = f"""\
    Dear {username}, \n
    
    Please click the link below to confirm your account: \n \n
    
    {url}
        
    Sincerely,
    
    Team Peerbrain
    """
    html = f"""\
    <html>
    <body>
        <p>Dear {username},<br><br>
        Please click the link below to confirm your account: <br>
        <br>
        
        <b><a href="{url}confirm-email?token={token}&username={username}">{link_text}</a></b>
        
        <br>  <br> 
        Sincerely,<br>
        <br>
        Team Peerbrain
        </p>
    </body>
    </html>
    """

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT , context=context) as server:
        server.login(SENDER, PASSWORD)
        server.sendmail(
            SENDER, receiver, message.as_string()
        )
    
    print(f"Email sent to {receiver}")

