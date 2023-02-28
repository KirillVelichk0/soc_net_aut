import json
import smtplib as smtp
import sys
from email.mime.text import MIMEText
from email.header import Header
try:
    try:
        with open('../configs/emailSenderConfig.json') as jConfig:
            configDict = json.load(jConfig)
        login = configDict['emailSenderLogin']
        pathToPass = configDict['pathToPass']
    except:
        sys.exit(3)

    with open(pathToPass) as file:
        lines = [line.rstrip() for line in file]
    password = lines[0]
    argvData = sys.argv
    try:
        server = smtp.SMTP_SSL('smtp.yandex.ru', 587)
    except smtp.SMTPConnectError:
        sys.exit(1)
    server.starttls()
    try:
        server.login(login, password)
    except smtp.SMTPAuthenticationError:
        sys.exit(2)

    subject = 'Account registration'
    text = str(argvData[2])
    try:
        mime = MIMEText(text, 'plain', 'utf-8')
        mime['Subject'] = Header(subject, 'utf-8')
        server.sendmail(login, str(argvData[1]), mime.as_string())
    except:
        sys.exit(4)
except:
    sys.exit(322)