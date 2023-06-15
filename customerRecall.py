from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
from dotenv import load_dotenv



load_dotenv()
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')

def send_email(from_email, to_email, subject, content):
    message = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        html_content=content)
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)

# HTML邮件内容
content = """
<html>
<head>
    <title>Technical Support</title>
    <style type="text/css">
        body {font-family: Arial, sans-serif;}
        h2 {color: #4285F4;}
        p {line-height: 1.6;}
    </style>
</head>
<body>
    <h2>亲爱的张先生，</h2>
    <p>感谢您联系我们的技术支持团队。我们已经收到了您的请求，我们的团队正在紧急处理您所反映的问题。</p>
    <p>目前，我们的同事还没有重现这个问题，正在进行进一步排查。我们建议您刷新页面并再次尝试，因为这种情况可能与网络不稳定有关。</p>
    <p>如果刷新页面后问题仍然存在，或者您遇到其他问题，请随时联系我们。我们将尽快解决您的问题。</p>
    <p>非常感谢您的理解和耐心。</p>
    <p>祝好，<br/>mychatgpt.io技术支持团队</p>
    <hr>
    <h2>Dear Rui Zhang,</h2>
    <p>Thank you for contacting our technical support team. We have received your request, and our team is urgently addressing the issue you reported.</p>
    <p>At present, our colleagues have not been able to reproduce the issue and are conducting further investigations. We suggest you refresh the page and try again, as the issue might be related to network instability.</p>
    <p>If the problem persists after refreshing the page, or if you encounter any other issues, please do not hesitate to contact us. We will resolve your issue as soon as possible.</p>
    <p>Thank you very much for your understanding and patience.</p>
    <p>Best regards,<br/>mychatgpt.io Support Team</p>
</body>
</html>
"""
print(SENDGRID_API_KEY)
# 发送邮件
#send_email("support@mychatgpt.io", "zhangrui824@gmail.com", "We have received your technical support request", content)
