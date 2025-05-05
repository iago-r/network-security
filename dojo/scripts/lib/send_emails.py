import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time

from .settings import SENDER, SMTP_PASS, SMTP_PORT, SMTP_SERVER, SMTP_USER, USERS_FILE


# cunha: convert to template-strings when we migrate to Python 3.14
# https://peps.python.org/pep-0750/
EMAIL_TEMPLATE = """\
Olá, {name}!

Seja bem vindo ao time do GT-Crivo. Como mencionado anteriormente, iremos realizar análises de vulnerabilidades, classificando-as segundo sua severidade.

Preparamos uma playlist no Youtube onde colocamos vídeos introdutórios sobre gerência de vulnerabilidades, metadados mantidos pela comunidade de segurança (como índices de severidade CVSS e EPSS) e uma introdução às extensões que adicionamos ao DefectDojo:

https://[...]

Durante a análise de vulnerabilidades, considere que:
Os scans foram realizados em uma empresa com diversos departamentos.
A empresa possui um firewall externo que bloqueia conexões externas; porém, portas podem ser liberadas no firewall externo quando necessário.
A varredura foi realizada a partir de um dispositivo dentro da empresa (isto é, dentro do firewall), o que dá um nível de acesso maior à varredura do que um adversário externo teria.

O sistema de gerência de vulnerabilidades está executando em {URL}. Para que você possa começar, criamos uma conta exclusiva para você com as seguintes credenciais:

Usuário: {email}
Senha: {password}

Por razões de segurança, recomendamos que você altere sua senha na primeira vez que acessar sua conta.

Selecionamos um conjunto de 30 vulnerabilidades de diferentes tipos para você analisar. Se precisar de ajuda ou tiver dúvidas, estamos à disposição.

Após a realização dos experimentos iremos compartilhar um formulário de feedback e enviaremos um relatório comparando suas análises com as realizadas pelos outros participantes do programa Hackers do Bem.

Seja muito bem-vindo(a)!
Equipe GT Crivo
"""


def send_email(server, name, email, password):
    email_body = EMAIL_TEMPLATE.format(name=name, email=email, password=password)

    msg = MIMEMultipart()
    msg["From"] = SENDER
    msg["To"] = email
    msg["Subject"] = "Bem-vindo(a) ao DefectDojo Crivo!"
    msg.attach(MIMEText(email_body, "plain"))

    try:
        server.sendmail(SENDER, email, msg.as_string())
        print(f"Email sent to {name} <{email}>")
    except Exception as e:
        print(f"Error sending email to {name} <{email}>: {e}")


def send_emails():
    with open(USERS_FILE, "r", encoding="utf-8") as file:
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)

                for line in file:
                    name, email, password = map(str.strip, line.split(","))
                    send_email(server, name, email, password)
                    time.sleep(10)
        except Exception as e:
            print(f"Error: {e}")
