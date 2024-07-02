import re
import dns.resolver
import smtplib
import socket
import pandas as pd
from validate_email_address import validate_email

# Lista de dominios desechables conocidos (algunos ejemplos, se pueden expandir según sea necesario)
disposable_domains = {
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
    "yopmail.com"
    # Añadir más dominios desechables según sea necesario
}

# Lista de correos electrónicos basados en roles comunes
role_based_emails = [
    "admin", "administrator", "contact", "info", "marketing",
    "sales", "support", "help", "office"
]

def is_valid_email_format(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def has_mx_record(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return len(records) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return False

def is_disposable_email(email):
    domain = email.split('@')[1]
    return domain in disposable_domains

def is_role_based_email(email):
    local_part = email.split('@')[0]
    return local_part in role_based_emails

def smtp_check(email, retries=1, timeout=5):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, socket.error) as e:
        print(f"DNS or socket error: {e}")
        return False

    sender_addresses = ['mauro.vaquero@comprandoengrupo.net']
    ports = [25, 587, 465]

    for attempt in range(retries):
        for sender in sender_addresses:
            for port in ports:
                try:
                    server = smtplib.SMTP(timeout=timeout)
                    server.connect(mx_record, port)
                    server.ehlo_or_helo_if_needed()
                    server.mail(sender)
                    code, message = server.rcpt(email)
                    server.quit()

                    if code == 250:
                        return True
                except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPHeloError, smtplib.SMTPSenderRefused) as e:
                    print(f"SMTP error on attempt {attempt + 1} with sender {sender} on port {port}: {e}")
                except (socket.error, socket.timeout) as e:
                    print(f"Socket error on attempt {attempt + 1} with sender {sender} on port {port}: {e}")
                    continue  # Continuar con el siguiente puerto
    return False

def verify_email(email):
    if not is_valid_email_format(email):
        return "🔴 Formato inválido"

    domain = email.split('@')[1]

    if not has_mx_record(domain):
        return "🔴 Sin registro MX"

    if is_disposable_email(email):
        return "🔴 Correo desechable"

    if is_role_based_email(email):
        return "🔴 Correo basado en rol"

    if not smtp_check(email):
        return "🔴 Dirección de correo inválida"

    return "🟢 Correo válido"

# Leer el archivo CSV
try:
    emails_df = pd.read_csv('base_rebotada.csv', encoding='utf-8')
except UnicodeDecodeError:
    emails_df = pd.read_csv('base_rebotada.csv', encoding='latin1')

# Suponiendo que la columna con los correos electrónicos se llama 'email'
emails = emails_df['email'].tolist()

# Crear listas para almacenar los resultados y los correos válidos
results = []
valid_emails = []

# Verificar cada correo electrónico y almacenar el resultado
for email in emails:
    result = verify_email(email)
    results.append((email, result))
    print(f"{email}: {result}")  # Mostrar el resultado en consola a medida que se verifica cada correo

    if result == "Correo válido":
        valid_emails.append(email)

# Crear un DataFrame con los resultados
results_df = pd.DataFrame(results, columns=['email', 'verification_result'])

# Guardar los resultados en un nuevo archivo CSV
results_df.to_csv('verified_emails.csv', index=False)

# Crear un DataFrame solo con los correos válidos
valid_emails_df = pd.DataFrame(valid_emails, columns=['email'])

# Guardar los correos válidos en un nuevo archivo CSV
valid_emails_df.to_csv('valid_emails_only.csv', index=False)

print("Verificación completa. Los resultados se han guardado en 'verified_emails.csv'. Los correos válidos se han guardado en 'valid_emails_only.csv'.")