import re
import dns.resolver
import smtplib
import socket
import pandas as pd
from validate_email_address import validate_email

# Lista de dominios desechables conocidos
disposable_domains = {
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
    "yopmail.com"
    # Agrega más dominios desechables según sea necesario
}

# Lista de correos electrónicos basados en roles comunes
role_based_emails = [
    "admin", "administrator", "contact", "info", "marketing",
    "sales", "support", "help", "office"
]

# Lista de dominios trampa conocidos (ejemplo, reemplaza con una lista real)
spam_trap_domains = ["spamtraps.com", "spam.example.com"]

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

def is_spam_trap_domain(domain):
    return domain in spam_trap_domains

def smtp_check(email, retries=3, timeout=5, sender_addresses=["info@tudominio.com", "noreply@tudominio.com"]):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, socket.error) as e:
        print(f"Error de DNS o socket: {e}")
        return False

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
                    elif code in (450, 550):
                        # Decodificamos el mensaje de bytes a una cadena de texto (UTF-8)
                        decoded_message = message.decode('utf-8')
                        if "mailbox unavailable" in decoded_message.lower() or "user unknown" in decoded_message.lower():
                            return "🔴 Posible catch-all (error SMTP: buzón no disponible o usuario desconocido)"
                        else:
                            return "🔴 Posible catch-all (error SMTP)"
                except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPHeloError, smtplib.SMTPSenderRefused) as e:
                    print(f"Error de SMTP en el intento {attempt + 1} con el remitente {sender} en el puerto {port}: {e}")
                except (socket.error, socket.timeout) as e:
                    print(f"Error de socket en el intento {attempt + 1} con el remitente {sender} en el puerto {port}: {e}")
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

    if is_spam_trap_domain(domain):
        return "🔴 Posible correo trampa (dominio sospechoso)"

    smtp_result = smtp_check(email)
    if smtp_result == True:  # Verificamos explícitamente si smtp_result es True
        return "🟢 Correo válido"  # Devolvemos el mensaje formateado
    elif isinstance(smtp_result, str):  # Si es una cadena, es un posible catch-all
        return smtp_result
    else:  # Si es False, es un correo inválido
        return "🔴 Dirección de correo inválida"

# Leer el archivo CSV (asegúrate de tener el archivo 'base_rebotada.csv' en la misma carpeta)
try:
    emails_df = pd.read_csv('base-1.csv', encoding='utf-8')
except UnicodeDecodeError:
    emails_df = pd.read_csv('base-1.csv', encoding='latin1')

# Suponiendo que la columna con los correos electrónicos se llama 'email'
emails = emails_df['email'].tolist()

# Crear listas para almacenar los resultados y los correos válidos
results = []
valid_emails = []

# Verificar cada correo electrónico y almacenar el resultado
for email in emails:
    result = verify_email(email)
    results.append((email, result))
    print(f"{email}: {result}")  # Mostrar el resultado en consola

    if result == "🟢 Correo válido":
        valid_emails.append(email)

# Crear un DataFrame con los resultados
results_df = pd.DataFrame(results, columns=['email', 'verification_result'])

# Guardar los resultados en un nuevo archivo CSV
results_df.to_csv('verified_emails-1.csv', index=False)

# Crear un DataFrame solo con los correos válidos
valid_emails_df = pd.DataFrame(valid_emails, columns=['email'])

# Guardar los correos válidos en un nuevo archivo CSV
valid_emails_df.to_csv('valid_emails_only-1.csv', index=False)

print("Verificación completa. Los resultados se han guardado en 'verified_emails.csv'. Los correos válidos se han guardado en 'valid_emails_only.csv'.")
