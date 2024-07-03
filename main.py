import re
import dns.resolver
import smtplib
import socket
import pandas as pd
import logging
from validate_email_address import validate_email

# Configuración del registro de errores
logging.basicConfig(filename='email_verifier.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Listas de dominios y correos (personalizables)
disposable_domains = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com"
}
role_based_emails = ["admin", "administrator", "contact", "info", "marketing", "sales", "support", "help", "office"]
spam_trap_domains = ["spamtraps.com", "spam.example.com"]  # Reemplaza con una lista real

# Funciones de verificación
def is_valid_email_format(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def has_mx_record(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return False

def is_disposable_email(email):
    return email.split('@')[1] in disposable_domains

def is_role_based_email(email):
    return email.split('@')[0] in role_based_emails

def is_spam_trap_domain(domain):
    return domain in spam_trap_domains

def smtp_check(email, retries=3, timeout=5, sender_addresses=["info@tudominio.com", "noreply@tudominio.com"]):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, 
            dns.resolver.NoNameservers, socket.error) as e:
        logging.error(f"Error de DNS o socket: {e}")
        return False

    for attempt in range(retries):
        for sender in sender_addresses:
            for port in [25, 587, 465]:
                try:
                    with smtplib.SMTP(timeout=timeout) as server:
                        server.connect(mx_record, port)
                        server.ehlo_or_helo_if_needed()
                        server.mail(sender)
                        code, message = server.rcpt(email)
                        if code == 250:
                            return True
                        elif code in (450, 550):
                            decoded_message = message.decode('utf-8', errors='replace')
                            if "mailbox unavailable" in decoded_message.lower() or "user unknown" in decoded_message.lower():
                                return "🔴 Posible catch-all (error SMTP: buzón no disponible o usuario desconocido)"
                            else:
                                return "🔴 Posible catch-all (error SMTP)"
                except (smtplib.SMTPException, socket.error) as e:
                    logging.error(f"Error de SMTP o socket: {e}")

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
    return smtp_result if isinstance(smtp_result, str) else ("🟢 Correo válido" if smtp_result else "🔴 Dirección de correo inválida")

# Menú principal y ejecución
def main():
    while True:
        print("\n--- Verificador de Correos Electrónicos ---")
        print("1. Verificar un solo correo")
        print("2. Verificar una base de correos (archivo CSV)")
        print("3. Salir")

        opcion = input("Elija una opción: ")

        if opcion == '1':
            email = input("Ingrese el correo electrónico a verificar: ")
            resultado = verify_email(email)
            print(f"{email}: {resultado}")
        elif opcion == '2':
            archivo_csv = input("Ingrese el nombre del archivo CSV a verificar (por ejemplo, base.csv): ")
            try:
                emails_df = pd.read_csv(archivo_csv, encoding='utf-8')
            except FileNotFoundError:
                print(f"🔴 Error: No se encontró el archivo '{archivo_csv}'")
            except UnicodeDecodeError:
                print(f"🔴 Error: El archivo '{archivo_csv}' no tiene codificación UTF-8 válida.")
            except KeyError:
                print(f"🔴 Error: La columna 'email' no existe en el archivo '{archivo_csv}'")
            except pd.errors.EmptyDataError:
                print(f"🔴 Error: El archivo '{archivo_csv}' está vacío.")
            except Exception as e:  # Captura cualquier otra excepción inesperada
                print(f"🔴 Error inesperado: {e}")
            else:  # Si no hubo errores, procede con la verificación
                results = []
                total_emails = len(emails_df)
                for index, row in emails_df.iterrows(): 
                    email = row['email']
                    resultado = verify_email(email)
                    results.append((email, resultado))
    
                    # Cálculo y visualización del porcentaje de completado
                    porcentaje_completado = round((index + 1) / total_emails * 100, 2)
                    print(f"{email}: {resultado} ({porcentaje_completado}% completado)") 
    
                results_df = pd.DataFrame(results, columns=['email', 'verification_result'])
                results_df.to_csv('verified_emails.csv', index=False)
                print("Verificación completa. Los resultados se han guardado en 'verified_emails.csv'.")

        elif opcion == '3':
            break
        else:
            print("🔴 Opción inválida. Por favor, elija 1, 2 o 3.")

if __name__ == "__main__":
    main()
