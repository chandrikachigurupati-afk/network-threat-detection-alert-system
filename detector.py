from scapy.all import sniff, IP, TCP, UDP
import smtplib
from datetime import datetime

log_file = "alerts.log"
report_file = "threat_report.txt"

sender_email = "yourmail@gmail.com"
receiver_email ="yourmail@gmail.com"
app_password = "YOUR_PASSWORD_HERE"


def log_alert(message):
    with open(log_file, "a") as file:
        file.write(message + "\n")


def send_email_alert(message):
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, app_password)

        email_message = f"Subject: Network Threat Alert\n\n{message}"

        server.sendmail(
            sender_email,
            receiver_email,
            email_message
        )


print("🛡️ Network Threat Detection Started...")
print("Monitoring network traffic...\n")

packet_count = {}
THRESHOLD = 20
alerted_ips = set()
alerted_ports = set() 

total_packets = 0
threat_count = 0
threat_score = 0


def detect_packet(packet):

    global total_packets
    global threat_count
    global threat_score

    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        total_packets += 1

        packet_count[source_ip] = packet_count.get(source_ip, 0) + 1
        count = packet_count[source_ip]

        alert_message = None

        # High Traffic Detection
        if count >= THRESHOLD and source_ip not in alerted_ips:

            threat_count += 1
            threat_score += 50

            severity = "MEDIUM"
            threat_type = "HIGH TRAFFIC"

            print("🚨 HIGH TRAFFIC DETECTED!")
            print(f"⚠️ Source IP: {source_ip}")
            print(f"📊 Packets detected: {count}")
            print(f"🟠 Severity: {severity}")
            print(f"🛡️ Threat Type: {threat_type}")

            alert_message = (
                f"{datetime.now()} | "
                f"Source: {source_ip} | "
                f"Packets: {count} | "
                f"Severity: {severity} | "
                f"Threat Type: {threat_type} | "
                f"HIGH TRAFFIC DETECTED"
            )

            alerted_ips.add(source_ip)
            

            log_alert(alert_message)
            send_email_alert(alert_message)

        # Protocol and Port Detection
        if TCP in packet:

            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:

            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:

            protocol = "Other"
            source_port = "-"
            destination_port = "-"

        print(
            f"📡 {protocol} | "
            f"{source_ip}:{source_port} → "
            f"{destination_ip}:{destination_port}"
        )

        print(f"📊 Total Packets Captured: {total_packets}")

        # Suspicious Port Detection
        suspicious_ports = [21, 23, 445, 3389]

        if destination_port in suspicious_ports and (source_ip, destination_port) not in alerted_ports:

            threat_count += 1
            threat_score += 30

            severity = "HIGH"
            threat_type = "SUSPICIOUS PORT"

            print("⚠️ SUSPICIOUS PORT DETECTED!")
            print("🚨🚨🚨 REAL-TIME THREAT ALERT 🚨🚨🚨")
            print("⚠️ Immediate attention required!")
            print(f"🚨 Destination Port: {destination_port}")
            print(f"🔴 Severity: {severity}")
            print(f"🛡️ Threat Type: {threat_type}\n")

            alert_message = (
                f"{datetime.now()} | "
                f"Source: {source_ip} | "
                f"Destination: {destination_ip} | "
                f"Protocol: {protocol} | "
                f"Port: {destination_port} | "
                f"Severity: {severity} | "
                f"Threat Type: {threat_type} | "
                f"THREAT DETECTED"
            )

            alerted_ports.add((source_ip, destination_port))

            log_alert(alert_message)
            send_email_alert(alert_message)


sniff(prn=detect_packet, store=False)


print("\n🛡️ Monitoring Stopped")
print(f"📊 Total Packets Captured: {total_packets}")
print(f"🚨 Total Threats Detected: {threat_count}")
print(f"🎯 Total Threat Score: {threat_score}")
with open(report_file, "w") as file:
    file.write("NETWORK THREAT DETECTION REPORT\n")
    file.write("--------------------------------\n")
    file.write(f"Total Packets Captured: {total_packets}\n")
    file.write(f"Total Threats Detected: {threat_count}\n")
    file.write(f"Total Threat Score: {threat_score}\n")
