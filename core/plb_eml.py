from email.utils import parseaddr
from urllib.parse import urlparse

def extract_domains(links):
    domains = set()
    for link in links:
        parsed = urlparse(link.replace("hxxp", "http", 1))  # 원래 스킴으로 복원
        domains.add(parsed.netloc)
    return list(domains)

class PLBEml:
    def __init__(self, file_name, message_id, date, subject, from_, to, body, suspicious_link) -> None:
        self.file_name = file_name
        self.message_id = message_id
        self.date = date
        self.subject = subject
        self.from_ = parseaddr(from_)[1]
        self.to = parseaddr(to)[1]
        self.body = body
        self.suspicious_link = suspicious_link or []
        self.suspicious_domain = extract_domains(suspicious_link) or []
        
    def __repr__(self) -> str:
        return f"<MY_EML {self.file_name} | {self.message_id}>"

    