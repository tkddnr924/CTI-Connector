import os
import re
from email import policy
from email.parser import BytesParser
from dateutil import parser as date_parser
from core.plb_eml import PLBEml
# from parser.eml.screenshot import get_eml_to_image

def extract_suspicious_links(body):
    urls = re.findall(r'https?://[^\s\'"<>]+', body)
    return [url.replace("http", "hxxp", 1) for url in urls]

def parse_all_eml_files(folder_path="Target"):
    eml_list = []

    for file_name in os.listdir(folder_path):
        if file_name.lower().endswith(".eml"):
            file_path = os.path.join(folder_path, file_name)
            try:
                with open(file_path, "rb") as f:
                    msg = BytesParser(policy=policy.default).parse(f)

                message_id = msg.get("Message-ID", "").strip()
                date_raw = msg.get("Date")
                date_parsed = date_parser.parse(date_raw)
                iso_date = date_parsed.strftime("%Y-%m-%dT%H:%M:%SZ")

                subject = msg.get("Subject", "")
                from_ = msg.get("From", "")
                to = msg.get("To", "")
                body = msg.get_body(preferencelist=('plain', 'html')).get_content()

                suspicious_links = extract_suspicious_links(body)

                eml_obj = PLBEml(
                    file_name=file_name,
                    message_id=message_id,
                    date=iso_date,
                    subject=subject,
                    from_=from_,
                    to=to,
                    body=body,
                    suspicious_link=suspicious_links
                )
                eml_list.append(eml_obj)

                # get_eml_to_image(file_path)

            except Exception as e:
                print(f"[!] Error parsing {file_name}: {e}")

    return eml_list
