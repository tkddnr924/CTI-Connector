import os
import re
from email import policy
from email.parser import BytesParser
from dateutil import parser as date_parser
from core.plb_eml import PLBEml
# from parser.eml.screenshot import get_eml_to_image

import pandas as pd

EML_EXCEL = "osint_eml.xlsx"
SHEET_NAME = "EML"

def extract_suspicious_links(body):
    urls = re.findall(r'https?://[^\s\'"<>]+', body)
    return [url.replace("http", "hxxp", 1) for url in urls]

def exist_data(value):
    if len(value) > 0:
        return [value]

    return value

def parse_all_eml_data(folder_path="Target"):
    eml_list = []
    
    xls_path = os.path.join(folder_path, EML_EXCEL)
    df = pd.read_excel(xls_path, sheet_name=SHEET_NAME, engine='openpyxl')
    eml_data = df.to_dict(orient='records')
    
    for eml in eml_data:
        file_name = eml.get("FILE NAME", "-")
        date = pd.Timestamp(eml.get("DATE", "-")).tz_localize("UTC", ambiguous='NaT').isoformat().replace("+00:00", "Z")
        subject = eml.get("SUBJECT", "-")
        from_ = eml.get("FROM", "-")
        to_ = exist_data(eml.get("TO", []))
        cc_ = exist_data(eml.get("CC", []))
        message_id = eml.get("MESSAGE ID", "-")
        slink = exist_data(eml.get("SUSPICIOUS URL", []))
        sfile = exist_data(eml.get("SUSPICIOUS FILE", []))
        md5 = eml.get("MD5", "-")
        
        eml_obj = PLBEml(
            file_name, message_id, date, subject, from_, to_, cc_, slink, sfile, md5
        )
        
        eml_list.append(eml_obj)
        
    return eml_list
    
    
    
    