from pathlib import Path
from playwright.sync_api import sync_playwright
from email import policy
from email.parser import BytesParser

SCREENSHOT_DIR = Path("Screenshot")
SCREENSHOT_DIR.mkdir(exist_ok=True)

class EmlObject:
    def __init__(self, file_name, html):
        self.file_name = file_name
        self.html = html

def sanitize_html(html):
    html = html.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return html

def parse_eml_html(file_path):
    with open(file_path, "rb") as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    # HTML 파트 추출
    html = None
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html":
                html = part.get_content()
                break
    else:
        if msg.get_content_type() == "text/html":
            html = msg.get_content()
    
    return sanitize_html(html or "<html><body>(No HTML content)</body></html>")

def get_eml_to_image(eml):
    try:
        eml_path = Path(eml)
        output_path = SCREENSHOT_DIR / f"{eml_path.name}.png"
        parsed_html = parse_eml_html(eml)

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(parsed_html, wait_until="domcontentloaded")
            page.set_viewport_size({"width": 1280, "height": 800})
            page.screenshot(path=str(output_path), full_page=True)
            browser.close()
    except Exception as e:
        print(f"[!] Error parsing {eml}: {e}")