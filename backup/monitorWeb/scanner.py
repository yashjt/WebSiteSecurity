# crawling_logic.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from html import escape
from .models import ScannedWebsite
def crawl_website(url):
    visited_urls = set()
    queue = [url]

    while queue:
        current_url = queue.pop(0)
        visited_urls.add(current_url)

        try:
            response = requests.get(current_url)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract links and add them to the queue
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(current_url, link['href'])
                if urlparse(absolute_url).netloc == urlparse(url).netloc and absolute_url not in visited_urls:
                    queue.append(absolute_url)

            # Implement XSS scanning logic here
            vulnerabilities = scan_for_xss(soup)

            # Save scan result to the database
            website = ScannedWebsite(url=current_url, scan_result="\n".join(vulnerabilities))
            website.save()

        except Exception as e:
            print(f"Error scanning {current_url}: {str(e)}")



def scan_for_xss(soup):
    vulnerabilities = []

    # Find all HTML tags and their content
    for tag in soup.find_all(True):
        # Check attributes of each tag for potential vulnerabilities
        for attr, value in tag.attrs.items():
            # Check for potential XSS in attribute values
            if is_potential_xss_in_attribute(attr, value):
                vulnerabilities.append(f"Potential XSS in tag '{tag.name}' attribute '{attr}': {escape(value)}")

        # Check tag content for potential vulnerabilities
        if is_potential_xss_in_content(tag):
            vulnerabilities.append(f"Potential XSS in tag '{tag.name}' content: {escape(str(tag))}")

    return vulnerabilities
import re

def is_potential_xss_in_attribute(attr, value):
    # Implement more sophisticated checks for potential XSS in attribute values
    patterns_to_check = [
        r'javascript\s*:',
        r'vbscript\s*:',
        r'on\w+\s*=\s*["\']\s*.*\s*["\']',  # Event handler attributes
        r'\b(unescape|eval|prompt|confirm|window\.[a-zA-Z_]+\s*=)\b',  # JavaScript keywords
        r'\bexpression\s*\([^)]+\)',  # CSS expression() function
        r'\burl\s*\(\s*[\'"]?\s*javascript\s*:\s*',  # CSS url() function with JavaScript
        r'\bdata\s*:\s*[^,;]*base64[^,;]*,',  # Data URIs with base64
    ]
    
    for pattern in patterns_to_check:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False

def is_potential_xss_in_content(tag):
    # Implement more sophisticated checks for potential XSS in tag content
    if tag.name in ['script', 'iframe', 'img', 'a', 'embed']:
        return True
    
    # Check for event handler attributes in tags
    event_attributes = ['onabort', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onerror', 'onfocus',
                        'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onmousedown', 'onmousemove',
                        'onmouseout', 'onmouseover', 'onmouseup', 'onreset', 'onresize', 'onselect',
                        'onsubmit', 'onunload']
    
    for attr in event_attributes:
        if tag.get(attr):
            return True
    
    return False
