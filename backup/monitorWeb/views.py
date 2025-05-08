# Create your views here.
import requests
from django.shortcuts import render , redirect , HttpResponseRedirect
from .models import WebsiteTraffic, PingResult
import socket 
from django.shortcuts import  get_object_or_404
from django.http import Http404
import random
import string
from .models import ShortenedURL , ScannedWebsite , Website , Customer , Admin1 , Vulnerability , ScannedURL , CSFScannerResult , SQLInjectionResult , NmapScanResult, SQLInjectionScanResult
from .scanner import crawl_website, scan_for_xss
from .forms import WebsiteForm , ScanForm , CSFScannerForm , SQLInjectionScannerForm , SQLInjectionForm , NmapScanForm , OWASPSecurityScanForm
import time
from django.contrib import messages
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_exempt
from bs4 import BeautifulSoup
from urllib.parse import urljoin , urlparse
from urllib.parse import quote
import subprocess
import re
from django.core.mail import send_mail
 
# from owasp_zap_v2 import ZAPv2


def login(request):
    if request.method=="POST":
      email=request.POST.get('email')
      passw=request.POST.get('password')
      custs=Customer.objects.filter(email=email,password=passw)
      for cust in custs:
         request.session['cid']=cust.customer_id
         return redirect("/user_page/")
      return render(request,"HomePage/login.html")
    return render(request,"HomePage/login.html")


@csrf_exempt 
def logout_view(request):

    logout(request)

    return redirect('index') 


def Adminlogin(request):
   if request.method=="POST":
      name=request.POST.get('email')
      passw=request.POST.get('password')
      ads=Admin1.objects.filter(admin_name=name,password=passw)
      for ad in ads:
         request.session['aid']=ad.admin_id
         return redirect("/website_monitoring/")
      return render(request,"AdminPage/login.html")
   return render(request,"AdminPage/login.html")



# def user_page(request):
#     if request.session.has_key('cid'):
#         cust= request.session['cid']
#         custs=Customer.objects.get(customer_id=cust)
#         return render(request,'HomePage/index.html',{"user":custs})
#     else:
#         return render(request,'HomePage/registration.html')


# def login(request):
#     if request.method == "POST":
#         email = request.POST.get('email')
#         passw = request.POST.get('password')
#         try:
#             cust = Customer.objects.get(email=email, password=passw)
#             request.session['cid'] = cust.customer_id
#             return redirect("/user_page/")
#         except Customer.DoesNotExist:
#             pass

#     return render(request, "HomePage/login.html")



def register(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']

        user = Customer(name=name, email=email, password=password)
        user.save()
        return redirect('/login/')
    
    return render(request, 'HomePage/registration.html')

def user_page(request):
    if 'cid' in request.session:
        cust_id = request.session['cid']
        try:
            cust = Customer.objects.get(customer_id=cust_id)
            return render(request, 'website_monitor/monitor_website.html', {"user": cust})
        except Customer.DoesNotExist:
            pass
    return render(request, 'HomePage/registration.html')



# def login(request):
#     if request.method == 'POST':
#         email = request.POST['email']
#         password = request.POST['password']

#         try:
#             user = Customer.objects.get(email=email, password=password)
#             # Perform login logic by setting a session variable
#             request.session['user_id'] = user.customer_id  # Store user's ID in the session

#             # Optionally, you can set other session data like user roles or permissions

#             return redirect('/user_page/')  # Redirect to the dashboard or another page after successful login
#         except Customer.DoesNotExist:
#             messages.error(request, 'Invalid credentials')  # Display an error message
#             return render(request, 'HomePage/registration.html')

#     return render(request, 'HomePage/login.html')



def index(request):
    return render(request , 'HomePage/HomePage.html')

def about(request):
    return render(request , 'HomePage/about.html')

def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        content = request.POST.get('content')

        # Send email
        send_mail(
            'New Contact Form Submission',
            f'Name: {name}\nEmail: {email}\nMessage: {content}',
            
            
            'yashjt080@gmail.com',  # Sender's email address
            ['yashtfp@gmail.com'],  # Recipient's email address
            fail_silently=False,
        )

        # Redirect to a success page
       
    
    return render(request, 'HomePage/contact.html')
def home(request):
    websites = WebsiteTraffic.objects.all()
    return render(request , 'home.html' , {'websites': websites})

def add_website(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    website, created = WebsiteTraffic.objects.get_or_create(url=url)
                    website.visits += 1
                    website.save()
            except requests.exceptions.RequestException:
                pass
    return redirect('home')

# new ping 

# def ping_form(request):
#     return render(request, 'ping/ping_form.html')

# def ping_website_new(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         try:
#             ip_address = re.search(r'[0-9]+(?:\.[0-9]+){3}', subprocess.check_output(['ping', '-c', '1', url]).decode()).group()
#             response_time = requests.get(url).elapsed.total_seconds()
#             result = Ping.objects.create(url=url, ip_address=ip_address, response_time=response_time)
#         except (subprocess.CalledProcessError, requests.RequestException):
#             result = None
#         return render(request, 'ping/ping_form.html', {'result': result})
#     else:
#         return render(request, 'ping/ping_form.html')


# ping scanner



# def ping_website(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         try:
#             response = requests.get(url)
#             is_online = response.status_code == 200
#             PingResult.objects.create(website_url=url, is_online=is_online)
#         except requests.exceptions.RequestException:
#             PingResult.objects.create(website_url=url, is_online=False)
#     return redirect('ping_results')

def ping_website(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        try:
            response = requests.get(url)
            is_online = response.status_code == 200
            PingResult.objects.create(website_url=url, is_online=is_online)
        except requests.exceptions.RequestException:
            PingResult.objects.create(website_url=url, is_online=False)
    return redirect('ping_results')

def ping_results(request):
    ping_results = PingResult.objects.all().order_by('-timestamp')[:10]  # Show the latest 10 results
    return render(request, 'ping.html', {'ping_results': ping_results})

def ping_url(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            try:
                # Get IP address of the website
                ip_address = socket.gethostbyname(url)

                # Send a request to the provided URL
                response = requests.get(url)

                if response.status_code == 200:
                    response_time = response.elapsed.total_seconds() * 1000  # Convert to milliseconds
                    return render(request, 'result.html', {'url': url, 'ip_address': ip_address, 'response_time': response_time})
                else:
                    error_message = f"Received status code {response.status_code}"
            except (requests.exceptions.RequestException, socket.gaierror) as e:
                error_message = str(e)
            return render(request, 'error.html', {'url': url, 'error_message': error_message})
    return render(request, 'pingCommand.html')

def ping_scanner(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        try:
            # Sending a ping command to the provided URL
            response = subprocess.check_output(['ping', '-c', '4', url]).decode('utf-8')
            
            # Extracting IP address and ping time from the ping response using regular expressions
            ip_address = re.search(r'\d+\.\d+\.\d+\.\d+', response).group()
            ping_times = re.findall(r'time=\d+\.\d+', response)
            ping_times = [float(re.search(r'\d+\.\d+', time).group()) for time in ping_times]
            
            # Calculating average ping time in milliseconds
            avg_ping_time = sum(ping_times) / len(ping_times)
            
            result = f"Success: {url} is reachable.\nIP Address: {ip_address}\nAverage Ping Time: {avg_ping_time:.2f} ms"
        except subprocess.CalledProcessError as e:
            result = f"Error: {e.output.decode('utf-8')}"
        
        return render(request, 'ping/ping_result.html', {'url': url, 'result': result})

    return render(request, 'ping/ping_form.html')



def website_monitoring(request):
    if request.method == 'POST':
        # Handle website monitoring form
        form = WebsiteForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            try:
                start_time = time.time()
                response = requests.get(url)
                end_time = time.time()
                status_code = response.status_code
                response_time = end_time - start_time
            except Exception as e:
                status_code = None
                response_time = None

            website = Website(url=url, status_code=status_code, response_time=response_time)
            website.save()

        # Handle website pinging
        url_to_ping = request.POST.get('url_to_ping')
        if url_to_ping:
            try:
                ping_response = requests.get(url_to_ping)
                is_online = ping_response.status_code == 200
                PingResult.objects.create(website_url=url_to_ping, is_online=is_online)
            except requests.exceptions.RequestException:
                PingResult.objects.create(website_url=url_to_ping, is_online=False)

    else:
        form = WebsiteForm()

    # Delete website based on URL parameter
    delete_url = request.GET.get('delete_url')
    if delete_url:
        try:
            Website.objects.filter(url=delete_url).delete()
        except Website.DoesNotExist:
            pass

    websites = Website.objects.all()
    ping_results = PingResult.objects.all().order_by('-timestamp')[:10]  # Show the latest 10 results

    return render(request, 'website_monitor/monitor_website.html', {'form': form, 'websites': websites, 'ping_results': ping_results})


# portscanner
def scan_ports(request):
    if request.method == 'POST':
        target_url = request.POST.get('url')
        open_ports = []
        closed_ports = []
        error_ports = []

        try:
            # Resolve the URL to an IP address
            ip_address = socket.gethostbyname(target_url)

            # Specify the range of ports to scan (e.g., 1 to 1024)
            start_port = 1
            end_port = 65535

            # Perform port scanning
            for port in range(start_port, end_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Adjust the timeout as needed
                result = sock.connect_ex((ip_address, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
                elif result == 10061:
                    closed_ports.append(port)
                else:
                    error_ports.append(port)
        
        except (socket.gaierror, socket.error):
            error_message = f"Could not resolve or connect to {target_url}"
            return render(request, 'portscanner/scan.html', {'error_message': error_message})

        return render(request, 'portscanner/scan.html', {
            'url': target_url,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'error_ports': error_ports
        })
    
    return render(request, 'portscanner/scan.html')


# bitlilink
# def shorten_url(request):
#     if request.method == 'POST':
#         long_url = request.POST.get('long_url')
#         if long_url:
#             # Generate a unique short code
#             short_code = generate_short_code()
            
#             # Create a new ShortenedURL object
#             shortened_url = ShortenedURL(long_url=long_url, short_code=short_code)
#             shortened_url.save()
#             return render(request, 'bitlilink/success.html', {'shortened_url': shortened_url})
    
#     return render(request, 'bitlilink/shorten.html')

# def resolve_url(request, short_code):
#     try:
#         shortened_url = get_object_or_404(ShortenedURL, short_code=short_code)
#         return redirect(shortened_url.long_url)
#     except Http404:
#         return render(request, 'bitlilink/error.html', {'error_message': 'Short URL not found'})

# def generate_short_code():
#     # Generate a random short code (e.g., a combination of letters and digits)
#     characters = string.ascii_letters + string.digits
#     short_code = ''.join(random.choice(characters) for _ in range(6))  # Adjust the length as needed
#     return short_code

def shorten_or_resolve_url(request, short_code=None):
    if request.method == 'POST':
        long_url = request.POST.get('long_url')
        if long_url:
            if short_code:
                # If a custom short code is provided, check if it already exists
                existing_url = ShortenedURL.objects.filter(short_code=short_code).first()
                if existing_url:
                    return render(request, 'bitlilink/shorten.html', {'error_message': 'Custom short code already in use'})
            else:
                # Generate a unique short code
                short_code = generate_short_code()
            
            # Create a new ShortenedURL object
            shortened_url = ShortenedURL(long_url=long_url, short_code=short_code)
            shortened_url.save()
            return render(request, 'bitlilink/shorten.html', {'shortened_url': shortened_url})
    
    elif short_code:
        # Resolve the short URL
        try:
            shortened_url = get_object_or_404(ShortenedURL, short_code=short_code)
            return redirect(shortened_url.long_url)
        except Http404:
            return render(request, 'bitlilink/shorten.html', {'error_message': 'Short URL not found'})
    
    return render(request, 'bitlilink/shorten.html', {'short_code': short_code})

def generate_short_code():
    # Generate a random short code (e.g., a combination of letters and digits)
    characters = string.ascii_letters + string.digits
    short_code = ''.join(random.choice(characters) for _ in range(6))  # Adjust the length as needed
    return short_code

# CSS
# def initiate_scan(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         crawl_website(url)
#         return redirect('list_scanned_websites')
#     return render(request, 'initiate_scan.html')

# def list_scanned_websites(request):
#     websites = ScannedWebsite.objects.all()
#     return render(request, 'list_websites.html', {'websites': websites})

# def view_scan_result(request, website_id):
#     website = ScannedWebsite.objects.get(id=website_id)
#     return render(request, 'view_scan_result.html', {'website': website})



def xss_scanner(request):
    scanned_url = None

    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            is_vulnerable, scan_result = scan_for_xss(url)
            scanned_url = ScannedURL(url=url, is_vulnerable=is_vulnerable, scan_result=scan_result)
            scanned_url.save()

    else:
        form = ScanForm()

    return render(request, 'crossSite/xss_scanner.html', {'form': form, 'scanned_url': scanned_url})

def scan_for_xss(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')

        if scripts:
            return True, "XSS vulnerabilities detected"
        else:
            return False, "No XSS vulnerabilities detected"
    except Exception as e:
        return False, f"Error: {str(e)}"

# monitor website 
# def website_monitoring(request):
#     if request.method == 'POST':
#         form = WebsiteForm(request.POST)
#         if form.is_valid():
#             url = form.cleaned_data['url']
#             try:
#                 start_time = time.time()
#                 response = requests.get(url)
#                 end_time = time.time()
#                 status_code = response.status_code
#                 response_time = end_time - start_time
#             except Exception as e:
#                 status_code = None
#                 response_time = None

#             website = Website(url=url, status_code=status_code, response_time=response_time)
#             website.save()
#     else:
#         form = WebsiteForm()

#     websites = Website.objects.all()

#     return render(request, 'website_monitor/monitor_website.html', {'form': form, 'websites': websites})

'''SQL INJECTION CODE '''
def sql_injection_scanner(request):
    if request.method == 'POST':
        form = SQLInjectionForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            try:
                response = requests.get(url)
                # Implement your logic to check for SQL injection vulnerability in response content
                is_vulnerable = check_for_sql_injection_vulnerability(response)
                SQLInjectionResult.objects.create(url=url, is_vulnerable=is_vulnerable)
            except requests.exceptions.RequestException:
                is_vulnerable = False
                # Handle exception, log error, or perform appropriate action

            return render(request, 'sqlInjection/sql_injection_from.html', {'url': url, 'is_vulnerable': is_vulnerable})

    else:
        form = SQLInjectionForm()

    return render(request, 'sqlInjection/sql_injection_form.html', {'form': form})


def check_for_sql_injection_vulnerability(response):
    # Check response content for common SQL injection error messages
    sql_error_messages = ['error in your SQL syntax', 'mysql_fetch_array()', 'supplied argument is not a valid MySQL']
    for error_message in sql_error_messages:
        if error_message in response.text.lower():
            return True

    # Check response headers for potential SQL injection headers
    sql_headers = ['mysql_error', 'sql_exception']
    for header in sql_headers:
        if header in response.headers:
            return True

    # Check status codes for potential SQL injection status codes
    sql_status_codes = [500]  # Internal Server Error
    if response.status_code in sql_status_codes:
        return True

    # If no common SQL injection patterns found, return False
    return False


def sql_injection_scan(request):
    if request.method == 'POST':
        # Get the user-provided URL from the form input
      user_url = request.POST.get('url')

        # Check if the URL includes a scheme (http:// or https://)
      parsed_url = urlparse(user_url)
      if not parsed_url.scheme:
            # If the scheme is missing, add 'http://' by default
        user_url = 'http://' + user_url

        # URL-encode the user-provided URL
        url = quote(user_url)
        # SQL injection payloads to test
        sql_payloads = ["' OR '1'='1", "1' OR '1'='1' --", "1' OR '1'='1' #", "' OR 'a'='a", "'; DROP TABLE users--"]

        s = requests.Session()
        s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"

        def get_forms(url):
            soup = BeautifulSoup(s.get(url).content, "html.parser")
            return soup.find_all("form")

        def form_details(form):
            detailsOfForm = {}
            action = form.attrs.get("action", "").lower()
            method = form.attrs.get("method", "get").lower()
            inputs = []

            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                input_value = input_tag.attrs.get("value", "")
                inputs.append({"type": input_type, "name": input_name, "value": input_value})

            detailsOfForm["action"] = action
            detailsOfForm["method"] = method
            detailsOfForm["inputs"] = inputs
            return detailsOfForm

        def vulnerable(response):
            errors = [
                "quoted string not properly terminated",
                "unclosed quotation mark after the character string",
                "you have an error in your sql syntax;",
                # Add more SQL error messages here as needed
            ]

            for error in errors:
                if error in response.content.decode().lower():
                    return True
            return False

        def perform_sql_injection_scan(url):
            forms = get_forms(url)
            detected_vulnerabilities = []

            for form in forms:
                details = form_details(form)

                for input_tag in details["inputs"]:
                    if input_tag["type"] != "submit":
                        for payload in sql_payloads:
                            data = {input_tag["name"]: payload}
                            url = urljoin(url, details["action"])

                            if details["method"] == "post":
                                res = s.post(url, data=data)
                            elif details["method"] == "get":
                                res = s.get(url, params=data)

                            if vulnerable(res):
                                detected_vulnerabilities.append(url)
                                break  # If a vulnerability is detected, no need to continue with other payloads

            return detected_vulnerabilities

        detected_vulnerabilities = perform_sql_injection_scan(url)

        # Create and save Vulnerability instances for detected vulnerabilities
        for vulnerability_url in detected_vulnerabilities:
            Vulnerability.objects.create(url=vulnerability_url, method='POST')

        # Fetch all vulnerabilities from the database
        vulnerabilities = Vulnerability.objects.all()

        return render(request, 'sqlInjection/vulnerabilities.html', {'vulnerabilities': vulnerabilities})

    return render(request, 'sqlInjection/sql_injection_scan.html')



def sql_injection_scanner(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        payloads = [
            "' OR '1'='1",
            "' OR 'a'='a",
            "' OR 'x'='x",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            "' OR '1'='1' or '1'='1",
            "' OR '1'='1' OR 'a'='a",
            "' OR '1'='1' OR 'x'='x",
            "admin' --",
            "admin' #",
            "admin'/*",
            "admin' OR '1'='1",
            "admin' OR 'a'='a",
            "admin' OR 'x'='x",
            "admin' AND 1=0 UNION ALL SELECT null, null, null, null, null, null, null, null, null --",
            "admin' AND 1=0 UNION ALL SELECT null, null, null, null, null, null, null, null, null #",
            "admin' AND 1=0 UNION ALL SELECT null, null, null, null, null, null, null, null, null /*"
        ]

        is_vulnerable = False

        try:
            for payload in payloads:
                # Sending a malicious SQL query to the provided URL
                response = requests.get(url + payload)
                if 'error' in response.text.lower() or 'syntax' in response.text.lower():
                    is_vulnerable = True
                    break
        except requests.RequestException:
            is_vulnerable = False

        # Save the scan result to the database
        scan_result = SQLInjectionScanResult.objects.create(url=url, is_vulnerable=is_vulnerable)

        return render(request, 'sqlinjection2/sqlinjection_form.html', {'scan_result': scan_result})

    return render(request, 'sqlinjection2/sqlinjection_form.html')


# cross Site forgery 
def csrf_scanner(request):
    if request.method == 'POST':
        form = CSFScannerForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            try:
                response = requests.get(url)
                # Check for CSRF vulnerability in the response content or headers
                is_vulnerable = check_for_csrf_vulnerability(response)
                
                # Save the scan result to the database
                result = CSFScannerResult(url=url, is_vulnerable=is_vulnerable)
                result.save()
                
            except requests.exceptions.RequestException:
                is_vulnerable = False

            return render(request, 'csrf/csrf_form.html', {'url': url, 'is_vulnerable': is_vulnerable})

    else:
        form = CSFScannerForm()

    return render(request, 'csrf/csrf_form.html', {'form': form})


def check_for_csrf_vulnerability(response):
    # Check for common CSRF tokens in response content
    csrf_tokens = ['csrfmiddlewaretoken', 'csrf_token', 'authenticity_token']  # Add more tokens if necessary

    # Check response content
    response_content = response.text.lower()  # Convert to lowercase for case-insensitive matching
    for token in csrf_tokens:
        if token in response_content:
            return True

    # Check response headers for common CSRF headers
    csrf_headers = ['x-csrf-token', 'x-requested-with']  # Add more headers if necessary
    for header in csrf_headers:
        if header in response.headers:
            return True

    # Check for anti-CSRF JavaScript functions
    csrf_js_functions = ['getcsrf', 'gettoken', 'getcsrftoken']  # Add more functions if necessary
    for js_function in csrf_js_functions:
        if js_function in response_content:
            return True

    # If no common CSRF patterns found, return False
    return False

# NMAP

# def nmap_scan(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         try:
#             # Run Nmap command to scan open ports
#             result = subprocess.check_output(['nmap', '-Pn', url]).decode('utf-8')
#             open_ports = [line.split('/')[0] for line in result.splitlines() if '/open' in line]
#             open_ports_str = ', '.join(open_ports)

#             # Save scan result to the database
#             scan_result = ScanResult(url=url, ports_open=open_ports_str)
#             scan_result.save()

#             return render(request, 'Nmap/scan_result.html', {'url': url, 'open_ports': open_ports})
#         except Exception as e:
#             error_message = f"Error: {e}"
#             return render(request, 'error.html', {'error_message': error_message})

#     return render(request, 'Nmap/scan_form.html')


# def nmap_scan(request):
#     if request.method == 'POST':
#         form = NmapScanForm(request.POST)
#         if form.is_valid():
#             target_url = form.cleaned_data['target_url']
#             nm = nmap.PortScanner()
#             nm.scan(hosts=target_url, arguments='-Pn')
#             scan_result = nm.csv()
#             # Save the scan result to the database
#             NmapScanResult.objects.create(target_url=target_url, scan_result=scan_result)
#             return render(request, 'Nmap/scan_result.html', {'scan_result': scan_result})
#     else:
#         form = NmapScanForm()
#     return render(request, 'Nmap/scan_form.html', {'form': form})


#Admin 

def info(request):
    return render(request , 'HomePage/info.html')

# admin 
def AdminDashboard(request):
    return render (request , 'AdminPage/Admin_login.html')


def scanned_website_list(request):
    websites = ScannedWebsite.objects.all()
    return render(request, 'AdminPage/scanned_website_list.html', {'websites': websites})


def website_list(request):
    websites = Website.objects.all()
    return render(request, 'AdminPage/monitor_list.html', {'websites': websites})

# def website_list(request):
#     if 'aid' in request.session:
#         # Admin is logged in, perform actions accordingly
#         websites = Website.objects.all()
#         return render(request, 'AdminPage/monitor_list.html', {'websites': websites})
#     else:
#         # Admin is not logged in, redirect to the login page or handle it as needed
#         return redirect("/Adminlogin/")  # You may adjust the URL
    
# cross Site forgery 


def Abitlilink(request):
    websites = ShortenedURL.objects.all()
    return render(request , 'AdminPage/AdminBitlilink.html' , {'websites': websites})


def xss_List(request):
    xss = ScannedURL.objects.all()
    return render(request , 'AdminPage/CrossSiteList.html' , {'xss': xss})

def customer_list(request):
    customer = Customer.objects.all()
    return render(request , 'AdminPage/Customer_list.html' , {'customer': customer})

def csrf_list(request):
    csrf = CSFScannerResult.objects.all()
    return render(request , 'AdminPage/csrfList.html' , {'csrf':csrf})

def sqlList(request):
    sqlInjection = SQLInjectionScanResult.objects.all()
    return render(request, 'AdminPage/sqlInjection.html' , {'sqlInject':sqlInjection})
# delete button view 

def delete_xss_scan(request, scan_id):
    try:
        scanned_url = ScannedURL.objects.get(pk=scan_id)
        scanned_url.delete()
    except ScannedURL.DoesNotExist:
        pass  # Handle the case where the scan doesn't exist

    return redirect('xss_List')

def customer_Delete(request , cust_id):
    try:
        customer = Customer.objects.get(customer_id = cust_id)
        customer.delete()
    except:
        print("A problem has  occured")
    
    return redirect('customer_list')

def del_bit(request , b_id):
    try:
        bitli = ShortenedURL.objects.get(id=b_id)
        bitli.delete()
    except:
        print("Some error has occure")
    
    return redirect('Abitlilink')

def del_website(request , w_id):
    try:
        website = Website.objects.get(id=w_id)
        website.delete()
    except:
        print('Some erro has occured ')
    
    return redirect('website_list')
        
def csrfDel(request , cr_id):
    try:
        csrf = CSFScannerResult.objects.get(id=cr_id)
        csrf.delete()
    except:
        print("Some error has occure ")
        
    return redirect('csrf_list')

def sql_del(request , sql_id):
    try:
        sql = SQLInjectionScanResult.objects.get(id=sql_id)
        sql.delete()
    except:
        print("Some Error has occured ")
    
    return redirect('sqlList')


# def owasp_security_scan(request):
#     if request.method == 'POST':
#         form = OWASPSecurityScanForm(request.POST)
#         if form.is_valid():
#             target_url = form.cleaned_data['target_url']
#             # Perform OWASP ZAP scan
#             zap = ZAPv2()
#             zap.urlopen(target_url)
#             scan_result = zap.ascan.scan(target_url)
#             # Save the scan result to the database
#             OWASPSecurityScan.objects.create(target_url=target_url, scan_result=scan_result)
#             return HttpResponseRedirect(reverse('scan_result', args=[scan_result['scan'][0]['scan']]))
#     else:
#         form = OWASPSecurityScanForm()
#     return render(request, 'owasp_form.html', {'form': form})