#!/usr/bin/env python
# coding=utf-8
#######################################################################
### server-status_PWN
# Description:
# A script that monitors and extracts URLs from Apache server-status.
### Version:
# 0.3
### Homepage:
# https://github.com/mazen160/server-status_PWN
## Author:
# Mazin Ahmed <Mazin AT MazinAhmed DOT net>
# Modified by Assistant
#######################################################################

# Modules
import time
import sqlite3
import calendar
import argparse

# External modules
import requests
from bs4 import BeautifulSoup

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="The Apache server-status URL.",
                    action='store',
                    required=True)
parser.add_argument("--sleeping-time",
                    dest="sleeping_time",
                    help="Sleeping time between each request. (Default: 10)",
                    action='store',
                    default=10)
parser.add_argument("--db", dest="db",
                    help="Outputs database path. (Default: /tmp/server-status_PWN.db).",
                    action='store',
                    default='/tmp/server-status_PWN.db')
parser.add_argument("-o", "--output",
                    dest="output_path",
                    help="Saves output constantly into a newline-delimited output file.",
                    action='store')
parser.add_argument("--enable-full-logging",
                    dest="enable_full_logging",
                    help="Enable full logging for all requests with timestamps of each request.",
                    action='store_true',
                    default=False)
parser.add_argument("--debug",
                    dest="enable_debug",
                    help="Shows debugging information for errors and exceptions",
                    action='store_true',
                    default=False)

args = parser.parse_args()

url = args.url if args.url else ''
sleeping_time = args.sleeping_time if args.sleeping_time else ''
db = args.db if args.db else ''
output_path = args.output_path if args.output_path else ''
enable_full_logging = args.enable_full_logging
enable_debug = args.enable_debug


class tcolor:
    """
    A simple coloring class.
    """
    endcolor = '\033[0m'
    red = '\033[31m'
    green = '\033[32m'
    purple = '\033[35m'
    yellow = '\033[93m'
    light_blue = '\033[96m'


def Exception_Handler(e):
    """
    Catches exceptions, and shows it on screen when --debug is True.
    """
    global enable_debug
    if enable_debug is True:
        print('%s%s%s' % (tcolor.red, str(e), tcolor.endcolor))
    return(0)


class Request_Handler():
    """
    Handles anything related to requests.
    """
    def __init__(self):
        self.user_agent = 'server-status_PWN (https://github.com/mazen160/server-status_PWN)'
        self.timeout = '3'
        self.origin_ip = '127.0.0.1'
        self.additional_headers = {}

    def send_request(self, url):
        """
        Sends requests.
        """
        headers = {"User-Agent": self.user_agent, 'Accept': '*/*'}
        headers.update(self.additional_headers)

        try:
            req = requests.get(url,
                             headers=headers,
                             timeout=int(self.timeout),
                             verify=False,
                             allow_redirects=False)
            output = str(req.text)  # Changed from req.content to req.text
        except Exception as e:
            Exception_Handler(e)
            output = ''
        return(output)

def normalize_url(url):
    """Clean and normalize URL"""
    try:
        # Already a full URL
        if url.startswith(('http://', 'https://')):
            return url
        
        # Handle relative paths and full paths
        url = url.strip()
        
        # Remove HTTP methods at the beginning
        http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']
        for method in http_methods:
            if url.startswith(method):
                url = url[len(method):].lstrip()

        # Remove HTTP version and trailing parts
        if ' HTTP/' in url:
            url = url.split(' HTTP/')[0]
            
        # Clean up URL
        url = url.strip('/')
        
        # Clean query parameters if present
        if '?' in url:
            base_path, params = url.split('?', 1)
            clean_params = []
            
            for param in params.split('&'):
                if '=' not in param:
                    continue
                    
                key, value = param.split('=', 1)
                # Skip empty values and common timestamps
                if not value or key.lower() in ['ts', 't', 'time', '_']:
                    continue
                    
                clean_params.append(f"{key}={value}")
            
            url = f"{base_path}?{'&'.join(sorted(clean_params))}" if clean_params else base_path
        
        return url
        
    except Exception as e:
        if enable_debug:
            print(f"{tcolor.red}[!] Error normalizing URL: {str(e)}{tcolor.endcolor}")
        return None

def validate_url(url):
    """Validate URL format and content"""
    try:
        # Basic validation
        if not url or len(url) < 2:
            return False
            
        # If it's an absolute URL, verify format
        if url.startswith(('http://', 'https://')):
            # Ensure has valid domain and path
            parts = url.split('/', 3)
            if len(parts) < 4:  # protocol + empty + domain + path
                return False
            
        return True
            
    except Exception:
        return False

def clean_request(request):
    """Clean request string"""
    request = request.strip()
    
    # Remove HTTP methods
    http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']
    for method in http_methods:
        if request.startswith(method):
            request = request[len(method):].lstrip()
            
    # Remove HTTP version and trailing parts
    if ' HTTP/' in request:
        request = request.split(' HTTP/')[0]
    
    # Remove any trailing indicators
    for suffix in [' HTTP', ' HT', ' H', '/1.1', '/1.0']:
        if request.endswith(suffix):
            request = request[:-len(suffix)]
    
    return request.strip('/')

def organize_urls_by_type(urls):
    """Organize URLs by their pattern/type"""
    # Group by first two path segments
    groups = {}
    
    for url in urls:
        # Get path part for grouping
        if url.startswith(('http://', 'https://')):
            # For absolute URLs, get path after domain
            path = '/' + '/'.join(url.split('/', 3)[3:])
        else:
            path = '/' + url if not url.startswith('/') else url
            
        # Get first two path segments for grouping
        segments = [s for s in path.split('/') if s][:2]
        if segments:
            group_key = '/' + '/'.join(segments)
        else:
            group_key = '/'
            
        if group_key not in groups:
            groups[group_key] = set()
        groups[group_key].add(url)
        
    return groups

def get_normalized_url(url):
    """
    Get normalized URL by removing dynamic parameters and standardizing format
    """
    if '?' not in url:
        return url
        
    base_path, params = url.split('?', 1)
    param_list = []
    dynamic_params = ['ts', 't', 'time', 'timestamp', '_', 'random', 'nocache']
    
    for param in params.split('&'):
        if '=' in param:
            key, value = param.split('=', 1)
            # Skip dynamic parameters
            if any(key.startswith(dp) for dp in dynamic_params):
                continue
            # Skip empty or truncated values
            if not value or len(value) < 2:
                continue
            param_list.append(f"{key}={value}")
    
    if param_list:
        return f"{base_path}?{'&'.join(sorted(param_list))}"  # Sort params for consistency
    return base_path

def get_base_url(url):
    """Get base URL without timestamps"""
    # Split URL into path and query
    if '?' in url:
        path, query = url.split('?', 1)
        # Remove timestamp parameters
        params = [p for p in query.split('&') 
                 if not any(ts in p.lower() for ts in ['ts=', 't=', 'time=', 'timestamp='])]
        if params:
            return f"{path}?{'&'.join(params)}"
        return path
    return url

def group_urls_by_path(urls):
    """Group URLs by their path structure"""
    groups = {}
    for url in urls:
        # Get path without query string
        base_path = url.split('?')[0] if '?' in url else url
        # Get the first two path components for grouping
        path_parts = [p for p in base_path.split('/') if p][:2]
        if path_parts:
            group_key = f"/{'/'.join(path_parts)}"
        else:
            group_key = "/"
            
        if group_key not in groups:
            groups[group_key] = set()
        groups[group_key].add(url)
    return groups

class Response_Handler():
    """
    Handles validation and parsing of response.
    """
    def validate_response(self, response):
        """
        Validates the response, and checks whether the output is valid.
        """
        print(f"{tcolor.yellow}[*] Response preview (first 500 chars):{tcolor.endcolor}")
        print(f"{tcolor.light_blue}{response[:500]}...{tcolor.endcolor}")
        
        valid_patterns = ['Server Version:', 'Server MPM:', 'Server Built:']
        found_patterns = []
        for pattern in valid_patterns:
            if pattern in response:
                found_patterns.append(pattern)
                print(f"{tcolor.green}[+] Found valid server-status pattern: {pattern}{tcolor.endcolor}")
        
        if found_patterns:
            return True
            
        print(f"{tcolor.red}[!] No valid server-status patterns found{tcolor.endcolor}")
        return False

    def parse_response(self, response):
        """
        Parses Apache server-status response.
        """
        VHOST_List = []
        REQUEST_URI_List = []
        FULL_URL_List = []
        CLIENT_IP_ADDRESS_List = []
        seen_urls = set()

        try:
            print(f"{tcolor.yellow}[*] Starting to parse response...{tcolor.endcolor}")
            soup = BeautifulSoup(response, 'html.parser')
            
            # Find the VHost and Request columns
            headers = None
            columns = {}
            
            # First find the correct table
            tables = soup.find_all('table')
            status_table = None
            
            for table in tables:
                first_row = table.find('tr')
                if first_row:
                    cells = [cell.get_text().strip() for cell in first_row.find_all(['th', 'td'])]
                    if 'VHost' in cells and 'Request' in cells and 'Client' in cells:
                        status_table = table
                        # Find column positions
                        columns = {
                            'client': cells.index('Client'),
                            'vhost': cells.index('VHost'),
                            'request': cells.index('Request')
                        }
                        break
            
            if not status_table:
                print(f"{tcolor.red}[!] Could not find server status table{tcolor.endcolor}")
                return {"VHOST": [], "REQUEST_URI": [], "FULL_URL": [], "CLIENT_IP_ADDRESS": []}
            
            print(f"{tcolor.green}[+] Found server status table with column indices: {columns}{tcolor.endcolor}")
            
            # Process each row
            for row in status_table.find_all('tr')[1:]:  # Skip header
                cells = row.find_all(['td', 'th'])
                if len(cells) > max(columns.values()):
                    client = cells[columns['client']].get_text().strip()
                    vhost = cells[columns['vhost']].get_text().strip()
                    request = cells[columns['request']].get_text().strip()
                    
                    # Filter and clean data
                    if (vhost and request and client and 
                        not any(x in request for x in ['OPTIONS', 'HEAD']) and
                        not '127.0.0.1' in client and
                        vhost != ''):
                        
                        # Clean hostname (remove port)
                        vhost = vhost.split(':')[0]
                        
                        # Clean request
                        request = clean_request(request)
                        
                        # Build and normalize URL
                        full_url = f"https://{vhost}/{request.lstrip('/')}"
                        normalized_url = normalize_url(full_url)
                        
                        if normalized_url and validate_url(normalized_url):
                            # Add only if unique
                            if normalized_url not in seen_urls:
                                seen_urls.add(normalized_url)
                                VHOST_List.append(vhost)
                                REQUEST_URI_List.append(request)
                                FULL_URL_List.append(normalized_url)
                                CLIENT_IP_ADDRESS_List.append(client)
                                print(f"{tcolor.green}[+] Added URL: {normalized_url}{tcolor.endcolor}")

            # Group URLs by endpoint type
            grouped_urls = organize_urls_by_type(FULL_URL_List)

            # Display results by group
            print(f"\n{tcolor.green}[+] Found {len(FULL_URL_List)} unique URLs{tcolor.endcolor}")
            
            # Display grouped results
            for base_path, urls in sorted(grouped_urls.items()):
                print(f"\n{tcolor.yellow}[*] {base_path}{tcolor.endcolor}")
                for url in sorted(urls):
                    relative_path = url.split(base_path, 1)[1] if base_path in url else url
                    print(f"  {tcolor.light_blue}└─{tcolor.endcolor} {relative_path}")

            return {
                "VHOST": VHOST_List,
                "REQUEST_URI": REQUEST_URI_List,
                "FULL_URL": FULL_URL_List,
                "CLIENT_IP_ADDRESS": CLIENT_IP_ADDRESS_List
            }

        except Exception as e:
            print(f"{tcolor.red}[!] Major error during parsing: {str(e)}{tcolor.endcolor}")
            if enable_debug:
                import traceback
                print(traceback.format_exc())
            return {"VHOST": [], "REQUEST_URI": [], "FULL_URL": [], "CLIENT_IP_ADDRESS": []}
    
def output_to_file(output_data):
    """
    Outputs identified URLs into a newline-delimited file.
    """
    try:
        o_file = open(output_path, 'a')
        o_file.write(str(output_data) + '\n')
        o_file.close()
    except Exception as e:
        print('%s[!] Error writing to file. %s' % (tcolor.red, tcolor.endcolor))
        Exception_Handler(e)
        return(1)
    return(0)


class DBHandler():
    def __init__(self):
        global db
        try:
            self.conn = sqlite3.connect(db)
            self.c = self.conn.cursor()
        except Exception as e:
            print('%s[!] Error: SQLITE3-related error.%s' % (tcolor.red, tcolor.endcolor))
            Exception_Handler(e)
            print('\nExiting...')
            exit(0)

    def DB_initialize(self):
        """
        Initialize the DB.
        """
        self.c.execute("""CREATE TABLE IF NOT EXISTS "Data"( "FULL_URL" TEXT, "VHOST" TEXT, "REQUEST_URI" TEXT)""")
        self.c.execute("""CREATE TABLE IF NOT EXISTS "Identified_Clients"("IP_Address" TEXT)""")
        self.c.execute("""CREATE TABLE IF NOT EXISTS "Full_Logs"("Timestamp" TEXT, "IP_Address" TEXT, "VHOST" TEXT, "REQUEST_URI" TEXT, "FULL_URL" TEXT)""")
        self.conn.commit()

    def Add_Identified_URL(self, VHOST, REQUEST_URI, FULL_URL):
        """
        Adds identified URL into DB.
        """
        self.c.execute("""INSERT INTO Data VALUES(?,?,?)""", (FULL_URL, VHOST, REQUEST_URI, ))
        self.conn.commit()
        return(0)

    def Add_Identified_Client(self, IP_Address):
        """
        Adds identified Client's IP address into DB.
        """
        self.c.execute("""INSERT INTO Identified_Clients VALUES(?)""", (IP_Address, ))
        self.conn.commit()
        return(0)

    def Add_Full_Log(self, Timestamp, IP_Address, VHOST, REQUEST_URI, FULL_URL):
        """
        Responsible for adding data into Full_Logs.
        """
        self.c.execute("""INSERT INTO Full_Logs VALUES(?,?,?,?,?)""", (Timestamp, IP_Address, VHOST, REQUEST_URI, FULL_URL, ))
        self.conn.commit()
        return(0)

    def Check_If_URL_Exists(self, FULL_URL):
        """
        Checks if the URL exists on the DB.
        """
        self.c.execute("""SELECT "FULL_URL" FROM "Data" """)
        output = self.c.fetchall()
        for _ in output:
            if (_[0] == FULL_URL):
                return(True)
        return(False)

    def Check_If_Client_Exists(self, IP_Address):
        """
        Checks if the Client's IP address exists on the DB.
        """
        self.c.execute("""SELECT "IP_Address" FROM "Identified_Clients" """)
        output = self.c.fetchall()
        for _ in output:
            if (_[0] == IP_Address):
                return(True)
        return(False)

def main(url, full_logging=False):
    DBHandler().DB_initialize()
    error_limit = 20
    error_counter = 0
    
    while True:
        print(f"\n{tcolor.yellow}[*] Sending request to {url}{tcolor.endcolor}")
        output = Request_Handler().send_request(url)
        
        if not output:
            print(f"{tcolor.red}[!] Empty response received{tcolor.endcolor}")
            error_counter += 1
            if error_counter >= error_limit:
                print(f"{tcolor.red}[!] Too many empty responses. Exiting...{tcolor.endcolor}")
                exit(1)
            continue

        validate_output = Response_Handler().validate_response(output)
        
        if not validate_output:
            print(f"{tcolor.red}[!] Invalid response format{tcolor.endcolor}")
            error_counter += 1
            if error_counter >= error_limit:
                print(f"{tcolor.red}[!] Too many invalid responses. Exiting...{tcolor.endcolor}")
                exit(1)
        else:
            results = Response_Handler().parse_response(output)

            # Process URLs
            for i in range(len(results["FULL_URL"])):
                current_url = results["FULL_URL"][i]
                if current_url and not DBHandler().Check_If_URL_Exists(current_url):
                    try:
                        DBHandler().Add_Identified_URL(
                            results["VHOST"][i],
                            results["REQUEST_URI"][i],
                            current_url
                        )
                        print(f"[New URL]: {current_url}")
                    except Exception as e:
                        print(f"{tcolor.red}[!] Error adding URL to DB: {str(e)}{tcolor.endcolor}")
                    
                    if output_path:
                        output_to_file(current_url)

            # Process Client IPs
            for ip in results["CLIENT_IP_ADDRESS"]:
                if ip and not DBHandler().Check_If_Client_Exists(ip):
                    try:
                        DBHandler().Add_Identified_Client(ip)
                        print(f"{tcolor.purple}[New Client]:{tcolor.endcolor} {ip}")
                    except Exception as e:
                        print(f"{tcolor.red}[!] Error adding client IP to DB: {str(e)}{tcolor.endcolor}")

            # Full Logging
            if full_logging:
                timestamp = calendar.timegm(time.gmtime())
                for i in range(len(results["FULL_URL"])):
                    try:
                        DBHandler().Add_Full_Log(
                            timestamp,
                            results["CLIENT_IP_ADDRESS"][i],
                            results["VHOST"][i],
                            results["REQUEST_URI"][i],
                            results["FULL_URL"][i]
                        )
                    except Exception as e:
                        print(f"{tcolor.red}[!] Error adding to full log: {str(e)}{tcolor.endcolor}")

        # Sleep timer with countdown
        st = int(sleeping_time)
        while st != 0:
            print(f"{tcolor.light_blue}New request in {st} seconds...{tcolor.endcolor}", end='\r')
            time.sleep(1)
            st = st - 1

if __name__ == "__main__":
    try:
        main(url, full_logging=enable_full_logging)
    except KeyboardInterrupt:
        print('\nExiting...')
        exit(0)
    except Exception as e:
        Exception_Handler(e)
