from requests import get
from re import findall, sub
from json import loads
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr
from subprocess import check_output
from PyQt5 import QtCore

# def processable(processable_func):
#     """ Function decorator. Grays out the application and sets the PROCESSING overlay on, executes the given function and disables the overlay. """
#     def wrapper(*args, **kwargs):
#         enable_loading_overlay(ui.processingLabel)
#         processable_func(*args, **kwargs)
#         disable_loading_overlay(ui.processingLabel)
#     return wrapper

# def trace(addr, args = '-w 3 -h 50 -d'):
#     """ Returns a tuple of (a tuple of subsequent addresses) and (amount of timeouts as string). Wraps tracert via subprocess.check_output

#     -w int = timeout
#     -h int = maximum hops
#     -d = do not resolve addresses"""
#     if  len(addr) < 1:
#         return None, None
#     arr = check_output('tracert' + ' ' + args + ' ' + addr).decode('utf-8')
#     if 'Unable to resolve' in arr:
#         return None, None
#     timeouts = arr.count("Request timed out.")
#     arr = regex.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', arr)
#     return (arr, str(timeouts))

def reverseIP(ip):
    """ Reverses the order of octets in the IPv4 address """
    return '.'.join(reversed(ip.split('.')))

def tracert(dst):
    """ A scapy-based implementation of Window's tracert. Returns IP addresses only, without latency measurements. Automatic address resolving."""

    if len(findall(r"""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""", dst)) == 0:
        dst = dns(dst)

    ttl = 1
    ips = []
    current_dst = ''
    data = '\0' * 64
    while current_dst != dst:
        QtCore.QCoreApplication.processEvents()
        try:
            current_dst = sr(IP(dst=dst, ttl=ttl)/ICMP()/data, retry=2, timeout=1, verbose=False)[0][0][1].src
        except IndexError:
            ttl += 1
            ips.append('timeout')
            continue
        ttl += 1
        ips.append(current_dst)
    return ips

def dns(addr):
    js = loads(get('https://dns-api.org/A/' + (addr if not addr.startswith('www.') else addr[4:])).content)
    try:
        return js[0]['value']
    except:
        raise Exception('Unresolvable address')

def reverse_dns_hackertarget(ip):
    """ Resolves addresses via hackertarget.com. 100 requests per day. """
    response = get('https://api.hackertarget.com/reversedns/?q=' + ip).text
    if response != 'no records found':
        return response.replace(ip, '').strip()
    return None

def reverse_dns_google(ip):
    """ IP resolution via Google's DNS, pass IP as string. Return is None if not resolved, or string if resolved"""
    response = get('https://dns.google.com/resolve?name=' + reverseIP(ip) + '.in-addr.arpa&type=PTR')
    jsonned = loads(response.text)
    try:
        return jsonned['Answer'][0]['data']
    except KeyError:
        return None

def reverse_dns_nslookup(ip, dns_server = '8.8.8.8'):
    """ Resolves addresses via calling nslookup, defaults to google's 8.8.8.8 DNS server. Returns None if no match."""
    ns = check_output('nslookup ' + ip + ' ' + dns_server).decode()
    if ns.count('Name:'):
        # entering the try-except block as different ending lines might break the regex
        try:
            nameline = findall("""\r?\nName.*?\r?\n""", ns)[0]
            nameline = sub("""\r?\nNa.*? (?=[a-zA-Z])""", '', nameline)
        except:
            return None
        return nameline.strip()
    return None
    
def get_own_address(https = False):
    """ Returns own external address by calling api.ipify.org via requests module. HTTP by default"""
    api_address = 'http' + ('s' if https == True else '') + '://api.ipify.org/'
    return get(api_address).text

def check_addresses(addresses, key = 'at_ZSL2SY85dqgF5P1TD1AB5Sk0TPbQw'):
    """ Returns a list of json-formatted information about the address(es) provided. The argument must be a string for one address, or a list of strings for multiple addresses. Processed via geo.ipify.org, which requires a free, email-bound key. 1000 addresses per month per free key.
        
    There is a default key supplied."""
    addresses = addresses if type(addresses) == list else [addresses]
    addresses_json = []
    for address in addresses:
        QtCore.QCoreApplication.processEvents()
        response = get('https://geo.ipify.org/api/v1?apiKey=' + key + '&ipAddress=' + str(address))
        addresses_json.append(response.text)
    return addresses_json

def enable_loading_overlay(widget):
    widget.setVisible(True)

def disable_loading_overlay(widget):
    widget.setHidden(True)

def download_map(latitude, longitude, *, map_type = 'map', pixel_width = '541', pixel_height = '511', zoom = '3', map_format = 'jpg'):
    """ Downloads a binary string of a raster map of the chosen location via www.mapquestapi.com. Max X downloads per month.
    
    type = map/hyb/sat/light/dark"""
    
    url = 'https://www.mapquestapi.com/staticmap/v5/map?key=5vFGDlfYUcnwaCvFVxLutfLf5D5YANOg' \
    + '&format='+ str(map_format) \
    +'&size=' + str(pixel_width) + ',' + str(pixel_height) \
    + '&type=' + str(map_type) \
    + '&zoom=' + str(zoom) \
    + '&center=' + str(latitude) + ',' + str(longitude) \
    + '&locations=' + str(latitude) + ',' + str(longitude) \
    + '|via-sm-ff0000-000000'
    
    return get(url).content

def prepare_data(ip, dns = 'google'):
    """ Doc - to be written
    DNS:
    hackertarget = DEFAULT - https://hackertarget.com Public DNS API, max 100 requests per day
    nslookup = nslookup to 8.8.8.8, Google's public DNS server
    google = Public Google DNS API"""
    tracert_results = tracert(ip)
    tracert_results[0] = get_own_address()
    final = [[] for x in range(0, len(tracert_results))]
    for counter, value in enumerate(tracert_results):
        QtCore.QCoreApplication.processEvents()
        if value == 'timeout':
            final[counter].append('IPv4: timed out')
            final[counter].append('Resolved: not resolved')
            final[counter].append(None)
            final[counter].append(None)
            continue
        final[counter].append("IPv4: " + value)

        if dns == 'hackertarget':
            resolved = reverse_dns_hackertarget(value)
        elif dns == 'google':
            resolved = reverse_dns_google(value)
        else:
            resolved = reverse_dns_nslookup(value)
        
        final[counter].append("Resolved: " + (str(resolved) if resolved != None else 'not resolved'))
        
        try:
            json_data = loads(check_addresses(value)[0])
        except:
            final[counter].append(None)

        if json_data['location']['lat'] != 0 or json_data['location']['lng'] != 0:
            QtCore.QCoreApplication.processEvents()
            final[counter].append(download_map(str(json_data['location']['lat']), str(json_data['location']['lng'])))
        else:
            final[counter].append(None)

        for dict_key, dict_val in json_data['location'].items():
            QtCore.QCoreApplication.processEvents()
            final[counter].append(str(dict_key) + ': ' + str(dict_val))
            
    return final, tracert_results.count('timeout')