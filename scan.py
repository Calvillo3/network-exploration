import sys
import math
import json
import time
import subprocess
import requests
import socket
import urllib.request
import http.client

resolverslist = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6", "91.239.100.100",
                 "185.228.168.168", "77.88.8.7", "156.154.70.1", "198.101.242.72", "176.103.130.130"]

def function(input, output):
    file = open(input, 'r')
    lines = file.readlines()
    filelines = []
    json_object = {}
    for line in lines:
        object1 = {}   #reset the onject every time
        #print('Line:',line.strip())
        filelines.append(line.strip()) #each entru of file has \n at the end of it

        object1["scan_time"] = time.time()   #add scan time
        #result = subprocess.check_output(["nslookup", "-type=AAAA", line.strip(), "8.8.8.8"],
        #                        timeout=10, stderr=subprocess.STDOUT).decode("utf-8")
        #print(result)
        print(line)

        thesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #insecure http using socket.py
        location = (socket.gethostbyname(line.strip()), 80)
        check = thesocket.connect_ex(location)
        thesocket.close()
        if check == 0:  #insecure_http Part E
            object1["insecure_http"] = True
            #object1["redirect_to_https"] = checkstatus(line.strip(), 0)
            redirect_hsts = redirect(line.strip(), 0)
            object1["redirect_to_https"] = redirect_hsts[0]
            object1["hsts"] = redirect_hsts[1]
            #object1["tls_versions"] = findtls(line.strip()) #make sure to uncomment this line 
        else:
            object1["insecure_http"] = False
            object1["redirect_to_https"] = False
            object1["hsts"] = False
            object1["tls_versions"] = []

        try:    #this is the http_server part D
            response = requests.get("http://" + line.strip())
            try: server = response.headers['Server']
            except: server = None
        except: server = None
        object1["http_server"] = server
        object1["ipv6_addresses"] = ipparse(line, 'AAAA')
        object1["ipv4_addresses"] = ipparse(line, 'A')

        #tls versions
        #result = subprocess.check_output(["echo | openssl s_client -tls1_3 -connect", line.strip() + ":443",], timeout=1,
        #                                 stderr=subprocess.STDOUT).decode("utf-8")


        json_object[line.strip()] = object1   #finish the object


    with open(output, "w") as f:
        json.dump(json_object, f, sort_keys=True, indent=4)  #dump the entire file

def findtls(url):
    list = []
    #uncomment for now while not on moore
    result = ""
    try:
        result = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", url], timeout=8, stderr=subprocess.STDOUT).decode("utf-8")
        if "TLSv1.2" in result:
            list.append("TLSv1.2")
        if "TLSv1.1" in result:
            list.append("TLSv1.1")
        if "TLSv1.0" in result:
            list.append("TLSv1.0")
    except: pass
    try:
        result = subprocess.check_output(["echo", "|", "openssl", "s_client", "-tls1_3", "-connect", url + ":443"], timeout=3, stderr=subprocess.STDOUT).decode("utf-8")
        if "TLSv1.3" in result:
            list.append("TLSv1.3")
    except: pass
    return list

def redirect(url, check):
    if check > 9:
        return (False, False)
    if 'http://' in url:
        useless, url = url.split('http://')
        url = url[:-1] #remove final '/' for GET method
        connection = http.client.HTTPConnection(url)
        connection.request('GET', '/')
        response = connection.getresponse()
        secure = response.getheader('strict-transport-security')
        if response.status > 299 and response.status < 310:  # 30X status code
            loc = response.getheader('location')
            connection.close()
            if loc != None:
                return redirect(loc, check + 1)
        connection.close()
        if secure != None:
            return (False, True)
        else:
            return (False, False)
    elif 'https://' in url:
        useless, url = url.split('https://')
        url = url[:-1] #remove final '/' for GET method
        connection = http.client.HTTPSConnection(url)
        connection.request('GET', '/')
        response = connection.getresponse()
        secure = response.getheader('strict-transport-security')
        #if response.status > 199 and response.status < 300: #Good status code
        #    return True
        #elif response.status > 299 and response.status < 310:  # 30X status code
        #    loc = response.getheader('location')
        #    connection.close()
        #    if loc != None:
        #        return redirect(loc, check + 1)
        #    else:
        #        return False
        connection.close()
        if secure != None:
            return (True, True)
        else:
            return (True, False)
    connection = http.client.HTTPConnection(url)
    connection.request('GET', '/')
    response = connection.getresponse()
    secure = response.getheader('strict-transport-security')
    if response.status > 299 and response.status < 310: #30X status code
        loc = response.getheader('location')
        connection.close()
        if loc != None:
            return redirect(loc, check + 1)
    connection.close()
    if secure != None:
        return (False, True)
    else:
        return (False, False)

def ipparse(url, type):
    fullarr = []
    if type == 'AAAA':
        for curr in resolverslist:
            try:
                result = subprocess.check_output(["nslookup", "-type=AAAA", url.strip(), curr], timeout=1, stderr=subprocess.STDOUT).decode("utf-8")
                if "Non-existent domain" in result:
                    continue
                if "No IPv6 address" in result:
                    continue
                useless, useful = result.split("Name:  ")
                try: useless, useful = useful.split("Addres")
                except: return []
                try:
                    useful, useless = useful.split("\r\n\r\n", 1)
                except:
                    pass
                useless, useful = useful.split(":  ", 1)
                try:
                    useful = useful.split()
                except:
                    pass
                for i in useful:
                    if i not in fullarr:
                        fullarr.append(i)
            except: pass
        return fullarr
    if type == 'A':
        for curr in resolverslist:
            try:
                result = subprocess.check_output(["nslookup", "-type=A", url.strip(), curr], timeout=1, stderr=subprocess.STDOUT).decode("utf-8")
                if "Non-existent domain" in result:
                    continue
            #print(result)
                useless, useful = result.split("Name:  ")
                useless, useful = useful.split("Addres")
                try: useful, useless = useful.split("\r\n\r", 1)
                except: pass
                try: useful, ueseless = useful.split("Aliases:", 1)
                except:
                    pass
                useless, useful = useful.split(":  ", 1)
                try: useful = useful.split( )
                except: pass
                for i in useful:
                    if i not in fullarr:
                        fullarr.append(i)
            except: pass
        return fullarr
        #useless, useful = useful.split("Address:  ")
        #try: useless, useful = useful.split("\r\n", 1)
        #while True:
        #    try: newstring


if __name__ == '__main__':
    function(sys.argv[1], sys.argv[2])