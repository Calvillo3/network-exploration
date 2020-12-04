import sys
import json
import time
import subprocess
import requests
import socket
import maxminddb
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
        #print(line)

        thesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #insecure http using socket.py
        thesocket.settimeout(5.0)
        location = (socket.gethostbyname(line.strip()), 80)
        check = thesocket.connect_ex(location)
        thesocket.close()
        if check == 0:  #insecure_http Part E
            object1["insecure_http"] = True
            #object1["redirect_to_https"] = checkstatus(line.strip(), 0)
            redirect_hsts = redirect(line.strip(), 0)
            object1["redirect_to_https"] = redirect_hsts[0]
            object1["hsts"] = redirect_hsts[1]
            object1["tls_versions"] = findtls(line.strip()) #make sure to uncomment this line
            object1["root_ca"] = root_ca(line.strip())
        else:
            object1["insecure_http"] = False
            object1["redirect_to_https"] = False
            object1["hsts"] = False
            object1["tls_versions"] = []
            object1["root_ca"] = None


        #try:    #this is the http_server part D
        #    response = requests.get("http://" + line.strip())
        #    try:
        #        server = response.headers['Server']
        #        print('old: ',server)
        #    except: server = None
        #except: server = None
        object1["http_server"] = serverhttp(line.strip())
        #object1["ipv6_addresses"] = ipparse(line, 'AAAA')
        #object1["ipv4_addresses"] = ipparse(line, 'A')
        object1["ipv6_addresses"] = ipparsemoore(line, 'AAAA')
        object1["ipv4_addresses"] = ipparsemoore(line, 'A')
        #print(line.strip() + ":443")

        object1["rdns_names"] = findrdns(object1["ipv4_addresses"])
        object1["rtt_range"] = rtt(object1["ipv4_addresses"])
        #geo location
        object1["geo_locations"] = geolocate(object1["ipv4_addresses"])

        json_object[line.strip()] = object1   #finish the object
    with open(output, "w") as f:
        json.dump(json_object, f, sort_keys=True, indent=4)  #dump the entire file


def serverhttp(url):
    #print('waiting')
    string = "GET / HTTP/1.0\r\nHost: " + url + "\r\n\r\n"
    string = string.encode('utf-8')
    try:
        result = subprocess.check_output(["openssl", "s_client", "-connect", url + ":443", "-ign_eof", "-quiet"],
                                  input=string, stderr=subprocess.STDOUT,
                                  timeout=2).decode('utf-8')
        #print(result)
        if "Server: " in result:
            useless, useful = result.split("Server: ", 1)
            useful, useless = useful.split('\r\n', 1)
            return useful
        elif "server: " in result:
            useless, useful = result.split("server: ", 1)
            useful, useless = useful.split('\r\n', 1)
            return useful
        else: return None
    except: return None

def geolocate(ips):
    reader = maxminddb.open_database('GeoLite2-City.mmdb')
    arr = []
    for i in ips:
        city = ""
        country = ""
        state = ""
        full = ""
        try:
            val = reader.get(i)
            #print(val)
            try:
                country = val['country']['names']['en']
                city = val['city']['names']['en']
                state = val['subdivisions'][0]['names']['en']
            except: pass
            #print(city, state, country)
        except:
            pass
        if city != "":
            full = city + ", "
        if state != "":
            full += state + ", "
        if country != "":
            full += country
        if full != "" and full not in arr:
            arr.append(full)
    reader.close()
    return arr

def rtt(ips):
    min = float('inf')
    max = -1.0
    temp = 0.0
    for i in ips:
        try:
            result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet " + i + " 443"],
                                    timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            useless, useful = result.split('real', 1)
            useless, useful = useful.split('m', 1)
            useful, useless = useful.split('s', 1)
            temp = float(useful)
            #print(result)
            if temp > max:
                max = temp
            if temp < min:
                min = temp
        except:
            #print('exception1')
            try:
                result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet " + i + " 80"],
                                                 timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                useless, useful = result.split('real', 1)
                useless, useful = useful.split('m', 1)
                useful, useless = useful.split('s', 1)
                temp = float(useful)
                #print(result)
                if temp > max:
                    max = temp
                if temp < min:
                    min = temp
            except:
                try:
                    result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet " + i + " 22"],
                                                     timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    useless, useful = result.split('real', 1)
                    useless, useful = useful.split('m', 1)
                    useful, useless = useful.split('s', 1)
                    temp = float(useful)
                    #print(result)
                    if temp > max:
                        max = temp
                    if temp < min:
                        min = temp
                except:
                    pass
                    #print('exception2')
    if min == float('inf'):
        return None
    return [int(min*1000), int(max*1000)]
def findrdns(ips):
    rdarray = []
    for i in ips:
        try:
            result = subprocess.check_output(["nslookup", "-type=PTR", i], timeout=2, stderr=subprocess.STDOUT).decode(
                "utf-8")
            if "NXDOMAIN" in result:
                continue
            if "SERVFAIL" in result:
                continue
            useless, useful = result.split("Non-authoritative", 1)
            useful, useless = useful.split("Authoritative", 1)
            newarr = useful.splitlines( )
            for j in newarr:
                if "name" in j:
                    old, new = j.split("name = ",1)
                    if new not in rdarray:
                        rdarray.append(new[:-1]) #remove . at the end of each server name, could cause issues later
        except:
            continue
    return rdarray


def findtls(url):
    list = []
    #uncomment for now while not on moore
    result = ""
    try:
        result = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", url], timeout=8, stderr=subprocess.DEVNULL).decode("utf-8")
        if "TLSv1.2" in result:
            list.append("TLSv1.2")
        if "TLSv1.1" in result:
            list.append("TLSv1.1")
        if "TLSv1.0" in result:
            list.append("TLSv1.0")
    except:
        pass
    #print(url + ":443")
    try:
        result = subprocess.check_output(["openssl", "s_client", "-tls1_3", "-connect", url + ":443"], input="", stderr=subprocess.DEVNULL, timeout=3).decode("utf-8") #add q here
        #print('uh oh')
    except:
        pass
    #print(result)
    if "TLSv1.3" in result:
        list.append("TLSv1.3")
    return list

def redirect(url, check):
    #print(url)
    if check > 9:
        return (False, False)
    if 'http://' in url:
        useless, url = url.split('http://')
        #url = url[:-1] #remove final '/' for GET method
        try: url, extension = url.split('/', 1)
        except:
            extension = ""
        try:
            connection = http.client.HTTPConnection(url, timeout=4)
            connection.request('GET', '/' + extension)
            response = connection.getresponse()
        except: return (False,False)
        if response.status >= 400:
            return (False, False)
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
        #url = url[:-1] #remove final '/' for GET method
        try: url, extension = url.split('/', 1)
        except:
            extension = ""
        try:
            connection = http.client.HTTPSConnection(url, timeout=4)
            connection.request('GET', '/' + extension)
            response = connection.getresponse()
            secure = response.getheader('strict-transport-security')
        except: return (False, False)
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
    try:
        connection = http.client.HTTPConnection(url, timeout=4)
        connection.request('GET', '/')
        response = connection.getresponse()
    except: return (False, False)
    if response.status >= 400:
        return (False, False)
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
                #print(result)
                if "Non-existent domain" in result:
                    continue
            #print(result)
                useless, useful = result.split("Name:  ")
                #print(useful)
                useless, useful = useful.split("Addres")
                #print(useful)
                try: useful, useless = useful.split("\r\n\r", 1)
                except: pass
                #print(useful)
                try: useful, ueseless = useful.split("Aliases:", 1)
                except:
                    pass
                useless, useful = useful.split(":  ", 1)
                #print(useful)
                try: useful = useful.split( )
                except: pass
                #print(useful)
                for i in useful:
                    if i not in fullarr:
                        fullarr.append(i)
            except: pass
        return fullarr
        #useless, useful = useful.split("Address:  ")
        #try: useless, useful = useful.split("\r\n", 1)
        #while True:
        #    try: newstring
def ipparsemoore(url, type):
    fullarr = []
    if type == 'AAAA':
        for curr in resolverslist:
            try:
                result = subprocess.check_output(["nslookup", "-type=AAAA", url.strip(), curr], timeout=2,
                                             stderr=subprocess.STDOUT).decode("utf-8")
                if "Non-existent domain" in result:
                    continue
                if "No IPv6 address" in result:
                    continue
                useless, result = result.split("Name:", 1)
                lines = result.splitlines()
                for i in lines:
                    #print(i)
                    if "Address: " in i:
                        #print('HITHITHITHIHTIH')
                        uselss, answer = i.split("Address: ", 1)
                        #print(useless)
                        #print(answer)
                        if answer not in fullarr:
                            fullarr.append(answer)
            except: pass
        return fullarr
    elif type == 'A':
        for curr in resolverslist:
            try:
                result = subprocess.check_output(["nslookup", "-type=A", url.strip(), curr], timeout=2,
                                             stderr=subprocess.STDOUT).decode("utf-8")
                if "Non-existent domain" in result:
                    continue
                useless, result = result.split("Name:", 1)
                lines = result.splitlines( )
                for i in lines:
                    #print(i)
                    if "Address: " in i:
                        #print('HITHIHTIHTIHTIHTIHT')
                        useless, answer = i.split("Address: ")
                        #print("useless: ",useless)
                        #print('ANSWER: ',answer)
                        if answer not in fullarr:
                            fullarr.append(answer)
            except: pass
        return fullarr
def root_ca(url):
    answer = None
    try:
        resultt = subprocess.check_output(["openssl", "s_client", "-connect", url + ":443"], input="", stderr=subprocess.STDOUT, timeout=2).decode("utf-8")
        useless, string1 = resultt.split("Certificate chain", 1) #gets the text for the chain.
        string1, useless = string1.split("Server certificate", 1)
        arr = string1.split("O = ")
        answer, rest = arr[-1].split(',', 1)
        if answer == "":
            return None
    except:
        pass
    return answer

if __name__ == '__main__':
    function(sys.argv[1], sys.argv[2])