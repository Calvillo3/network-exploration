import json
import texttable
import sys




def function(input, output):
    f = open(input,)
    g = open(output, "w")
    data = json.load(f)
    count = 0.0
    tls1count = 0.0
    tls2count = 0.0
    tls0count = 0.0
    tls3count = 0.0
    insecure = 0.0
    redirect = 0.0
    hsts = 0.0
    ipv6 = 0.0
    webservers = {}
    roots = {}
    time = {}
    #table = texttable.Texttable()
    #table.add_row(["Domain", "scan_time", "ipv4_addresses", "ipv6_addresses", "http_server",
    #               "insecure_http","redirect_to_https","hsts","tls_versions","root_ca","rdns_names","rtt_range","geo_locations"])


    for i in data:
        count += 1.0
        table = texttable.Texttable()
        #table.add_row(["Domain", "scan_time", "ipv4_addresses", "ipv6_addresses", "http_server",
        #               "insecure_http", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names",
        #               "rtt_range", "geo_locations"])
        #table.add_row([i, data[i]["scan_time"],data[i]["ipv4_addresses"],data[i]["ipv6_addresses"],data[i]["http_server"],
        #               data[i]["insecure_http"],data[i]["redirect_to_https"],
        #               data[i]["hsts"],data[i]["tls_versions"],data[i]["root_ca"],data[i]["rdns_names"],data[i]["rtt_range"],data[i]["geo_locations"]])

        table.add_rows([["Domain", i],
                        ["scan_time", data[i]["scan_time"]],
                        ["ipv4_addresses",data[i]["ipv4_addresses"]],
                        ["ipv6_addresses",data[i]["ipv6_addresses"]],
                        ["http_server",data[i]["http_server"]],
                        ["insecure_http",data[i]["insecure_http"]],
                        ["redirect_to_https",data[i]["redirect_to_https"]],
                        ["hsts",data[i]["hsts"]],
                        ["tls_versions",data[i]["tls_versions"]],
                        ["root_ca",data[i]["root_ca"]],
                        ["rdns_names",data[i]["rdns_names"]],
                        ["rtt_range",data[i]["rtt_range"]],
                        ["geo_locations",data[i]["geo_locations"]]])
        ##Part 2
        time[i] = data[i]['rtt_range']

        ##Part 3
        if data[i]['root_ca'] not in roots:
            roots[data[i]['root_ca']] = 1
        else:
            roots[data[i]['root_ca']] += 1

        ##Part 4
        if data[i]['http_server'] not in webservers:
            webservers[data[i]['http_server']] = 1
        else: webservers[data[i]['http_server']] +=1

        ##Part 5
        if "TLSv1.0" in data[i]['tls_versions']:
            tls0count +=1.0
        if "TLSv1.1" in data[i]['tls_versions']:
            tls1count +=1.0
        if "TLSv1.2" in data[i]['tls_versions']:
            tls2count +=1.0
        if "TLSv1.3" in data[i]['tls_versions']:
            tls3count +=1.0
        if data[i]['insecure_http']:
            insecure += 1.0
        if data[i]['redirect_to_https']:
            redirect +=1.0
        if data[i]['hsts']:
            hsts +=1.0
        if data[i]['ipv6_addresses']:
            ipv6 += 1.0
        #print(table.draw())
        g.write(table.draw())
        g.write('\r\n\r\n')

    #for i in roots:
    #    print(i, roots[i])
    tls0count = tls0count / count
    tls1count = tls1count / count
    tls2count = tls2count / count
    tls3count = tls3count / count
    insecure = insecure / count
    redirect = redirect / count
    hsts = hsts / count
    ipv6 = ipv6 / count
    time = {k: v for k, v in sorted(time.items(), key=lambda item: item[1][0])}
    roots = {k: v for k, v in sorted(roots.items(), key=lambda item: item[1], reverse=True)} #order them largest to smallest
    webservers = {k: v for k, v in sorted(webservers.items(), key=lambda item: item[1], reverse=True)} #order again
    table2 = texttable.Texttable()
    table2.set_cols_align(["c","c"])
    table2.set_cols_valign(["m","m"])
    table2.add_row(["Domain", "RTT"])
    for i in time:
        table2.add_row([i, time[i]])
    #print(table2.draw())
    table3 = texttable.Texttable()
    table3.set_cols_align(["c", "c"])
    table3.set_cols_valign(["m", "m"])
    table3.add_row(["Root Cert Authority", "Frequency"])
    for i in roots:
        table3.add_row([i, roots[i]])
    #print(table3.draw())
    table4 = texttable.Texttable()
    table4.set_cols_align(["c", "c"])
    table4.set_cols_valign(["m", "m"])
    table4.add_row(["Server", "Frequency"])
    for i in webservers:
        table4.add_row([i, webservers[i]])
    #print(table4.draw())
    table5 = texttable.Texttable()
    table5.set_cols_align(["c", "c"])
    table5.set_cols_valign(["m", "m"])
    table5.add_rows([["Category", "Frequency (%)"],
                    ["TLSv1.0", tls0count],
                     ["TLSv1.1", tls1count],
                     ["TLSv1.2", tls2count],
                     ["TLSv1.3", tls3count],
                     ["plain http", insecure],
                     ["https redirect", redirect],
                     ["hsts", hsts],
                     ["ipv6", ipv6]])
    #print(table5.draw())
    g.write(table2.draw())
    g.write('\r\n\r\n')
    g.write(table3.draw())
    g.write('\r\n\r\n')
    g.write(table4.draw())
    g.write('\r\n\r\n')
    g.write(table5.draw())
    g.write('\r\n\r\n')
    g.close()


    #print(time)
    #print(tls0count, tls1count, tls2count, tls3count)
    #print(insecure)
    #print(redirect)
    #print(hsts)
    #print(ipv6)

    f.close()
if __name__ == '__main__':
    function(sys.argv[1], sys.argv[2])