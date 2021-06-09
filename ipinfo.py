import argparse
import requests
import requests_html
import json
from datetime import date, timedelta
from pyfiglet import figlet_format  # fonts http://www.figlet.org/examples.html

class ip_info:
    def __init__(self):
        pass

    def get_info(self, ip):
        r = requests.get('http://ip-api.com/json/' + ip + '?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query')
        info = json.loads(r.text)

        if (info['status'] != "success"):
            print("Invalid IP address")
            exit()

        print("IP: " + info['query'])
        print("\n[+] Continent: " + info['continent'])
        print("[+] Continent: " + info['continentCode'])
        print("[+] Country: " + info['country'])
        print("[+] Country Code: " + info['countryCode'])
        print("[+] Region: " + info['regionName'])
        print("[+] City: " + info['city'])
        print("[+] Zip: " + info['zip'])
        print("[+] Latitude: " + str(info['lat']))
        print("[+] Longitude: " + str(info['lon']))
        print("[+] ISP: " + info['isp'])
        print("[+] ORG: " + info['org'])
        print("[+] ASN: " + info['as'])
        print("[+] ASN Name: " + info['asname'])
        print("[+] Reverse: " + info['reverse'])
        print("[+] Mobile: " + str(info['mobile']))
        print("[+] Proxy: " + str(info['proxy']))
        print("[+] Hosting: " + str(info['hosting']))

    def get_addinfo(self, ip):
        r = requests.get('https://ipwhois.app/json/' + ip)
        add_info = json.loads(r.text)
        print("[+] Currency: " + add_info['currency'])
        print("[+] Currency Code: " + add_info['currency_code'])
        print("[+] Currency Symbol: " + add_info['currency_symbol'])
        print("[+] Currency Rates: " + add_info['currency_rates'])
        print("[+] Currency Plural: " + add_info['currency_plural'])
        print("[+] Timezone: " + add_info['timezone'])
        print("[+] Timezone Name: " + add_info['timezone_name'])
        print("[+] Timezone DST Offset: " + add_info['timezone_dstOffset'])
        print("[+] Timezone GMT Offset: " + add_info['timezone_gmtOffset'])
        print("[+] Timezone GMT: " + add_info['timezone_gmt'])
        print("[+] Country Neighbors: " + add_info['country_neighbours'])

    def checkTor(self, ip):
        today = date.today()
        b4_yesterday = today - timedelta(days=2)

        url = 'https://metrics.torproject.org/exonerator.html?ip=' + ip + '&timestamp=' + str(b4_yesterday) + '&lang=en'

        try:
            session = requests_html.HTMLSession()
            response = session.get(url)
        except requests.exceptions.RequestException as e:
            print(e)

        r = response.html.find('.panel-body', first=True).text
        print("[+] - " + r)

    def checkBlacklist(self, ip):

        url = 'https://www.abuseipdb.com/check/' + ip

        try:
            session = requests_html.HTMLSession()
            response = session.get(url)
        except requests.exceptions.RequestException as e:
            print(e)

        r = response.html.find('p', containing='This IP address has been reported')

        if r:
            for x in r:
                print("[+] -" + x.text)
        else:
            print("[+] - This IP address has not been reported")

    def checkCVEPorts(self, ip):
        # Get CVEs and Open Ports: https://spyse.com/target/ip/78.47.211.252
        url = 'https://spyse.com/target/ip/' + ip
        try:
            session = requests_html.HTMLSession()
            response = session.get(url)
        except requests.exceptions.RequestException as e:
            print(e)

        r = response.html.find('.security-block', first=True).text
        risks = r.split("\n")

        # Accessing directly to the array elements because the response will always have the same format
        print("[+] - Security Score: " + risks[1])
        print("[+] - " + risks[2])
        print("[#] / Critical risk: " + risks[4])
        print("[#] / Medium risk: " + risks[6])
        print("[#] / Medium risk: " + risks[8])

        r = response.html.find('.cve__id')
        if r:
            print("\n[+] - CVEs number: ")
            for x in r:
                print("[#] / " + x.text)

        print("\nChecking if IP has open ports")
        r = response.html.find('.port__value')
        if r:
            # Formatting output, deleting repeated ports
            ports = []
            for x in r:
                if x not in ports:
                    ports.append(x.text)
            ports = set(ports)
            for x in ports:
                print("[+] - " + x + " (Open)")
        else:
            print("[+] - No open ports")

    def main(self, args):
        ip = args.ip
        print("\nGeneral Info:")
        self.get_info(ip)
        print("\nAdditional Info:")
        self.get_addinfo(ip)
        print("\nChecking if the IP was used as a TOR relay:")
        self.checkTor(ip)
        print("\nChecking if the IP has been reported:")
        self.checkBlacklist(ip)
        print("\nChecking IP security score:")
        self.checkCVEPorts(ip)


if __name__ == "__main__":
    print("###################################################################")
    print(figlet_format("                  IPinfo", font="standard"))
    print("###################################################################")

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, help='The target IP.', required=True)

    args = parser.parse_args()
    p = ip_info()
    p.main(args)
