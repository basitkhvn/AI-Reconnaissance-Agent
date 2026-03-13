from langgraph.graph import StateGraph, MessagesState, START, END
from typing import TypedDict,List
from langchain_core.messages import HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import whois
import dns.resolver
import os
import certifi
import requests

from Wappalyzer import Wappalyzer, WebPage

os.environ['SSL_CERT_FILE'] = certifi.where()
os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()
class whoisinfo(TypedDict):
    registrar: str
    creation_date: str
    expiry_date: str
    name_servers: list
    error: str    
     
def formatdate(date):
     if isinstance(date,list):
          return str(date[0])
     elif isinstance(date,str):
          return str(date)
def whoislookup(domain: str) -> whoisinfo:
        try:
            w=whois.whois(domain)
            domain_info: whoisinfo= {"registrar":w["registrar"],"creation_date": formatdate(w.get("creation_date")),"expiry_date": formatdate(w.get("expiration_date")),"name_servers": w["name_servers"]}
            return domain_info
        except Exception as e:
             return {"error": str(e)}
# fetch A and MX records   
# def dns_lookup(domain):
#      records={"A":[],"MX":[]}
#      try:
#           arecords=dns.resolver.resolve(domain,'A')
#           for rdata in arecords:
#                records["A"].append(str(rdata))
#      except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
#         pass 
#      try:
#            mxrecords=dns.resolver.resolve(domain,'MX')
#            for mxdata in mxrecords:
#                 records["MX"].append(str(mxdata))
#      except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
#         pass # No MX records found
#      return records
import dns.resolver

def dns_lookup(domain):
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": []
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)

            for rdata in answers:
                if rtype == "MX":
                    records["MX"].append(str(rdata.exchange))
                elif rtype == "TXT":
                    txt_content = "".join([s.decode('utf-8') for s in rdata.strings])
                    records["TXT"].append(txt_content)
                else:
                    records[rtype].append(str(rdata))

        except (dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.resolver.Timeout):
            continue

    return records
import requests
import ssl
import socket
def header_lookup(domain):
     headers={"Content-Security-Policy": "missing","X-Frame-Options": "missing", "Strict-Transport-Security": "missing", "X-Content-Type-Options": "missing"}
     # we also need to check if the ssl certificates are valid or not

     try:
          response=requests.get(f"https://{domain}")
          answer=response.headers
          for i in headers:
               if i in answer:
                    headers[i]=answer[i]
     except Exception as e:
          return {"error":f"{e}"}
          
     return headers
def ssl_lookup(domain):
     sslvalues = {"issuer": "missing", "expiry": "missing"}
     context = ssl.create_default_context()
     try:
          with socket.create_connection((domain, 443)) as sock:
               with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    sslvalues["issuer"]=issuer.get("organizationName")

                    sslvalues["expiry"]=cert["notAfter"]
                    return sslvalues
     except Exception as e:
          return {"Error": f"{e}"}

               
def subdomain_lookup(domain):
     url=f"https://crt.sh/?q=%.{domain}&output=json"  
     response = requests.get(url)
     sblist=[]
     try:
          data= response.json()
          for i in data:
               subdomains=i["name_value"]
               subdomains=subdomains.splitlines()
               for j in subdomains:
                    sblist.append(j)
          realsubs=list(set(sblist)) # we want to remove duplicates     
          return {"subdomains": realsubs}
     except Exception as e:
           return {"error": str(e)}
import nmap 
def port_scan_node(domain):

    nm = nmap.PortScanner()
    #nm.scan(domain, '1-1024')
    try:
       nm.scan(domain, '80,443,22,21,8080,8443,3306,5432,6379,27017')
       open_ports = []
       for host in nm.all_hosts():
          for proto in nm[host].all_protocols():
               ports = nm[host][proto].keys()
               for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                         open_ports.append(port)

       return {"open_ports": open_ports}
    except Exception as e:
         return {"error": str(e)}

def tech_lookup(domain):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(f"https://{domain}")
        technologies = wappalyzer.analyze(webpage)

        return {"technologies": list(technologies)}

    except Exception as e:
        return {"error": str(e)}
domain="facebook.com"
# check=whoislookup(domain)
# print(f"Printing the whoislookup info: {check}")
# dnscheck=dns_lookup(domain)
# print(f"\nPrinting the dns info: {dnscheck}")

print(subdomain_lookup('google.com'))