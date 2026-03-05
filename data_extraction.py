from langgraph.graph import StateGraph, MessagesState, START, END
from typing import TypedDict,List
from langchain_core.messages import HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import whois
import dns.resolver

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
            print(w["creation_date"])
            return domain_info
        except Exception as e:
             return {"error": str(e)}
# fetch A and MX records   
def dns_lookup(domain):
     records={"A":[],"MX":[]}
     try:
          arecords=dns.resolver.resolve(domain,'A')
          for rdata in arecords:
               records["A"].append(str(rdata))
     except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass 
     try:
           mxrecords=dns.resolver.resolve(domain,'MX')
           for mxdata in mxrecords:
                records["MX"].append(str(mxdata))
     except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass # No MX records found
     return records
  
domain="google.com"
check=whoislookup(domain)
print(f"Printing the whoislookup info: {check}")
dnscheck=dns_lookup(domain)
print(f"\nPrinting the dns info: {dnscheck}")

