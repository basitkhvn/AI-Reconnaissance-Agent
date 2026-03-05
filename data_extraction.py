from langgraph.graph import StateGraph, MessagesState, START, END
from typing import TypedDict,List
from langchain_core.messages import HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import whois

class info(TypedDict):
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
def whoislookup(domain: str) -> info:
        try:
            w=whois.whois(domain)
            domain_info: info= {"registrar":w["registrar"],"creation_date": formatdate(w.get("creation_date")),"expiry_date": formatdate(w.get("expiration_date")),"name_servers": w["name_servers"]}
            print(w["creation_date"])
            return domain_info
        except Exception as e:
             return {"error": str(e)}
        
    


check=whoislookup("google.oom")
print(check)