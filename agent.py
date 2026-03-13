from typing import TypedDict
from data_extraction import whoislookup,dns_lookup,header_lookup,ssl_lookup,subdomain_lookup,port_scan_node,tech_lookup
from langgraph.graph import StateGraph, MessagesState, START, END
from typing import TypedDict,List
from langchain_core.messages import HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import json
load_dotenv()
llm=ChatGoogleGenerativeAI(model="gemini-2.5-flash")
class ReconState(TypedDict):
    domain: str
    whoisdata: dict
    dns_data: dict
    header_data: dict
    ssl_data: dict
    reasoning: str
    decisions: list
    risk_scores: list
    attack_map: str
    report: str
    subdomains: list
    open_ports: list
    technologies: list

def whois_node(state: ReconState):
        d=state["domain"]
        response=whoislookup(d)
        
        return {"whoisdata": response}
    
def dns_node(state: ReconState):
        d=state["domain"]
        response=dns_lookup(d)
        return {"dns_data": response}
def subdomain_node(state: ReconState):
    d = state["domain"]
    response = subdomain_lookup(d)
    return {"subdomains": response}
def ports_node(state: ReconState):
    d = state["domain"]
    response = port_scan_node(d)
    return {"open_ports": response}

def tech_node(state: ReconState):
    d = state["domain"]
    response = tech_lookup(d)
    return {"technologies": response}
def header_node(state: ReconState):
        d=state["domain"]

        response=header_lookup(d)

        return {"header_data": response}

def ssl_node(state: ReconState):
        d=state["domain"]
        response=ssl_lookup(d)

        return {"ssl_data": response}
def reasoning_node(state: ReconState):
       llm_msg={"whoisdata":state["whoisdata"],
                "dns_data": state["dns_data"],
                "header_data": state["header_data"],
                "ssl": state["ssl_data"],
                "subdomains": state["subdomains"],
                "open_ports": state["open_ports"],
                "technologies": state["technologies"]}
       msg = f"""
                You are a security analyst.

                Analyze the following reconnaissance data and identify potential vulnerabilities.

                Data:
                {json.dumps(llm_msg, indent=2)}
                """
       try:
             result= llm.invoke(msg)
             return {"reasoning": result.content}
       except Exception as e:
             result = {"error": str(e)}
             return {"reasoning": result}
       

import json

def decision_node(state: ReconState):

    reasoning = state["reasoning"]

    msg = f"""
    You are a cybersecurity analyst.

    Extract the specific security issues from the reasoning.

    Return ONLY JSON in this format:
    {{
        "issues": ["issue1", "issue2", "issue3"]
    }}

    Reasoning:
    {reasoning}
    """

    try:
        result = llm.invoke(msg)
        parsed = json.loads(result.content)
        decisions = parsed["issues"]
    except Exception as e:
        decisions = [str(e)]

    return {"decisions": decisions}

import json

def risk_scoring_node(state: ReconState):

    decisions = state["decisions"]

    msg = f"""
    Assign a severity level to each issue.

    Use CRITICAL, HIGH, MEDIUM, or LOW.

    Return ONLY JSON:

    {{
        "risks": [
            {{"issue": "...", "severity": "..."}}
            ]
        
    }}

    Issues:
    {decisions}
    """

    try:
        result = llm.invoke(msg)
        parsed = json.loads(result.content)
        risk_scores = parsed["risks"]
    except Exception as e:
        risk_scores = [{"error": str(e)}]

    return {"risk_scores": risk_scores}

def attack_surface_node(state: ReconState):

    dns_data = state["dns_data"]
    headers = state["header_data"]
    ssl = state["ssl_data"]

    msg = f"""
    You are a cybersecurity analyst.

    Identify the possible attack surface based on the following data.

    DNS Data:
    {dns_data}

    HTTP Headers:
    {headers}

    SSL Information:
    {ssl}

    List all exposed entry points or technologies that could be targeted.
    """

    try:
        result = llm.invoke(msg)
        attack_surface = result.content
    except Exception as e:
        attack_surface = str(e)

    return {"attack_map": attack_surface}

def report_node(state: ReconState):

    reasoning = state["reasoning"]
    decisions = state["decisions"]
    risk_scores = state["risk_scores"]
    attack_surface = state["attack_map"]

    msg = f"""
    You are a professional cybersecurity analyst.

    Generate a final security report using the following data.

    Reasoning:
    {reasoning}

    Identified Issues:
    {decisions}

    Risk Scores:
    {risk_scores}

    Attack Surface:
    {attack_surface}

    Format the report with clear sections:
    - Executive Summary
    - Identified Vulnerabilities
    - Risk Assessment
    - Attack Surface Overview
    - Recommendations
    """

    try:
        result = llm.invoke(msg)
        report = result.content
    except Exception as e:
        report = str(e)

    return {"report": report}

graph= StateGraph(ReconState)
graph.add_node("whois",whois_node)
graph.set_entry_point("whois")
graph.add_node("dns",dns_node)
graph.add_edge("whois","dns")
graph.add_node("header",header_node)
graph.add_edge("dns","header")
graph.add_node("ssl",ssl_node)
graph.add_edge("header","ssl")
graph.add_node("reasoning",reasoning_node)
graph.add_edge("ssl","subdomains")
graph.add_node("subdomains",subdomain_node)
graph.add_node("ports_open",ports_node)
graph.add_edge("subdomains","ports_open")
graph.add_node("tech",tech_node)
graph.add_edge("ports_open","tech")
graph.add_node("decision",decision_node)
graph.add_node("risk_scoring",risk_scoring_node)
graph.add_node("attackmap",attack_surface_node)
graph.add_node("report",report_node)
graph.add_edge("tech","reasoning")
graph.add_edge("reasoning","decision")
graph.add_edge("decision","risk_scoring")
graph.add_edge("risk_scoring","attackmap")
graph.add_edge("attackmap","report")
graph.add_edge("report",END)
app=graph.compile()
result=app.invoke({"domain": "google.com"})
print(result["report"])