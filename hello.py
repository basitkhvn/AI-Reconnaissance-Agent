from langgraph.graph import StateGraph, MessagesState, START, END
from typing import TypedDict,List
from langchain_core.messages import HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
load_dotenv()
llm=ChatGoogleGenerativeAI(model="gemini-2.5-flash")
class AgentState(TypedDict):
    messages: list

def respond(state:AgentState):
    msg=state["messages"]
    result=llm.invoke(msg)
    state["messages"].append(result)
    return {"messages": state["messages"]}


graph= StateGraph(AgentState)
graph.add_node("respond",respond)
graph.set_entry_point("respond")
graph.add_edge("respond",END)
app=graph.compile()
print("Please type to chat with gemini!")

history=[]

while True:
    user=input("Please type a message: ")
    history.append(HumanMessage(content=user))
    result= app.invoke({"messages": history})
    history=result["messages"]
    print(f"Gemini said: {history[-1].content}")
