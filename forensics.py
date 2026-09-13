# -*- coding: utf-8 -*-
"""Email Forensics with Autonomous LLM Agent, SQLite Persistence, and Single-Line Plotly Timeline.

Ported from untitled5.py so the live FastAPI service produces the same artifacts
(folium journey map, plotly timeline, agent verdict + reasoning, tool lookups).
"""

import os
import re
import time
import base64
import sqlite3
import requests
import email.utils
from datetime import datetime
from typing import Dict, Any, List, Optional
import warnings

import folium
import plotly.graph_objects as go

from .parser import EmailExtractedData, EmailForensicsExtractor

AGENT_AVAILABLE = False
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from langchain_core.messages import HumanMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import create_react_agent
    from langchain_openai import ChatOpenAI

    AGENT_AVAILABLE = True
except Exception:

    def tool(fn):  # no-op fallback when agent deps are not installed
        return fn


ANALYSIS_CACHE = {}


class IPGeoLookupTool:
    def __init__(self, api_token: str = None):
        self.api_token = api_token

    def lookup(self, ip_address: str) -> dict:
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = (
            {"Authorization": f"Bearer {self.api_token}"} if self.api_token else {}
        )
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            data = response.json()
            lat, lon = None, None
            if "loc" in data:
                lat_str, lon_str = data["loc"].split(",")
                lat, lon = float(lat_str), float(lon_str)
            return {
                "ip": data.get("ip"),
                "city": data.get("city"),
                "country": data.get("country"),
                "org": data.get("org"),
                "lat": lat,
                "lon": lon,
            }
        except Exception as e:
            return {"error": str(e), "ip": ip_address}


class VirusTotalURLTool:
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/urls/"

    def check_url(self, url: str) -> Dict[str, Any]:
        if not self.api_key or self.api_key == "YOUR_VT_API_KEY_HERE":
            return {"url": url, "error": "Provide a VirusTotal API key to check URLs."}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.api_key}
        try:
            time.sleep(15)
            response = requests.get(self.base_url + url_id, headers=headers, timeout=10)
            if response.status_code == 404:
                return {
                    "url": url,
                    "verdict": "SAFE_OR_UNKNOWN",
                    "details": "Not found in database",
                }
            response.raise_for_status()
            stats = (
                response.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            if stats.get("malicious", 0) > 0:
                verdict = "MALICIOUS"
            elif stats.get("suspicious", 0) > 0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "SAFE"
            return {
                "url": url,
                "verdict": verdict,
                "malicious_engines": stats.get("malicious", 0),
            }
        except Exception as e:
            return {"error": str(e), "url": url}


class VirusTotalHashTool:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3/files/"

    def check_hash(self, sha256_hash: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "Missing VirusTotal API Key."}
        headers = {"accept": "application/json", "x-apikey": self.api_key}
        try:
            time.sleep(15)
            response = requests.get(
                self.base_url + sha256_hash, headers=headers, timeout=10
            )
            if response.status_code == 404:
                return {
                    "hash": sha256_hash,
                    "verdict": "UNKNOWN",
                    "details": "File never seen",
                }
            response.raise_for_status()
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                verdict = "MALICIOUS"
            elif stats.get("suspicious", 0) > 0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "SAFE"
            return {
                "hash": sha256_hash,
                "verdict": verdict,
                "malicious_engines": stats.get("malicious", 0),
                "names": data.get("attributes", {}).get("names", [])[:3],
            }
        except Exception as e:
            return {"error": str(e), "hash": sha256_hash}


ip_lookup_tool_instance = IPGeoLookupTool(api_token=os.getenv("IPINFO_TOKEN"))
url_checker_tool_instance = VirusTotalURLTool(
    api_key="80a98b1877060fd020eac36fb723706103439806f49cb042143fb1d92d7eb314"
)
hash_checker_tool_instance = VirusTotalHashTool(
    api_key="80a98b1877060fd020eac36fb723706103439806f49cb042143fb1d92d7eb314"
)


@tool
def ip_geolocation_lookup(ip_address: str) -> Dict[str, Any]:
    """get ip locations from ips"""
    return ip_lookup_tool_instance.lookup(ip_address)


@tool
def url_threat_check(url: str) -> Dict[str, Any]:
    """Get Urls Threat checks"""
    return url_checker_tool_instance.check_url(url)


@tool
def hash_threat_check(sha256_hash: str) -> Dict[str, Any]:
    """Get Hash Threat checks"""
    return hash_checker_tool_instance.check_hash(sha256_hash)


@tool
def submit_final_verdict(verdict: str, reasoning: str) -> str:
    """submit the final verdict as 'THREAT','SPAM','SAFE'"""
    valid_verdicts = ["SAFE", "SPAM", "THREAT"]
    upper_verdict = verdict.upper()
    if upper_verdict not in valid_verdicts:
        return f"Error: Invalid verdict '{verdict}'. Must be SAFE, SPAM, or THREAT."
    ANALYSIS_CACHE["verdict"] = upper_verdict
    ANALYSIS_CACHE["reasoning"] = reasoning
    return "Verdict successfully recorded to global cache. You can now finish."


agent_tools = [
    ip_geolocation_lookup,
    url_threat_check,
    hash_threat_check,
    submit_final_verdict,
]

system_prompt = """You are an elite cybersecurity forensic analyst agent.
You are provided with extracted metadata from a potentially suspicious email.

Your directives:
1. Autonomously invoke the provided tools to investigate the origin IPs, linked URLs, and extracted attachment hashes.
2. Analyze the aggregate results to identify phishing attempts, malicious infrastructure, or known malware.
3. CRITICAL: When you have made a decision, you MUST call the `submit_final_verdict` tool to officially record your verdict ('SAFE', 'SPAM', or 'THREAT'). Do not just type it in the chat. Call the tool to end the process.
"""


def build_agent():
    llm = ChatOpenAI(
        model="openrouter/free",
        api_key=os.getenv("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
    )
    return create_react_agent(llm, tools=agent_tools, prompt=system_prompt)


def analyze_with_agent(extracted_data: EmailExtractedData) -> Dict[str, Any]:
    """Run the autonomous LLM agent over extracted email data (same flow as untitled5.py)."""
    if not AGENT_AVAILABLE:
        return {
            "run": False,
            "reason": "LLM agent dependencies not installed (langchain-core, langgraph, langchain-openai)",
        }
    if not os.getenv("OPENROUTER_API_KEY"):
        return {"run": False, "reason": "OPENROUTER_API_KEY not configured"}

    ANALYSIS_CACHE.clear()
    agent_app = build_agent()
    email_payload = extracted_data.model_dump_json(indent=2)
    user_message = HumanMessage(content=f"Analyze this email data:\n{email_payload}")

    thoughts = []
    tool_calls = []
    for event in agent_app.stream({"messages": [user_message]}):
        if "agent" in event:
            content = event["agent"]["messages"][0].content
            if content:
                thoughts.append(content)
        elif "tools" in event:
            for tool_msg in event["tools"]["messages"]:
                tool_calls.append({"name": tool_msg.name, "content": tool_msg.content})

    return {
        "run": True,
        "verdict": ANALYSIS_CACHE.get("verdict"),
        "reasoning": ANALYSIS_CACHE.get("reasoning"),
        "thoughts": thoughts,
        "tool_calls": tool_calls,
    }


def init_db(db_path: str = None):
    if db_path is None:
        db_path = os.getenv("MAILSENTINEL_SQLITE_PATH", "data/inbox_threats.db")
    if db_path != ":memory:":
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            message_id TEXT PRIMARY KEY,
            subject TEXT,
            verdict TEXT,
            date_received TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT,
            entity_value TEXT,
            entity_type TEXT,
            FOREIGN KEY(email_id) REFERENCES emails(message_id)
        )
    """)
    conn.commit()
    return conn


def save_to_db(conn, extracted_data, verdict: str):
    cursor = conn.cursor()
    msg_id = extracted_data.message_id or f"local_id_{int(time.time())}"
    subject = extracted_data.subject or "No Subject"

    try:
        if extracted_data.date:
            parsed_date = email.utils.parsedate_to_datetime(extracted_data.date)
            date_str = parsed_date.strftime("%Y-%m-%d %H:%M:%S")
        else:
            date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT OR IGNORE INTO emails (message_id, subject, verdict, date_received) VALUES (?, ?, ?, ?)",
        (msg_id, subject, verdict, date_str),
    )

    for ip in extracted_data.ip_hops:
        cursor.execute(
            "INSERT INTO entities (email_id, entity_value, entity_type) VALUES (?, ?, 'IP')",
            (msg_id, ip),
        )
    conn.commit()


def generate_journey_map(extracted_ips, ip_tool_instance):
    """Same folium journey map as untitled5.py. Returns the folium Map object."""
    chronological_ips = list(reversed(extracted_ips))
    journey_data = [
        ip_tool_instance.lookup(ip)
        for ip in chronological_ips
        if ip_tool_instance.lookup(ip).get("lat")
    ]
    if not journey_data:
        return None

    origin = journey_data[0]
    email_map = folium.Map(
        location=[origin["lat"], origin["lon"]],
        zoom_start=2,
        tiles="https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}",
        attr="Esri",
    )
    coordinates_path = []

    for index, hop in enumerate(journey_data):
        coord = (hop["lat"], hop["lon"])
        coordinates_path.append(coord)
        step_name = (
            "True Origin"
            if index == 0
            else (
                "Final Destination"
                if index == len(journey_data) - 1
                else f"Transit Hop {index}"
            )
        )
        icon_color = (
            "red"
            if index == 0
            else "green" if index == len(journey_data) - 1 else "blue"
        )
        folium.Marker(
            location=coord,
            popup=f"<b>{step_name}</b><br>IP: {hop['ip']}",
            tooltip=step_name,
            icon=folium.Icon(color=icon_color, icon="info-sign"),
        ).add_to(email_map)

    if len(coordinates_path) > 1:
        folium.PolyLine(
            coordinates_path, color="red", weight=2.5, opacity=0.8, dash_array="5, 5"
        ).add_to(email_map)
    return email_map


def generate_timeline_graph(conn):
    """Generates a single continuous line graph showing threat progression over time (same as untitled5.py).
    Returns the embeddable Plotly HTML string."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT date_received, verdict, subject FROM emails ORDER BY date_received ASC"
    )
    records = cursor.fetchall()

    if not records:
        print("[-] Not enough historical data to generate timeline graph.")
        return None

    import html as _html

    dates = []
    cumulative_threats = []
    hover_texts = []
    colors = []
    current_threat_count = 0

    for date_recv, verdict, subject in records:
        if verdict in ["THREAT", "SPAM"]:
            current_threat_count += 1

        dates.append(date_recv)
        cumulative_threats.append(current_threat_count)

        if verdict == "THREAT":
            colors.append("red")
        elif verdict == "SPAM":
            colors.append("orange")
        else:
            colors.append("green")

        hover_texts.append(
            f"<b>Time:</b> {date_recv}<br><b>Verdict:</b> {verdict}<br><b>Subject:</b> {_html.escape(subject or '')}"
        )

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=dates,
            y=cumulative_threats,
            mode="lines+markers",
            name="Inbox Events",
            line=dict(color="darkgray", width=2, shape="hv"),
            marker=dict(size=12, color=colors, line=dict(width=1, color="black")),
            text=hover_texts,
            hoverinfo="text",
        )
    )

    fig.update_layout(
        title="Inbox Threat Progression Timeline",
        xaxis_title="Timeline (from 1st Inbox Event)",
        yaxis_title="Cumulative Threats Detected",
        template="plotly_white",
        xaxis=dict(tickangle=-45, showgrid=False),
        yaxis=dict(showgrid=True, rangemode="tozero"),
        margin=dict(l=50, r=30, t=60, b=40),
        height=340,
    )

    return fig.to_html(full_html=False, include_plotlyjs="cdn")
