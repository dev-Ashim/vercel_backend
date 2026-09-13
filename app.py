import json, os, threading, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .parser import EmailExtractedData, EmailForensicsExtractor
from . import forensics

load_dotenv()

DATA_DIR = Path(os.getenv("MAILSENTINEL_DATA_DIR", "data"))
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = Path(os.getenv("DATABASE_URL", str(DATA_DIR / "mailsentinel.json")))
SQLITE_PATH = os.getenv("MAILSENTINEL_SQLITE_PATH", str(DATA_DIR / "inbox_threats.db"))
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
LOCK = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat()


def read_db():
    if not DB_PATH.exists():
        return {}
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except OSError, json.JSONDecodeError:
        return {}


def write_db(data):
    with LOCK:
        DB_PATH.write_text(json.dumps(data, default=str), encoding="utf-8")


def run_job(analysis_id, raw):
    data = read_db()
    item = data[analysis_id]
    sqlite_conn = forensics.init_db(SQLITE_PATH)
    try:
        item["status"] = "processing"
        item["stage"] = "extracting"
        write_db(data)
        extractor = EmailForensicsExtractor(raw)
        extracted = extractor.process()
        item["extraction"] = extracted.model_dump()
        item["stage"] = "analyzing"
        write_db(data)

        agent = forensics.analyze_with_agent(extracted)
        verdict = agent.get("verdict")
        if agent.get("run") and not verdict:
            raise RuntimeError("Agent failed to call the submit_final_verdict tool.")
        if not agent.get("run"):
            verdict = "INCONCLUSIVE"
        item["agent"] = {
            k: agent[k]
            for k in ("run", "reasoning", "thoughts", "tool_calls")
            if k in agent
        }
        if agent.get("reason"):
            item["warnings"] = item.get("warnings", []) + [agent["reason"]]
        if not os.getenv("IPINFO_TOKEN") and not os.getenv("VT_API_KEY"):
            item["warnings"] = item.get("warnings", []) + [
                "External indicator checks were unavailable."
            ]

        item["stage"] = "checking"
        write_db(data)
        tool_calls = agent.get("tool_calls") or []

        locations = []
        for ip in extracted.ip_hops:
            loc = forensics.ip_lookup_tool_instance.lookup(ip)
            if locations and loc.get("ip") == locations[-1].get("ip"):
                continue
            locations.append(loc)

        url_results = []
        for url in extracted.urls:
            result = next(
                (
                    c.get("content")
                    for c in tool_calls
                    if c.get("name") == "url_threat_check"
                    and isinstance(c.get("content"), dict)
                    and c.get("content", {}).get("url") == url
                ),
                None,
            )
            if not result:
                result = forensics.url_checker_tool_instance.check_url(url)
            url_results.append(result)

        hash_results = []
        for attachment in extracted.attachments:
            sha = attachment.sha256
            result = next(
                (
                    c.get("content")
                    for c in tool_calls
                    if c.get("name") == "hash_threat_check"
                    and isinstance(c.get("content"), dict)
                    and c.get("content", {}).get("hash") == sha
                ),
                None,
            )
            if not result:
                result = forensics.hash_checker_tool_instance.check_hash(sha)
            hash_results.append(
                {"hash": sha, **({k: v for k, v in result.items() if k != "hash"})}
            )

        item["provider_results"] = {
            "urls": url_results,
            "attachments": hash_results,
            "locations": locations,
        }

        item["stage"] = "verdict"
        write_db(data)
        forensics.save_to_db(sqlite_conn, extracted, verdict)

        if verdict in ["THREAT", "SPAM"]:
            journey_map = forensics.generate_journey_map(
                extracted.ip_hops, forensics.ip_lookup_tool_instance
            )
            if journey_map:
                item["map_html"] = journey_map.get_root()._repr_html_()

        item["verdict"] = verdict
        item["explanation"] = (
            agent.get("reasoning")
            or "Email extracted successfully, but the autonomous agent did not record a reasoned verdict."
        )
        item["status"] = "completed"
        item["stage"] = "complete"
        item["completed_at"] = now()
        write_db(data)
    except Exception as exc:
        item["status"] = "failed"
        item["stage"] = "failed"
        item["errors"] = [str(exc)]
        write_db(data)
    finally:
        sqlite_conn.close()


app = FastAPI(title="MailSentinel API", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "integrations": {
            "openrouter": bool(os.getenv("OPENROUTER_API_KEY")),
            "virustotal": bool(os.getenv("VT_API_KEY")),
            "ipinfo": bool(os.getenv("IPINFO_TOKEN")),
        },
    }


@app.post("/api/analyses", status_code=202)
async def create_analysis(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(422, "Only .eml files are accepted")
    raw = await file.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "Email exceeds the upload limit")
    analysis_id = str(uuid.uuid4())
    data = read_db()
    data[analysis_id] = {
        "analysis_id": analysis_id,
        "filename": file.filename,
        "status": "queued",
        "stage": "queued",
        "created_at": now(),
    }
    write_db(data)
    threading.Thread(target=run_job, args=(analysis_id, raw), daemon=True).start()
    return {"analysis_id": analysis_id, "status": "queued"}


@app.get("/api/analyses")
def list_analyses(
    search: Optional[str] = None,
    verdict: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    items = list(read_db().values())
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    if search:
        items = [x for x in items if search.lower() in json.dumps(x).lower()]
    if verdict:
        items = [x for x in items if x.get("verdict") == verdict.upper()]
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "total": len(items),
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str):
    item = read_db().get(analysis_id)
    if not item:
        raise HTTPException(404, "Analysis not found")
    return item


@app.get("/api/analyses/{analysis_id}/report")
def report(analysis_id: str):
    item = read_db().get(analysis_id)
    if not item:
        raise HTTPException(404, "Analysis not found")
    safe = dict(item)
    safe.pop("map_html", None)
    return JSONResponse(
        safe,
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}.json"'},
    )


@app.get("/api/dashboard/stats")
def stats():
    items = list(read_db().values())
    counts = {
        v: sum(x.get("verdict") == v for x in items)
        for v in ["THREAT", "SPAM", "SAFE", "INCONCLUSIVE"]
    }
    return {"total": len(items), "distribution": counts, "daily": []}


@app.get("/api/dashboard/timeline")
def timeline():
    conn = forensics.init_db(SQLITE_PATH)
    try:
        return {"html": forensics.generate_timeline_graph(conn)}
    finally:
        conn.close()
