import json
import logging
import os
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load configuration before importing modules that create API clients.
load_dotenv()

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

if __package__:
    from .parser import EmailForensicsExtractor
    from . import forensics
else:
    from parser import EmailForensicsExtractor
    import forensics


logger = logging.getLogger(__name__)
IS_VERCEL = bool(os.getenv("VERCEL"))

if IS_VERCEL:
    # Temporary, instance-local demo storage.
    # These files are not a durable or shared database.
    DATA_DIR = Path("/tmp/mailsentinel")
    DB_PATH = DATA_DIR / "mailsentinel.json"
    SQLITE_PATH = str(DATA_DIR / "inbox_threats.db")
else:
    DATA_DIR = Path(os.getenv("MAILSENTINEL_DATA_DIR", "data"))
    DB_PATH = Path(
        os.getenv("DATABASE_URL", str(DATA_DIR / "mailsentinel.json"))
    )
    SQLITE_PATH = os.getenv(
        "MAILSENTINEL_SQLITE_PATH",
        str(DATA_DIR / "inbox_threats.db"),
    )

for directory in (
    DATA_DIR,
    DB_PATH.parent,
    Path(SQLITE_PATH).parent,
):
    directory.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD = int(
    os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024))
)

if IS_VERCEL:
    # Leave room for multipart overhead under the platform request limit.
    MAX_UPLOAD = min(MAX_UPLOAD, 4 * 1024 * 1024)

DB_LOCK = threading.RLock()
AGENT_LOCK = threading.Lock()

VERDICTS = ("THREAT", "SPAM", "SAFE", "INCONCLUSIVE")


def now():
    return datetime.now(timezone.utc).isoformat()


def read_db():
    with DB_LOCK:
        if not DB_PATH.exists():
            return {}

        try:
            data = json.loads(DB_PATH.read_text(encoding="utf-8"))

            if not isinstance(data, dict):
                raise ValueError("Invalid analysis database format")

            return data

        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Unable to read local analysis storage"
            ) from exc


def save_item(item):
    # Read-modify-write under one lock to avoid overwriting other jobs
    # within this process. This does not coordinate separate instances.
    with DB_LOCK:
        data = read_db()
        data[item["analysis_id"]] = item

        temporary = DB_PATH.with_name(DB_PATH.name + ".tmp")
        temporary.write_text(
            json.dumps(data, default=str),
            encoding="utf-8",
        )
        os.replace(temporary, DB_PATH)


def cached_result(tool_calls, name, key, value):
    for call in tool_calls:
        if not isinstance(call, dict):
            continue

        content = call.get("content")

        if (
            call.get("name") == name
            and isinstance(content, dict)
            and content.get(key) == value
        ):
            return content

    return None


def run_job(analysis_id, raw):
    item = read_db().get(analysis_id)

    if item is None:
        raise RuntimeError("Analysis record not found")

    connection = None

    try:
        item.update(status="processing", stage="extracting")
        save_item(item)

        extracted = EmailForensicsExtractor(raw).process()
        item["extraction"] = extracted.model_dump()

        item["stage"] = "analyzing"
        save_item(item)

        # Protect agent globals within this process.
        with AGENT_LOCK:
            cache = getattr(forensics, "ANALYSIS_CACHE", None)

            if isinstance(cache, dict):
                cache.update(verdict=None, reasoning=None)

            agent = forensics.analyze_with_agent(extracted)

        if not isinstance(agent, dict):
            raise RuntimeError("Agent returned an invalid result")

        verdict = str(agent.get("verdict") or "").upper()

        if not agent.get("run") or verdict not in VERDICTS:
            verdict = "INCONCLUSIVE"
            item["warnings"].append(
                "Agent did not record a valid final verdict."
            )

        item["agent"] = {
            key: agent[key]
            for key in ("run", "reasoning", "tool_calls")
            if key in agent
        }

        if agent.get("reason"):
            item["warnings"].append(str(agent["reason"]))

        item["stage"] = "checking"
        save_item(item)

        calls = agent.get("tool_calls") or []

        locations = [
            forensics.ip_lookup_tool_instance.lookup(ip)
            for ip in dict.fromkeys(extracted.ip_hops)
        ]

        url_results = []

        for url in extracted.urls:
            result = cached_result(
                calls,
                "url_threat_check",
                "url",
                url,
            )

            if result is None:
                result = (
                    forensics.url_checker_tool_instance.check_url(url)
                )

            result = dict(result)

            if result.get("verdict") == "SAFE_OR_UNKNOWN":
                result["verdict"] = "UNKNOWN"

            url_results.append(result)

        hash_results = []

        for attachment in extracted.attachments:
            sha = attachment.sha256

            result = cached_result(
                calls,
                "hash_threat_check",
                "hash",
                sha,
            )

            if result is None:
                result = (
                    forensics.hash_checker_tool_instance.check_hash(sha)
                )

            hash_results.append({**result, "hash": sha})

        item["provider_results"] = {
            "urls": url_results,
            "attachments": hash_results,
            "locations": locations,
        }

        indicator_results = url_results + hash_results

        has_unknown = any(
            result.get("error")
            or result.get("verdict") == "UNKNOWN"
            for result in indicator_results
        )

        has_detection = any(
            result.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
            for result in indicator_results
        )

        if has_unknown:
            item["warnings"].append(
                "Some indicators have unknown or unavailable reports."
            )

        if any(result.get("error") for result in locations):
            item["warnings"].append(
                "Some IP locations were unavailable."
            )

        # Additional checks may contain evidence the agent never reviewed.
        if verdict == "SAFE" and has_detection:
            verdict = "INCONCLUSIVE"
            item["warnings"].append(
                "Later tool evidence conflicts with the agent verdict; "
                "review required."
            )

        if verdict == "SAFE" and has_unknown:
            verdict = "INCONCLUSIVE"
            item["warnings"].append(
                "Incomplete indicator evidence prevents a SAFE result."
            )

        item["stage"] = "saving"
        save_item(item)

        connection = forensics.init_db(SQLITE_PATH)
        forensics.save_to_db(connection, extracted, verdict)

        if verdict in ("THREAT", "SPAM"):
            try:
                journey = forensics.generate_journey_map(
                    extracted.ip_hops,
                    forensics.ip_lookup_tool_instance,
                )

                if journey is not None:
                    item["map_html"] = (
                        journey.get_root()._repr_html_()
                    )

            except Exception:
                logger.exception(
                    "Map generation failed: %s",
                    analysis_id,
                )
                item["warnings"].append(
                    "Map generation was unavailable."
                )

        item.update(
            verdict=verdict,
            explanation=(
                agent.get("reasoning")
                or "No reasoned AI verdict was available."
            ),
            status="completed",
            stage="complete",
            completed_at=now(),
        )

    except Exception:
        logger.exception("Analysis failed: %s", analysis_id)

        item.update(
            status="failed",
            stage="failed",
            completed_at=now(),
            errors=[
                "Analysis failed. Check backend logs "
                "using the analysis ID."
            ],
        )

    finally:
        if connection is not None:
            connection.close()

    save_item(item)
    return item


app = FastAPI(
    title="MailSentinel API",
    version="1.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip().rstrip("/")
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "MailSentinel API",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "temporary_storage": IS_VERCEL,
        "integrations": {
            "openrouter": bool(os.getenv("OPENROUTER_API_KEY")),
            "virustotal": bool(os.getenv("VT_API_KEY")),
            "ipinfo": bool(os.getenv("IPINFO_TOKEN")),
        },
    }


@app.post("/api/analyses")
async def create_analysis(file: UploadFile = File(...)):
    filename = file.filename or ""

    try:
        if not filename.lower().endswith(".eml"):
            raise HTTPException(
                status_code=422,
                detail="Only .eml files are accepted",
            )

        raw = await file.read(MAX_UPLOAD + 1)

    finally:
        await file.close()

    if not raw.strip():
        raise HTTPException(
            status_code=422,
            detail="Email file is empty",
        )

    if len(raw) > MAX_UPLOAD:
        raise HTTPException(
            status_code=413,
            detail="Email exceeds the upload limit",
        )

    analysis_id = str(uuid.uuid4())

    item = {
        "analysis_id": analysis_id,
        "filename": filename,
        "status": "queued",
        "stage": "queued",
        "created_at": now(),
        "warnings": [],
        "errors": [],
    }

    if IS_VERCEL:
        item["warnings"].append(
            "Demo storage is temporary; retain this response "
            "or download the report."
        )

    save_item(item)

    if IS_VERCEL:
        # Wait within this request instead of starting an untracked daemon.
        # The frontend must display this full response directly.
        # Long analyses can still exceed Vercel's execution timeout.
        result = await run_in_threadpool(
            run_job,
            analysis_id,
            raw,
        )
        return JSONResponse(result, status_code=200)

    # Local development retains the existing polling workflow.
    threading.Thread(
        target=run_job,
        args=(analysis_id, raw),
        daemon=True,
    ).start()

    return JSONResponse(
        {
            "analysis_id": analysis_id,
            "status": "queued",
        },
        status_code=202,
    )


@app.get("/api/analyses")
def list_analyses(
    search: Optional[str] = None,
    verdict: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    items = sorted(
        read_db().values(),
        key=lambda item: item.get("created_at", ""),
        reverse=True,
    )

    if search:
        items = [
            item
            for item in items
            if search.lower() in json.dumps(item).lower()
        ]

    if verdict:
        items = [
            item
            for item in items
            if item.get("verdict") == verdict.upper()
        ]

    start = (page - 1) * page_size

    return {
        "items": items[start : start + page_size],
        "total": len(items),
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: uuid.UUID):
    item = read_db().get(str(analysis_id))

    if item is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Analysis not found; temporary storage may have reset "
                "or another instance handled the request."
            ),
        )

    return item


@app.get("/api/analyses/{analysis_id}/report")
def report(analysis_id: uuid.UUID):
    item = dict(get_analysis(analysis_id))
    item.pop("map_html", None)

    return JSONResponse(
        item,
        headers={
            "Content-Disposition": (
                f'attachment; filename="{analysis_id}.json"'
            )
        },
    )


@app.get("/api/dashboard/stats")
def stats():
    items = list(read_db().values())

    counts = {
        verdict: sum(
            item.get("verdict") == verdict
            for item in items
        )
        for verdict in VERDICTS
    }

    days = defaultdict(
        lambda: {verdict: 0 for verdict in VERDICTS}
    )

    for item in items:
        verdict = item.get("verdict")

        if verdict in VERDICTS:
            day = item.get("created_at", "")[:10]
            days[day][verdict] += 1

    return {
        "total": len(items),
        "distribution": counts,
        "daily": [
            {"date": day, **days[day]}
            for day in sorted(days)
        ],
    }


@app.get("/api/dashboard/timeline")
def timeline():
    import plotly.graph_objects as go

    items = sorted(
        (
            item
            for item in read_db().values()
            if item.get("verdict")
        ),
        key=lambda item: item.get("created_at", ""),
    )

    if not items:
        return {"html": "<p>No completed analyses yet.</p>"}

    dates = []
    totals = []
    colors = []
    labels = []
    count = 0

    palette = {
        "THREAT": "red",
        "SPAM": "orange",
        "SAFE": "green",
        "INCONCLUSIVE": "gray",
    }

    for item in items:
        verdict = item["verdict"]

        count += int(verdict in ("THREAT", "SPAM"))

        dates.append(item["created_at"])
        totals.append(count)
        colors.append(palette.get(verdict, "gray"))

        subject = (
            item.get("extraction", {}).get("subject")
            or item["filename"]
        )
        labels.append(escape(str(subject)))

    figure = go.Figure(
        go.Scatter(
            x=dates,
            y=totals,
            text=labels,
            mode="lines+markers",
            line_shape="hv",
            marker_color=colors,
        )
    )

    figure.update_layout(
        title="Cumulative spam and threat detections",
        xaxis_title="Analysis time (UTC)",
        yaxis_title="Flagged emails",
        template="plotly_white",
    )

    # Generate HTML in memory instead of writing into the project folder.
    return {
        "html": figure.to_html(
            full_html=True,
            include_plotlyjs="cdn",
        )
    }