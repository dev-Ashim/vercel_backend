"""Safe, deterministic MIME extraction. Email content is treated as untrusted data."""

import email, hashlib, ipaddress, mimetypes, re
from email import policy
from typing import List, Optional
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field


class AttachmentMeta(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


class EmailAuthHeaders(BaseModel):
    spf_header: Optional[str] = None
    dkim_signature: Optional[str] = None
    auth_results: Optional[str] = None
    dmarc_result: Optional[str] = None


class EmailExtractedData(BaseModel):
    message_id: Optional[str] = None
    sender: Optional[str] = None
    return_path: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    auth_headers: EmailAuthHeaders = Field(default_factory=EmailAuthHeaders)
    ip_hops: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    attachments: List[AttachmentMeta] = Field(default_factory=list)
    body_text_sample: str = ""


class EmailForensicsExtractor:
    ipv4_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_regex = re.compile(r"https?://[^\s<>\"']+")

    def __init__(self, raw_eml_bytes: bytes):
        self.msg = email.message_from_bytes(raw_eml_bytes, policy=policy.default)

    @staticmethod
    def is_public_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False

    def extract_ip_hops(self) -> List[str]:
        hops = []
        for header in self.msg.get_all("Received", []):
            for value in self.ipv4_regex.findall(str(header)):
                if self.is_public_ip(value) and value not in hops:
                    hops.append(value)
        return hops

    def extract_auth_headers(self) -> EmailAuthHeaders:
        auth_results = self.msg.get("Authentication-Results") or None
        match = re.search(r"dmarc\s*=\s*([a-z]+)", auth_results or "", re.I)
        return EmailAuthHeaders(
            spf_header=self.msg.get("Received-SPF") or None,
            dkim_signature=self.msg.get("DKIM-Signature") or None,
            auth_results=auth_results,
            dmarc_result=match.group(1).lower() if match else None,
        )

    def extract_body_and_urls(self):
        urls, text = [], []
        for part in self.msg.walk():
            if "attachment" in str(part.get("Content-Disposition", "")).lower():
                continue
            try:
                if part.get_content_type() == "text/plain":
                    value = part.get_content()
                    text.append(value[:1500])
                    urls.extend(self.url_regex.findall(value))
                elif part.get_content_type() == "text/html":
                    soup = BeautifulSoup(part.get_content(), "html.parser")
                    urls.extend(
                        a["href"].strip()
                        for a in soup.find_all("a", href=True)
                        if a["href"].strip().startswith(("http://", "https://"))
                    )
            except UnicodeError, ValueError:
                continue
        clean = []
        for url in urls:
            url = url.rstrip(".,;)")
            if url not in clean:
                clean.append(url)
        return clean, " ".join(text)[:3000]

    def extract_attachments(self) -> List[AttachmentMeta]:
        result = []
        for index, part in enumerate(self.msg.walk()):
            if part.get_content_maintype() == "multipart":
                continue
            filename = part.get_filename()
            disposition = str(part.get("Content-Disposition", "")).lower()
            if (
                "attachment" not in disposition
                and not filename
                and part.get_content_maintype() == "text"
            ):
                continue
            payload = part.get_payload(decode=True) or b""
            filename = (
                filename
                or f"inline-{index}{mimetypes.guess_extension(part.get_content_type()) or '.bin'}"
            )
            result.append(
                AttachmentMeta(
                    filename=filename,
                    content_type=part.get_content_type(),
                    size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        return result

    def process(self) -> EmailExtractedData:
        urls, body = self.extract_body_and_urls()
        return EmailExtractedData(
            message_id=self.msg.get("Message-ID"),
            sender=self.msg.get("From"),
            return_path=self.msg.get("Return-Path"),
            recipient=self.msg.get("To"),
            subject=self.msg.get("Subject"),
            date=self.msg.get("Date"),
            auth_headers=self.extract_auth_headers(),
            ip_hops=self.extract_ip_hops(),
            urls=urls,
            attachments=self.extract_attachments(),
            body_text_sample=body,
        )
