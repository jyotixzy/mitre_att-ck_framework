# Purpose: Yeh file raw `.eml` email ko parse karne ke liye responsible hai.
# Iska main kaam email ke text/plain aur text/html parts ko read karke unme se URLs nikalna hai.
# URL analyzer pipeline ka actual input isi module se generate hota hai.

import re
from email import policy
from email.parser import BytesParser
from pathlib import Path


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def extract_urls_from_eml(eml_path: Path) -> list[str]:
    """Yeh function `.eml` file ko read karke body ke relevant parts inspect karta hai.
    Text aur HTML dono sections se regex ke through URLs nikale jate hain.
    Duplicate URLs remove karke unique list return ki jati hai, jo aage heuristics ko di jati hai."""
    with eml_path.open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    body_chunks: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type in {"text/plain", "text/html"}:
                try:
                    body_chunks.append(part.get_content())
                except (LookupError, UnicodeDecodeError):
                    payload = part.get_payload(decode=True) or b""
                    body_chunks.append(payload.decode(errors="ignore"))
    else:
        try:
            body_chunks.append(message.get_content())
        except (LookupError, UnicodeDecodeError):
            payload = message.get_payload(decode=True) or b""
            body_chunks.append(payload.decode(errors="ignore"))

    urls: list[str] = []
    for chunk in body_chunks:
        urls.extend(URL_PATTERN.findall(chunk or ""))

    seen: set[str] = set()
    unique_urls: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    return unique_urls
