"""Tamil Nadu weighing machine stamping application helper.

All document parsing and profile storage happens locally. Portal interactions are
performed in the Chromium browser bundled with the app using Playwright.
"""
from __future__ import annotations

import base64
import ctypes
import json
import math
import os
import queue
import re
import threading
import mimetypes
import sys
import subprocess
import time
import winreg
from difflib import SequenceMatcher
import tkinter as tk
from ctypes import wintypes
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_NAME = "TN Stamping Assistant"
PORTAL_URL = "https://labour.tn.gov.in/services/users/login?redirect=%2Fstamping-labours"
STAMPING_URL = "https://labour.tn.gov.in/services/stamping-labours/stamping"
STAMPING_LIST_URL = "https://labour.tn.gov.in/services/stamping-labours"
CHROMIUM_CDP_ENDPOINT = "http://127.0.0.1:9229"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TNStampingAssistant"
VAULT_FILE = APP_DIR / "profile.vault"
FALLBACK_APP_DIR = (Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent) / ".TNStampingAssistant"
ADDRESS_CACHE_LOCK = threading.Lock()
if getattr(sys, "frozen", False):
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(Path(sys._MEIPASS) / ".pw-browsers")
else:
    bundled_browsers = Path(__file__).resolve().parent / ".pw-browsers"
    if bundled_browsers.is_dir():
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(bundled_browsers)

FIELD_LABELS = {
    "Applicant / establishment name": ["name of the applicant", "applicant name", "name of the user", "name of the owner", "name of establishment", "trader name", "business name"],
    "Business address": ["address", "postal address", "address of the user", "address of the establishment", "premises address"],
    "Door number": ["door number", "door no"],
    "State": ["state"],
    "District": ["district"],
    "Taluk": ["taluk"],
    "Town / Village": ["town village", "town / village", "village"],
    "Street": ["street"],
    "Pincode": ["pincode", "pin code", "postal code"],
    "Previous CV number": ["previous cv number", "cv number", "certificate number", "previous verification certificate number", "previous certificate number"],
    "Previous CV date": ["previous cv date", "certificate date", "date of verification", "verification date"],
    "Application number": ["application number", "application no"],
    "Instrument description": ["type of weighing instrument", "weighing instrument", "instrument type", "description of instrument", "type of instrument"],
    "Instrument make": ["make", "manufacturer", "make of instrument"],
    "Instrument model": ["model", "model of instrument"],
    "Machine number": ["machine number", "machine no", "serial number", "instrument serial number"],
    "Maximum capacity": ["maximum capacity", "max capacity", "capacity", "max"],
    "Minimum capacity": ["minimum capacity", "min capacity", "min"],
    "Verification interval (e/d)": ["verification interval", "e/d", "division", "scale interval"],
    "Class": ["accuracy class", "class"],
    "Quantity": ["quantity", "number of instruments", "no. of instruments"],
    "Repairer name": ["repairer name", "repaired by", "repairer"],
    "Repairer licence number": ["repairer licence number", "repairer license number", "licence number", "license number"],
    "PAN name": ["pan name", "name on pan", "pan card name"],
    "PAN number": ["pan number", "pan card number"],
    "PAN date": ["date in pan card", "pan date"],
    "Applicant business name": ["establishment name"],
    "Applicant contact name": ["name"],
    "Registered name": ["name"],
    "Registered email": ["email"],
    "Registered mobile": ["mobile"],
    "Repairer licence date": ["license date", "licence date"],
    "Stamping office/site": ["whether stamping office or site"],
    "Trader / establishment number": ["manufacturer trader establishment number", "trader number"],
    "Used by / trader contact": ["repaired by used by", "used by"],
    "Dormant / Other": ["dormant", "other"],
}

PORTAL_IDS = {
    "Previous CV number": "#pur-invo-num",
    "Previous CV date": "#pur-invo-date",
    "Repairer name": "#repairedby",
    "Repairer licence number": "#licence-no",
    "Applicant / establishment name": "#trader-est-name",
    "Door number": "#trader-door",
    "Pincode": "#trader-pincode",
    "District": "#trader-district-id",
    "Taluk": "#trader-taluk-id",
    "Town / Village": "#trader-revenue-village-id",
    "Street": "#trader-street-id",
    "State": "#trader-state-id",
    "PAN number": "#pan-number",
    "PAN date": "#pan-date",
    "Quantity": "#stampinglabourmeasures-0-quantity",
    "Registered name": "#userlogname",
    "Registered email": "#userlogemail",
    "Registered mobile": "#userlogemobile",
    "Repairer licence date": "#licencedate",
    "Stamping office/site": "#is-office",
    "Instrument description": "#stampinglabourmeasures-0-stamping-type-id",
    "Trader / establishment number": "#uid-number",
    "Used by / trader contact": "#trader-name",
}

PORTAL_ID_ALIASES = {
    "Repairer licence number": ("#licenceno", "#license-no", "#license-number", "#licence-number"),
    "Repairer name": ("#repairer-name", "#repaired-by", "#repairedbyname"),
}

LOCAL_ONLY_FIELDS = {
    "Business address", "Denomination", "Instrument make", "Instrument model", "Machine number",
    "Maximum capacity", "Minimum capacity", "Verification interval (e/d)", "Class", "Application number", "Dormant / Other", "PAN name",
}

MACHINE_REVIEW_FIELDS = {
    "Instrument description", "Denomination", "Weights", "Instrument make", "Instrument model", "Machine number",
    "Maximum capacity", "Minimum capacity", "Verification interval (e/d)", "Class", "Quantity",
}


def _blob(data: bytes):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))), buf


def protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Encrypted profile storage is supported on Windows only.")
    inp, keepalive = _blob(data)
    out = type(inp)()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    blob_ptr = ctypes.POINTER(type(inp))
    crypt32.CryptProtectData.argtypes = [blob_ptr, wintypes.LPCWSTR, blob_ptr, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob_ptr]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    if not crypt32.CryptProtectData(ctypes.byref(inp), "TN Stamping Assistant", None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(out.pbData)


def unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Encrypted profile storage is supported on Windows only.")
    inp, keepalive = _blob(data)
    out = type(inp)()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    blob_ptr = ctypes.POINTER(type(inp))
    crypt32.CryptUnprotectData.argtypes = [blob_ptr, ctypes.POINTER(wintypes.LPWSTR), blob_ptr, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob_ptr]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    if not crypt32.CryptUnprotectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(out.pbData)


def load_vault() -> dict:
    global APP_DIR, VAULT_FILE
    candidates = (VAULT_FILE, FALLBACK_APP_DIR / "profile.vault")
    for candidate in candidates:
        if candidate.exists():
            profile = json.loads(unprotect(candidate.read_bytes()).decode("utf-8"))
            APP_DIR, VAULT_FILE = candidate.parent, candidate
            return profile
    return {}


def save_vault(data: dict) -> None:
    global APP_DIR, VAULT_FILE
    encrypted = protect(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    candidates = tuple(dict.fromkeys((APP_DIR, FALLBACK_APP_DIR)))
    last_error = None
    for directory in candidates:
        target = directory / "profile.vault"
        temp = target.with_suffix(".tmp")
        try:
            directory.mkdir(parents=True, exist_ok=True)
            temp.write_bytes(encrypted)
            os.replace(temp, target)
            APP_DIR, VAULT_FILE = directory, target
            return
        except OSError as exc:
            last_error = exc
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
    raise last_error or OSError("Could not save the encrypted profile.")


def pdf_text(path: str) -> str:
    try:
        import pdfplumber
    except ImportError as exc:
        raise RuntimeError("PDF reading module is missing. Reinstall using the included setup instructions.") from exc
    with pdfplumber.open(path) as pdf:
        return "\n".join(page.extract_text() or "" for page in pdf.pages)


def normalize_text(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return re.sub(r"(?<=\d)\s+(?=[a-z])", "", normalized)


def read_certificate_pages(path: str) -> tuple[int, list[dict]]:
    """Read certificate text and only extract tables from plausible machine pages."""
    try:
        import pdfplumber
    except ImportError as exc:
        raise RuntimeError("PDF reading module is missing. Reinstall using the included setup instructions.") from exc
    result = []
    with pdfplumber.open(path) as pdf:
        page_count = len(pdf.pages)
        for page_number, page in enumerate(pdf.pages, 1):
            text = page.extract_text() or ""
            meaningful = re.sub(r"(?im)^\s*powered\s+by\s+tcpdf.*$", "", text).strip()
            meaningful = re.sub(r"(?m)^\s*\d+\s*/\s*\d+\s*$", "", meaningful).strip()
            if not meaningful:
                continue
            # Table extraction is the expensive part for long certificates.
            # Skip it on pages that cannot contain an instrument record while
            # retaining text extraction for page numbering and header fields.
            is_stamping_transcription = bool(re.search(r"CERTIFICATE\s+DATA\s+TRANSCRIPTION", text, re.I))
            machine_page = is_stamping_transcription or bool(re.search(
                r"machine\s*(?:no\.?|number)|make\s*:|max\s*:|min\s*:|\be\s*/\s*d\s*:|"
                r"denomination|verification\s+fee|iron\s+hexagonal|weights\s+and\s+parallelepiped",
                text, re.I,
            ))
            tables = page.extract_tables() or [] if machine_page else []
            if meaningful:
                result.append({"page_number": page_number, "text": text, "tables": tables})
    return page_count, result


def first(pattern: str, text: str, flags=re.I | re.S) -> str:
    match = re.search(pattern, text, flags)
    return re.sub(r"\s+", " ", match.group(1)).strip(" .,:;\n") if match else ""


def _extract_machine_record(text: str, tables=None) -> dict[str, str]:
    """Read one weighing instrument row from a certificate table when available."""
    record = {name: "" for name in MACHINE_REVIEW_FIELDS}
    for table in tables or []:
        for row in table:
            cells = [str(cell or "") for cell in row]
            if len(cells) < 9 or not re.search(r"machine\s*(?:no|number)|make\s*:", " ".join(cells), re.I):
                continue
            manufacturer, model_cell, number_cell = cells[6], cells[7], cells[8]
            record.update({
                "Instrument description": _clean_cell(cells[0]),
                "Denomination": _clean_cell(cells[2]),
                "Weights": _clean_cell(cells[2]) if _is_weights_item(cells[0]) else "",
                "Quantity": _clean_cell(cells[1]),
                "Instrument make": first(r"Make\s*:\s*(.+?)(?=\s+Max\s*:|\s+Min\s*:|\s+e/d\s*:|$)", manufacturer),
                "Maximum capacity": first(r"Max\s*:\s*(.+?)(?=\s+Min\s*:|\s+e/d\s*:|$)", manufacturer),
                "Minimum capacity": first(r"Min\s*:\s*(.+?)(?=\s+e/d\s*:|$)", manufacturer),
                "Verification interval (e/d)": first(r"e/d\s*:\s*(.+?)\s*$", manufacturer),
                "Instrument model": _extract_model_value(model_cell),
                "Machine number": first(r"Machine\s*(?:No\.?|Number)\s*:\s*(.+)$", number_cell),
                "Class": _clean_cell(cells[5]),
                "Additional fee": first(r"50%\s+Additional\s+Fee\s*:\s*([\d,.]+)", cells[9]) if len(cells) > 9 else "",
            })
            for key in ("Instrument make", "Maximum capacity", "Minimum capacity", "Verification interval (e/d)", "Machine number"):
                record[key] = _clean_cell(record[key])
            if _is_weights_item(record.get("Instrument description", "")):
                record["Weights"] = record.get("Denomination", "")
                for key in ("Instrument make", "Maximum capacity", "Minimum capacity", "Verification interval (e/d)", "Instrument model", "Machine number"):
                    record[key] = ""
                record["Class"] = ""
            return record
    # Text-only fallback; keep each field bounded so adjacent table columns cannot leak into it.
    record.update({
        "Instrument description": first(r"((?:Non-)?Automatic\s+.+?Class\s+(?:III|IIII|II|IV))\s*(?:\(|\n)", text),
        "Instrument make": first(r"Make\s*:\s*([^\n]+?)(?=\s+Max\s*:|\s+Min\s*:|\s+e/d\s*:|\s+Model\b|\s+Machine\s+No|$)", text),
        "Instrument model": _extract_model_value(text),
        "Machine number": first(r"Machine\s+No\.?\s*:\s*([^\n]+)", text),
        "Maximum capacity": first(r"Max\s*:\s*([^\n]+?)(?=\s+Min\s*:|\s+e/d\s*:|$)", text),
        "Minimum capacity": first(r"Min\s*:\s*([^\n]+?)(?=\s+e/d\s*:|$)", text),
        "Verification interval (e/d)": first(r"e/d\s*:\s*([^\n]+)", text),
        "Class": first(r"\bClass\s+(III|IIII|II|IV|I)\b", text),
        "Quantity": first(r"(?:\n|Items\s+)\s*(\d{1,3})\s+\d+(?:\s*[a-zA-Z]+)?\s+-", text),
    })
    if _is_weights_item(record.get("Instrument description", "")):
        record["Weights"] = first(r"\b(\d+(?:\.\d+)?\s*(?:kg|g))\.?\b", text)
    return record


def _is_weights_item(description: str) -> bool:
    normalized = normalize_text(description)
    return "iron hexagonal knob type weights" in normalized and "parallelepiped weights" in normalized


def _item_count(value: str) -> int:
    """Use the printed count, or one unit for each distinct certificate row."""
    match = re.search(r"\d+", str(value or ""))
    return int(match.group(0)) if match else 1


def plan_machine_parts(machine_count: int, max_per_part: int = 35,
                       split_threshold: int = 40, min_tail: int = 10) -> list[int]:
    """Plan separate applications for large certificates.

    Up to 40 machines stay together. Larger files are balanced into batches
    of at most 35 where possible. A final remainder below 10 reduces the
    number of parts by one, then redistributes machines evenly (73 -> 37 +
    36). With two batches, rebalance them so neither creates a tiny part
    (for example 41 -> 21 + 20).
    """
    try:
        total = max(0, int(machine_count))
    except (TypeError, ValueError):
        return []
    if total == 0:
        return []
    if total <= split_threshold:
        return [total]

    part_count = math.ceil(total / max_per_part)
    # A tail below ten should not become its own application. Reduce the
    # number of parts and rebalance the records over the remaining parts.
    greedy_tail = total - max_per_part * (part_count - 1)
    if part_count >= 3 and 0 < greedy_tail < min_tail:
        part_count -= 1

    quotient, remainder = divmod(total, part_count)

    if part_count == 2:
        return [quotient + remainder, quotient]
    # Put any balancing extras at the end for predictable, near-even parts.
    return [quotient] * (part_count - remainder) + [quotient + 1] * remainder


def _clean_cell(value: str) -> str:
    value = (value or "").replace("–", "-").replace("—", "-").replace("−", "-").replace("�", " ")
    cleaned = re.sub(r"\s+", " ", value).strip(" .,:;\n")
    cleaned = re.sub(r"(?i)\bnon-\s+automatic\b", "Non-Automatic", cleaned)
    cleaned = re.sub(r"\(\s+", "(", cleaned)
    return re.sub(r"\bweigh\s+t\b", "weight", cleaned, flags=re.I)


def _clean_model(value: str) -> str:
    """Join fragments split by PDF line wrapping without joining whole words."""
    lines = [re.sub(r"\s+", " ", line).strip() for line in str(value or "").splitlines()]
    result = ""
    for line in (line for line in lines if line):
        if not result:
            result = line
            continue
        left = re.search(r"([A-Za-z0-9]+)$", result)
        right = re.match(r"([A-Za-z0-9]+)(.*)$", line)
        join_fragment = False
        if left and right:
            previous_fragment = left.group(1)
            next_fragment = right.group(1)
            # Numeric/code suffixes such as ELT3 + 0, plus short final
            # fragments such as weigh + t, are common in wrapped model cells.
            join_fragment = (
                len(next_fragment) <= 1
                or (previous_fragment[-1].isdigit() and next_fragment[0].isdigit())
            )
        if join_fragment:
            result += right.group(1) + right.group(2)
        else:
            result += " " + line
    return _clean_cell(result)


def _extract_model_value(text: str) -> str:
    """Extract a wrapped Model cell up to the next known certificate field."""
    match = re.search(
        r"\bModel\s*:\s*(.*?)(?=\bMachine\s*(?:No\.?|Number)\s*:|"
        r"\b(?:Stamping|Verification)\s+Fee\s*:|\b50%\s+Additional\s+Fee\s*:|$)",
        str(text or ""), re.I | re.S,
    )
    return _clean_model(match.group(1)) if match else ""


def extract_certificate_document(path: str) -> tuple[int, int, dict[str, str], list[dict[str, str]]]:
    page_count, pages = read_certificate_pages(path)
    machines = []
    first_machine_page = None
    for page in pages:
        machine = _extract_machine_record(page["text"], page["tables"])
        if machine.get("Machine number") or machine.get("Instrument make") or _is_weights_item(machine.get("Instrument description", "")):
            machine["Previous CV number"] = first(r"CV\s*No\.?\s*:\s*([^\n]+)", page["text"])
            machine["Previous CV date"] = extract_certificate(page["text"], page["tables"]).get("Previous CV date", "")
            machine["Source PDF page"] = page["page_number"]
            machine["Application number"] = first(r"Application\s+Number\s*:\s*([^\n]+)", page["text"])
            machine["Additional fee"] = first(r"50%\s+Additional\s+Fee\s*:\s*([\d,.]+)", page["text"]) or machine.get("Additional fee", "")
            machine["Stamping office/site"] = first(r"Stamping\s+at\s+(Office|Site)", page["text"])
            if first_machine_page is None:
                first_machine_page = page
            machines.append(machine)
    if not machines or first_machine_page is None:
        raise RuntimeError("No machine table was found in the PDF. Use a text-searchable previous CV or check the document.")
    values = extract_certificate(first_machine_page["text"], first_machine_page["tables"])
    values.update({key: value for key, value in machines[0].items() if key != "Source PDF page"})
    values["Repairer name"] = ""  # Filled from the selected PAN profile in the UI.
    if values.get("Stamping office/site", "").lower() == "site":
        fees = [re.sub(r"[^\d.]", "", row.get("Additional fee", "")) for row in machines]
        values["Dormant / Other"] = "Dormant" if fees and all(fee and float(fee) == 0 for fee in fees) else "Other"
    else:
        values["Dormant / Other"] = ""
    return page_count, len(pages), values, machines


def _locality_components(address: str) -> dict:
    """Split a locality using stable right-hand Taluk and District anchors."""
    parts = [re.sub(r"\s+", " ", part).strip(" \t\r\n.,") for part in (address or "").split(",")]
    parts = [part for part in parts if part]
    taluk_index = next((i for i, part in enumerate(parts) if re.search(r"\btaluk\b", part, re.I)), -1)
    taluk = town = district = ""
    town_index = -1
    if taluk_index >= 0:
        match = re.search(r"^(.+?)\s+taluk\b", parts[taluk_index], re.I)
        taluk = match.group(1).strip(" ,.") if match else re.sub(r"\s*taluk\b.*$", "", parts[taluk_index], flags=re.I).strip(" ,.")
        if taluk_index > 0:
            town_index = taluk_index - 1
            town = parts[town_index]
        for part in parts[taluk_index + 1:]:
            if re.search(r"\bTamil\s*Nadu\b", part, re.I) or re.fullmatch(r"\d{6}", part):
                continue
            district = part
            break

    prefix = parts[:town_index] if town_index >= 0 else []
    street_parts = prefix[-1:] if prefix else []
    door_parts = prefix[:-1] if prefix else []
    # Numeric plot/door identifiers anchor the left edge. The live Street
    # dropdown will determine the exact end of Street for comma-separated names.
    if len(prefix) > 1 and re.fullmatch(r"\d+[/-]\d+[A-Za-z]?(?:\s+.*)?", prefix[0]):
        door_parts = prefix[:1]
        street_parts = prefix[1:]

    return {
        "parts": parts,
        "taluk_index": taluk_index,
        "town_index": town_index,
        "prefix_parts": prefix,
        "taluk": taluk,
        "district": district,
        "town": town,
        "street": ", ".join(street_parts),
        "door_number": ", ".join(door_parts),
    }


def extract_certificate(text: str, tables=None) -> dict[str, str]:
    """Best-effort extraction. Never invent a value; unresolved fields stay blank."""
    # Keep the CV number paired with the Date immediately following it in the
    # certificate header, so a later machine-table date cannot be mistaken
    # for the previous CV date.
    cv_header = re.search(
        r"CV\s*No\.?\s*:\s*([A-Z0-9/.-]+)\s+Date\s*:\s*(\d{2}[-/]\d{2}[-/]\d{4})\b",
        text,
        re.I,
    )
    values = {
        "Previous CV number": _clean_cell(cv_header.group(1)) if cv_header else first(r"CV\s*No\.?\s*:\s*([^\n]+)", text),
        "Previous CV date": cv_header.group(2).replace("/", "-") if cv_header else first(r"Date\s*:\s*([^\n]+)", text),
        "Applicant / establishment name": first(r"belonging to\s+M/S\s+(.+?)(?:,\s*Locality|\n)", text),
        "Instrument description": first(r"((?:Non-)?Automatic\s+.+?Class\s+(?:III|II|IV))\s*(?:\(|\n)", text),
        "Instrument make": first(r"Make\s*:\s*([^\n]+?)(?:\s+Max\s*:|\s+Model\s*:|\s+Machine\s+No\.?\s*:|\n)", text),
        "Instrument model": _extract_model_value(text),
        "Machine number": first(r"Machine\s+No\.?\s*:\s*([^\n]+)", text),
        "Maximum capacity": first(r"Max\s*:\s*([^\n]+?)(?:\s+Min\s*:|\s+e/d\s*:|\n)", text),
        "Minimum capacity": first(r"Min\s*:\s*([^\n]+?)(?:\s+e/d\s*:|\n)", text),
        "Verification interval (e/d)": first(r"e/d\s*:\s*([^\n]+)", text),
        "Class": first(r"Class\s+(III|IIII|II|I)\b", text),
        "Quantity": first(r"(?:\n|Items\s+)\s*(?:\d+\s+)?(\d{1,3})\s+\d+(?:\s*[a-zA-Z]+)?\s+-", text),
        "Repairer name": first(r"Repaired by\s+(.+?)(?:,\s*\d|\n)", text),
        "Repairer mobile": first(r"Repaired by\s+.+?,\s*(\d{10})\b", text),
        "Repairer licence number": first(r"Licence Number\s*:\s*([^\n.]+)", text),
        "Stamping office/site": first(r"Stamping\s+at\s+(Office|Site)", text),
    }
    values.update(_extract_address_fields(text))
    values["Repairer licence date"] = first(r"Licence Number\s*:\s*[^\n]*?(\d{2}[-/]\d{2}[-/]\d{4})", text)
    values["Repairer business name"] = first(r"Repaired by\s+(.+?)(?:,\s*\d|\n)", text)
    values["Trader / establishment number"] = first(r"Trader\s+No\.?\s*:\s*\n\s*([^\n]+)", text)
    values.update(_extract_machine_record(text, tables))
    return values


def _extract_address_fields(text: str) -> dict[str, str]:
    """Extract address components without depending on a machine table."""
    raw_address = first(
        r"\bLocality\s+(.+?)(?=\s+Items\s+Quant(?:ity)?\b|\s+Verification\s+Fee\b|$)",
        text,
    )
    if not raw_address:
        raw_address = first(
            r"\bAddress\s*[:\-]\s*(.+?)(?=\s+(?:Phone|Mobile|Cell|GSTIN?|PAN|Items\b|Invoice\s+No)\b|$)",
            text,
        )
    if not raw_address:
        # Many certificates print the address in a block ending with the PIN,
        # without an explicit Address/Locality label. Keep only the lines
        # surrounding the first PIN rather than absorbing the rest of a PDF.
        lines = [re.sub(r"\s+", " ", line).strip() for line in (text or "").splitlines() if line.strip()]
        pin_index = next((i for i, line in enumerate(lines) if re.search(r"\b\d{6}\b", line)), -1)
        if pin_index >= 0:
            start = max(0, pin_index - 4)
            raw_address = ", ".join(lines[start:pin_index + 1])
    location = _locality_components(raw_address)
    return {
        "Business address": raw_address,
        "State": "Tamil Nadu" if re.search(r"Tamil\s*Nadu", raw_address or text, re.I) else "",
        "District": location["district"],
        "Taluk": location["taluk"],
        "Town / Village": location["town"],
        "Street": location["street"],
        "Door number": location["door_number"],
        "Pincode": first(r"\b(\d{6})\b", raw_address),
    }


def extract_address_document(path: str) -> dict[str, str]:
    """Read address-only source PDFs; machine/CV data is intentionally ignored."""
    text = pdf_text(path)
    if not text.strip():
        raise RuntimeError("No selectable text was found in the address PDF. Use a text-searchable PDF.")
    fields = _extract_address_fields(text)
    # When an alternate address PDF is selected, its applicant/establishment
    # name must override the name from the Previous CV. Prefer an explicit
    # field label, then the standard M/S ... , Locality line. Flattening the
    # latter handles PDF line wraps inside a business name.
    flat_text = re.sub(r"\s+", " ", text)
    applicant_name = first(
        r"(?:Applicant\s*/\s*Establishment\s*Name|Name\s+of\s+(?:the\s+)?(?:Applicant|Establishment|User|Owner)|Establishment\s+Name|Applicant\s+Name)\s*[:\-]\s*(.+?)(?=,\s*(?:Locality|Address|Door\s*(?:No|Number)|Street)\b|\r?$)",
        text,
        re.I | re.M,
    )
    if not applicant_name:
        applicant_name = first(
            r"(?:belonging\s+to\s+)?M/S\.?\s+(.+?)(?=,\s*(?:Locality|Address|Door\s*(?:No|Number)|Street)\b)",
            flat_text,
        )
    if not applicant_name:
        raise RuntimeError(
            "Could not identify the applicant/establishment name in the selected address PDF. "
            "Include an Applicant/Establishment Name field or an M/S name before the address. "
            "The Previous CV name will not be substituted."
        )
    fields["Applicant / establishment name"] = applicant_name
    if not any(fields.get(key) for key in ("Business address", "District", "Taluk", "Town / Village", "Pincode")):
        raise RuntimeError("No recognizable address was found. Use a PDF containing an address or locality with its PIN code.")
    return fields


class PortalWorker(threading.Thread):
    """Owns a persistent Playwright session; user handles CAPTCHA and payment."""
    def __init__(self, messages: queue.Queue):
        super().__init__(daemon=True)
        self.messages = messages
        self.commands: queue.Queue = queue.Queue()
        self.page = None
        self.context = None
        self.browser = None
        self.owns_browser = False
        self.ready = threading.Event()
        self.pending_application = None
        self.ready_for_submit = False
        self.final_edit_retry_used = False
        self.workflow_step = 0
        self.waiting_for_login = False
        self.login_attempt_at = 0.0
        self.last_captcha_value = ""
        self.captcha_candidate_value = ""
        self.captcha_candidate_since = 0.0
        self.application_queue: list[dict] = []
        self.application_queue_index = -1

    def _publish_fill_report(self, report):
        self.messages.put(("details", report))
        if report["required_blank"]:
            missing = "; ".join(report["required_blank"][:16])
            reasons = "; ".join(report.get("skipped", [])[:12])
            detail = f" Automation details: {reasons}." if reasons else ""
            self.messages.put(("error", f"The portal page is still incomplete. Missing or unconfirmed: {missing}.{detail} Complete those fields in the app browser; the application was not submitted."))
        elif not report.get("final_submit_visible"):
            self.messages.put(("error", "The portal did not reach a page with a visible Submit control. Review the fields reported as skipped, then use Fill now / retry; nothing was submitted."))
        else:
            self.ready_for_submit = True
            self.messages.put(("ready_to_submit", "The form reached final review. Check it in Chromium, then choose Submit application in the assistant when ready."))

    def run(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.ready.set()
            self.messages.put(("error", "Playwright is not installed. Follow README setup/build steps."))
            return
        with sync_playwright() as pw:
            try:
                browser, context, attached = self._connect_or_launch_chromium(pw)
                self.browser = browser
                self.context = context
                self.owns_browser = not attached
                self.page = self._find_active_portal_page(context)
                if self.page is None:
                    self.page = context.new_page()
                self.page.set_default_timeout(9000)
                self.page.set_default_navigation_timeout(20000)
            except Exception as e:
                self.ready.set()
                self.messages.put(("error", f"Could not reuse or initialize the bundled Chromium session. The assistant will not open a duplicate browser.\n{e}"))
                return
            self.ready.set()
            while True:
                try:
                    cmd, payload = self.commands.get(timeout=0.5)
                except queue.Empty:
                    if self.waiting_for_login:
                        try:
                            self._restore_active_portal_page()
                            if self._logged_in():
                                self.waiting_for_login = False
                                self.login_attempt_at = 0.0
                                self.messages.put(("login_ok", "Portal sign-in succeeded. Continue with Fill now / retry when the PDF draft is ready."))
                            else:
                                self._submit_login_after_captcha()
                                self._report_login_failure_if_due()
                        except Exception as exc:
                            self.waiting_for_login = False
                            self.messages.put(("error", f"The active Chromium session could not be checked. It was left open and no replacement browser was started. {exc}"))
                        continue
                    if self.pending_application is not None:
                        try:
                            self._restore_active_portal_page()
                            if not self._logged_in():
                                self._submit_login_after_captcha()
                                self._report_login_failure_if_due()
                                continue
                        except Exception as exc:
                            self.messages.put(("error", f"The active Chromium session could not be checked. It was left open and no replacement browser was started. {exc}"))
                            continue
                        application = self.pending_application
                        self.pending_application = None
                        self.login_attempt_at = 0.0
                        try:
                            if self.application_queue:
                                self._open_queued_application(0)
                            else:
                                report = self._fill_form(application)
                                report["automatic"] = True
                                self._publish_fill_report(report)
                        except Exception as e:
                            self.messages.put(("error", f"Login was detected, but the automatic form steps stopped safely: {e}"))
                    continue
                if cmd == "stop":
                    break
                try:
                    if cmd == "open":
                        self.pending_application = payload.get("application")
                        self.ready_for_submit = False
                        self._restore_active_portal_page()
                        if self._logged_in():
                            self.waiting_for_login = False
                            self.login_attempt_at = 0.0
                            self.messages.put(("opened", "Reused the active signed-in Chromium page; it was not restarted or navigated away."))
                        else:
                            current_url = (self.page.url or "").strip().lower()
                            if self._is_login_page():
                                self.waiting_for_login = True
                                self._fill_login(payload["credentials"])
                                self.messages.put(("opened", "Reused the active Chromium login page and filled saved sign-in. Enter the CAPTCHA there; the application will continue automatically after login."))
                            elif current_url in {"", "about:blank", "chrome://newtab/"}:
                                self.waiting_for_login = True
                                self._open_login_page()
                                self._fill_login(payload["credentials"])
                                self.messages.put(("opened", "Opened the portal in the existing Chromium window and filled saved sign-in. Enter the CAPTCHA there; the application will continue automatically after login."))
                            else:
                                self.waiting_for_login = False
                                self.messages.put(("error", "The active Chromium page is not the portal login or stamping form. It was left unchanged; navigate to the portal in that window, then use Fill now / retry."))
                    elif cmd == "fill":
                        self._restore_active_portal_page()
                        if self.application_queue and 0 <= self.application_queue_index < len(self.application_queue):
                            payload = self.application_queue[self.application_queue_index]
                        if not self._logged_in():
                            if self._is_login_page():
                                self.pending_application = payload
                                self.waiting_for_login = True
                                self._fill_login(payload.get("credentials", {}))
                                self.messages.put(("opened", "Sign in is needed. The current login page was kept open; complete the CAPTCHA to continue."))
                            else:
                                self.messages.put(("error", "The current portal page could not be confirmed as signed in. It was left open; sign in manually if needed, then retry."))
                        else:
                            report = self._fill_form(payload)
                            self._publish_fill_report(report)
                    elif cmd == "new_application":
                        # The current browser context keeps the existing portal
                        # cookies. Navigate this same tab back to the service
                        # landing page, open New Stamping, and reset only the
                        # workflow step for the new reviewed PDF.
                        self._restore_active_portal_page()
                        if not self._logged_in():
                            raise RuntimeError("The existing portal session is no longer signed in. Sign in in the current Chromium window, then start the new application again.")
                        self.ready_for_submit = False
                        self.pending_application = None
                        self.workflow_step = 0
                        self.final_edit_retry_used = False
                        self._navigate_to_stamping_form(force_new=True)
                        report = self._fill_form(payload)
                        self._publish_fill_report(report)
                    elif cmd == "apply_all_parts":
                        applications = payload.get("applications", [])
                        if len(applications) < 2:
                            raise RuntimeError("This PDF does not contain multiple application parts.")
                        if self.application_queue:
                            raise RuntimeError("A multi-part application is already in progress. Finish or correct its current part first.")
                        self._restore_active_portal_page()
                        self.application_queue = applications
                        self.application_queue_index = 0
                        self.ready_for_submit = False
                        self.messages.put(("multi_part_started", len(applications)))
                        if not self._logged_in():
                            self.pending_application = applications[0]
                            self.waiting_for_login = True
                            current_url = (self.page.url or "").strip().lower()
                            if self._is_login_page():
                                self._fill_login(payload.get("credentials", {}))
                                self.messages.put(("opened", "Sign in once and complete CAPTCHA. All remaining application parts will reuse this signed-in session."))
                            elif current_url in {"", "about:blank", "chrome://newtab/"}:
                                self._open_login_page()
                                self._fill_login(payload.get("credentials", {}))
                                self.messages.put(("opened", "Sign in once and complete CAPTCHA. All remaining application parts will reuse this signed-in session."))
                            else:
                                self._open_login_page()
                                self._fill_login(payload.get("credentials", {}))
                                self.messages.put(("opened", "Sign in once and complete CAPTCHA. All remaining application parts will reuse this signed-in session."))
                        else:
                            self._open_queued_application(0)
                    elif cmd == "submit":
                        submitted = self._submit()
                        if submitted and self.application_queue:
                            self._open_queued_application(self.application_queue_index + 1)
                    elif cmd == "credentials":
                        if not self._logged_in():
                            if self.pending_application is None:
                                self.pending_application = payload.get("application")
                            self._fill_login(payload["credentials"])
                            self.messages.put(("status", "Updated the login form with the edited saved credentials. Complete the CAPTCHA again to retry."))
                except Exception as e:
                    self.messages.put(("error", f"Portal action stopped safely: {e}"))
            try:
                if self.context is not None and self.owns_browser:
                    self.context.close()
                if self.browser is not None:
                    # For a CDP-attached browser this disconnects Playwright;
                    # it must not close the user's already-running Chromium.
                    self.browser.close()
            except Exception:
                pass

    @staticmethod
    def _find_active_portal_page(context):
        """Prefer the existing portal tab so retry never opens another window."""
        try:
            pages = [page for page in context.pages if not page.is_closed()]
            portal_pages = [page for page in pages if "labour.tn.gov.in" in (page.url or "").lower()]
            if portal_pages:
                stamping = [page for page in portal_pages if "/stamping" in (page.url or "").lower()]
                return stamping[-1] if stamping else portal_pages[-1]
            return pages[-1] if pages else None
        except Exception:
            return None

    def _restore_active_portal_page(self):
        """Recover an open tab in the current Chromium context, never launch another."""
        if self.context is None:
            raise RuntimeError("The Chromium context is not available; reopen the assistant before starting another session.")
        try:
            if self.page is not None and not self.page.is_closed():
                return
        except Exception:
            pass
        page = self._find_active_portal_page(self.context)
        if page is None:
            page = self.context.new_page()
        page.set_default_timeout(9000)
        page.set_default_navigation_timeout(20000)
        self.page = page

    @staticmethod
    def _bundled_chromium_is_running():
        """Detect an old bundled browser process that cannot be safely reattached."""
        browser_root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
        if not browser_root or not Path(browser_root).is_dir():
            return False
        try:
            candidates = [os.path.normcase(os.path.abspath(str(path))) for pattern in
                          ("chromium-*/chrome-win/chrome.exe", "chromium-*/chrome-win64/chrome.exe")
                          for path in Path(browser_root).glob(pattern)]
            if not candidates:
                return False
            from ctypes import wintypes
            TH32CS_SNAPPROCESS = 0x00000002
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            kernel32.Process32FirstW.restype = wintypes.BOOL
            kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            kernel32.Process32NextW.restype = wintypes.BOOL
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snapshot == wintypes.HANDLE(-1).value:
                return False
            try:
                entry = PROCESSENTRY32W()
                entry.dwSize = ctypes.sizeof(entry)
                has_process = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
                while has_process:
                    if entry.szExeFile.lower() == "chrome.exe":
                        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, entry.th32ProcessID)
                        if handle:
                            try:
                                buffer = ctypes.create_unicode_buffer(32768)
                                size = wintypes.DWORD(len(buffer))
                                if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                                    image = os.path.normcase(os.path.abspath(buffer.value))
                                    is_playwright_chromium = (
                                        image in candidates
                                        or bool(re.search(r"[\\/]chromium-\d+[\\/]chrome-win(?:64)?[\\/]chrome\.exe$", image, re.I))
                                    )
                                    if is_playwright_chromium:
                                        return True
                            finally:
                                kernel32.CloseHandle(handle)
                    has_process = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
            finally:
                kernel32.CloseHandle(snapshot)
        except Exception:
            # If process inspection is unavailable, the CDP port check still
            # prevents duplicate launches for sessions started by this build.
            return False
        return False

    @classmethod
    def _connect_or_launch_chromium(cls, pw):
        """Attach to this app's active Chromium first; launch only when none exists."""
        try:
            browser = pw.chromium.connect_over_cdp(CHROMIUM_CDP_ENDPOINT, timeout=2500)
            contexts = browser.contexts
            if contexts:
                return browser, contexts[0], True
            browser.close()
        except Exception:
            pass
        if cls._bundled_chromium_is_running():
            raise RuntimeError("A bundled Chromium process is already active but cannot be reattached. It was left untouched; close that browser window and retry to avoid opening a duplicate.")
        browser = pw.chromium.launch(
            headless=False,
            timeout=60000,
            args=["--start-maximized", "--remote-debugging-port=9229"],
        )
        context = browser.new_context(no_viewport=True)
        return browser, context, False

    def _open_login_page(self):
        """Open the portal while tolerating its immediate login-to-service redirect."""
        try:
            self.page.goto(PORTAL_URL, wait_until="commit", timeout=30000)
        except Exception as exc:
            message = str(exc).lower()
            # Some portal responses redirect again before Playwright's navigation
            # waiter settles. Continue only for that expected interruption.
            if "interrupted by another navigation" not in message and "net::err_aborted" not in message:
                raise
        previous_url = None
        for _ in range(4):
            try:
                self.page.locator("body").wait_for(state="attached", timeout=8000)
            except Exception:
                pass
            try:
                self.page.wait_for_load_state("domcontentloaded", timeout=6000)
            except Exception as exc:
                message = str(exc).lower()
                if "interrupted by another navigation" not in message and "timeout" not in message:
                    raise
            self.page.wait_for_timeout(250)
            current_url = self.page.url
            if current_url == previous_url:
                return
            previous_url = current_url

    def send(self, cmd: str, payload=None):
        # Never block the Tk UI waiting for Chromium. Queue the first command
        # immediately; the worker consumes it once Playwright and the browser
        # are ready, or posts a copyable startup error if they fail.
        if self.ident is None:
            self.start()
        elif not self.is_alive():
            raise RuntimeError("The Chromium worker stopped. Close and reopen the app, then retry.")
        self.commands.put((cmd, payload))

    def _login_controls(self):
        """Find the portal's visible username and password fields, including delayed forms."""
        for frame in self.page.frames:
            try:
                password = frame.locator('input[type="password"]:visible').first
                if not password.count():
                    continue
                inputs = frame.locator('input:visible').all()
                candidates = []
                for field in inputs:
                    kind = (field.get_attribute("type") or "text").lower()
                    if kind not in ("text", "email", "tel"):
                        continue
                    metadata = " ".join(filter(None, [
                        field.get_attribute("name"), field.get_attribute("id"),
                        field.get_attribute("placeholder"), field.get_attribute("aria-label"),
                        field.get_attribute("autocomplete"),
                    ])).lower()
                    score = sum(word in metadata for word in ("user", "email", "registered", "login"))
                    candidates.append((score, field))
                if candidates:
                    candidates.sort(key=lambda entry: entry[0], reverse=True)
                    return candidates[0][1], password
                labelled = frame.get_by_label(re.compile(r"username|registered email|email", re.I)).first
                if labelled.count():
                    return labelled, password
            except Exception:
                continue
        return None, None

    def _fill_login(self, data):
        if not data.get("username") or not data.get("password"):
            raise RuntimeError("Select a saved sign-in before opening the portal.")
        deadline = time.monotonic() + 30
        user, password = None, None
        while time.monotonic() < deadline:
            user, password = self._login_controls()
            if user is not None and password is not None:
                break
            self.page.wait_for_timeout(300)
        if user is None or password is None:
            raise RuntimeError("The portal login fields did not appear. Check that the login page finished loading, then retry.")
        user.fill(data["username"])
        password.fill(data["password"])
        if user.input_value() != data["username"] or password.input_value() != data["password"]:
            raise RuntimeError("The portal did not accept the saved sign-in values in its login fields.")
        self.last_captcha_value = ""
        self.captcha_candidate_value = ""
        self.captcha_candidate_since = 0.0

    def _captcha_value(self):
        for frame in self.page.frames:
            try:
                for field in frame.locator('input:visible').all():
                    metadata = " ".join(filter(None, [
                        field.get_attribute("name"), field.get_attribute("id"),
                        field.get_attribute("placeholder"), field.get_attribute("aria-label"),
                        field.evaluate("el => [...(el.labels || [])].map(label => label.innerText).join(' ')"),
                    ])).lower()
                    if re.search(r"captcha|verification\s+code|security\s+code|image\s+code", metadata):
                        value = field.input_value().strip()
                        if value:
                            focused = field.evaluate("el => document.activeElement === el")
                            return value, focused, False
                for token in frame.locator('textarea[name="g-recaptcha-response"],textarea[name="h-captcha-response"]').all():
                    value = token.input_value().strip()
                    if value:
                        return value, False, True
            except Exception:
                continue
        return "", False, False

    def _submit_login_after_captcha(self):
        """Submit only after the user has entered/completed the CAPTCHA."""
        value, field_focused, is_provider_token = self._captcha_value()
        if not value:
            self.last_captcha_value = ""
            self.captcha_candidate_value = ""
            self.captcha_candidate_since = 0.0
            return
        if value == self.last_captcha_value:
            return
        if value != self.captcha_candidate_value:
            self.captcha_candidate_value = value
            self.captcha_candidate_since = 0.0 if field_focused else time.monotonic()
            return
        if field_focused and not is_provider_token:
            self.captcha_candidate_since = 0.0
            return
        if not self.captcha_candidate_since:
            self.captcha_candidate_since = time.monotonic()
            return
        if time.monotonic() - self.captcha_candidate_since < 1.5:
            return
        for frame in self.page.frames:
            try:
                password = frame.locator('input[type="password"]:visible').first
                if not password.count():
                    continue
                button = frame.get_by_role("button", name=re.compile(r"^(log\s*in|sign\s*in)$", re.I)).last
                if button.count() and button.is_visible():
                    button.click()
                else:
                    form = password.locator("xpath=ancestor::form[1]")
                    submit = form.locator('button[type="submit"],input[type="submit"]').last
                    if not submit.count():
                        continue
                    submit.click()
                self.last_captcha_value = value
                self.login_attempt_at = time.monotonic()
                self.messages.put(("status", "CAPTCHA entry is complete. Signing in and continuing automatically."))
                return
            except Exception:
                continue

    def _report_login_failure_if_due(self):
        if not self.login_attempt_at or time.monotonic() - self.login_attempt_at < 15:
            return
        self.login_attempt_at = 0.0
        diagnostic = self._login_error_text()
        detail = f" Portal message: {diagnostic}" if diagnostic else " No readable portal error message was found."
        self.messages.put(("login_failed", "Sign-in was not confirmed after Login. Check the saved email/password with Edit credentials, then retry; the CAPTCHA may have expired or been rejected." + detail))

    def _login_error_text(self) -> str:
        """Read short, visible validation messages without collecting page contents or field values."""
        candidates = []
        selectors = (
            '[role="alert"]', '.alert', '.alert-danger', '.error', '.error-message',
            '.invalid-feedback', '.validation-summary-errors', '[aria-invalid="true"] + *',
        )
        for frame in self.page.frames:
            for selector in selectors:
                try:
                    for item in frame.locator(selector).all()[:8]:
                        if not item.is_visible():
                            continue
                        text = re.sub(r"\s+", " ", item.inner_text(timeout=700)).strip()
                        if 3 <= len(text) <= 220 and text.lower() not in {value.lower() for value in candidates}:
                            candidates.append(text)
                except Exception:
                    continue
        # Never echo an email address from a portal validation message into the app log.
        safe = []
        for text in candidates:
            text = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[email hidden]", text, flags=re.I)
            if any(word in text.lower() for word in ("invalid", "incorrect", "captcha", "verification", "expired", "locked", "failed", "error", "required", "denied")):
                safe.append(text)
        return "; ".join(safe[:3])

    def _logged_in(self) -> bool:
        page = self.page
        if page is None or page.is_closed():
            return False
        if page.locator('input[type="password"]:visible').count():
            return False
        for pattern in (r"log\s*out", r"dashboard", r"inbox"):
            if page.get_by_text(re.compile(pattern, re.I)).count():
                return True
        if page.get_by_text(re.compile(r"THE LEGAL METROLOGY ACT", re.I)).count():
            return True
        current_url = (page.url or "").lower()
        if "/services/stamping-labours/" in current_url and not re.search(r"/login(?:[/?#]|$)", current_url):
            return True
        return False

    def _is_login_page(self) -> bool:
        """Recognize the login page without navigating away from the current form."""
        try:
            return bool(self.page.locator('input[type="password"]:visible').count()
                        or re.search(r"/login(?:[/?#]|$)", self.page.url, re.I))
        except Exception:
            return False

    def _click_if_visible(self, locator) -> bool:
        try:
            if locator.count() and locator.first.is_visible():
                locator.first.click()
                self.page.wait_for_timeout(350)
                return True
        except Exception:
            pass
        return False

    def _navigate_to_stamping_form(self, force_new=False):
        page = self.page
        if force_new:
            # Keep the signed-in browser context and its cookies, but start a
            # clean New Stamping form from the service landing page.
            page.goto(STAMPING_LIST_URL, wait_until="commit", timeout=30000)
            try:
                page.get_by_text(re.compile(r"The Legal Metrology Act,\s*2009.*Verification and Stamping", re.I)).first.wait_for(state="visible", timeout=15000)
            except Exception:
                if not self._logged_in():
                    raise RuntimeError("The portal session expired while opening the service page; sign in again in the current browser.")
        elif not self._logged_in():
            raise RuntimeError("Login is not detected yet. Complete the CAPTCHA and click Login in the app browser.")
        if not force_new and page.locator("#Stamping").count() and page.locator("#Stamping").first.is_visible():
            # The portal often renders its form shell before the fields become
            # available. Wait for the first actual control before building the
            # fill queue; otherwise every dependent field can be misreported as
            # absent even though the page is still loading.
            try:
                page.locator("#newgood:visible").wait_for(state="visible", timeout=20000)
            except Exception:
                pass
            return
        section = page.get_by_text(re.compile(r"The Legal Metrology Act,\s*2009.*Verification and Stamping", re.I))
        self._click_if_visible(section)
        stamping = page.get_by_role("link", name=re.compile(r"^Stamping$", re.I))
        if not self._click_if_visible(stamping):
            self._click_if_visible(page.get_by_text(re.compile(r"^Stamping$", re.I)))
        new_stamping = page.get_by_text(re.compile(r"\+\s*New Stamping", re.I))
        if not self._click_if_visible(new_stamping):
            self._click_if_visible(page.get_by_role("button", name=re.compile(r"New Stamping", re.I)))
        if not page.locator("#Stamping").count():
            try:
                page.goto(STAMPING_URL, wait_until="commit", timeout=30000)
                page.locator("#Stamping").wait_for(state="attached", timeout=10000)
            except Exception as exc:
                raise RuntimeError(f"Could not reach the New Stamping form: {exc}") from exc

    def _open_queued_application(self, index):
        """Open one part in a fresh tab inside the already signed-in context."""
        if index < 0 or index >= len(self.application_queue):
            self.application_queue = []
            self.application_queue_index = -1
            self.messages.put(("multi_part_done", "All split application parts reached their individual final review/payment steps. Payment remains manual in each tab."))
            return
        if self.context is None:
            raise RuntimeError("The signed-in Chromium context is no longer available; no replacement browser was started.")
        self.application_queue_index = index
        self.page = self.context.new_page()
        self.page.set_default_timeout(9000)
        self.page.set_default_navigation_timeout(20000)
        payload = self.application_queue[index]
        self._navigate_to_stamping_form(force_new=True)
        self.messages.put(("progress", f"Filling application part {index + 1} of {len(self.application_queue)} in a new signed-in tab"))
        report = self._fill_form(payload)
        report["application_part"] = index + 1
        report["application_part_count"] = len(self.application_queue)
        self.messages.put(("multi_part_part", (index, len(self.application_queue))))
        self._publish_fill_report(report)

    @staticmethod
    def _norm(s: str) -> str:
        return normalize_text(s)

    def _field_for(self, names):
        page = self.page
        for name in names:
            # Prefer native accessible label matching.
            loc = page.get_by_label(re.compile(re.escape(name), re.I)).first
            try:
                if loc.count() and loc.is_visible():
                    return loc
            except Exception:
                pass
        # Fallback to fieldset/section/nearby label association, still by visible text.
        for label in page.locator("label").all():
            try:
                text = self._norm(label.inner_text())
                if any(self._norm(n) == text or self._norm(n) in text for n in names):
                    target_id = label.get_attribute("for")
                    if target_id:
                        target = page.locator(f"#{target_id}")
                        if target.count() and target.first.is_visible():
                            return target.first
                    nested = label.locator("input,select,textarea").first
                    if nested.count() and nested.is_visible():
                        return nested
                    nearby = self._control_near_label(label)
                    if nearby is not None:
                        return nearby
            except Exception:
                continue
        return None

    def _control_near_label(self, label, scope=None, selector="input:not([type='hidden']),select,textarea"):
        """Resolve unassociated Bootstrap labels by their nearest following control."""
        root = scope or self.page
        try:
            label_box = label.evaluate("el => { const r=el.getBoundingClientRect(); return {top:r.top,bottom:r.bottom,left:r.left,right:r.right}; }")
            # Prefer the label's own form-group/column so a neighboring select
            # in the same visual row cannot be mistaken for a text input.
            for depth in range(1, 7):
                ancestor = label.locator("xpath=" + "/".join([".."] * depth))
                controls = ancestor.locator(selector)
                local = []
                for control in controls.all():
                    if not control.is_visible():
                        continue
                    box = control.evaluate("el => { const r=el.getBoundingClientRect(); return {top:r.top,left:r.left,right:r.right}; }")
                    vertical = box["top"] - label_box["bottom"]
                    horizontal = max(0, label_box["left"] - box["right"], box["left"] - label_box["right"])
                    if -8 <= vertical <= 100 and horizontal <= 100:
                        local.append((abs(vertical) + horizontal * 2, control))
                if local:
                    return min(local, key=lambda item: item[0])[1]
            candidates = []
            for control in root.locator(selector).all():
                if not control.is_visible():
                    continue
                box = control.evaluate("el => { const r=el.getBoundingClientRect(); return {top:r.top,left:r.left,right:r.right}; }")
                vertical = box["top"] - label_box["bottom"]
                horizontal = max(0, label_box["left"] - box["right"], box["left"] - label_box["right"])
                if -8 <= vertical <= 100 and horizontal <= 100:
                    candidates.append((abs(vertical) + horizontal * 2, control))
            return min(candidates, key=lambda item: item[0])[1] if candidates else None
        except Exception:
            return None

    def _portal_field(self, field):
        """Prefer a visible known ID, then fall back to the portal's visible label."""
        selectors = ([PORTAL_IDS[field]] if field in PORTAL_IDS else []) + list(PORTAL_ID_ALIASES.get(field, ()))
        for selector in selectors:
            if field == "Repairer licence number":
                # The live form exposes the repairer license input by its
                # country-specific placeholder; some portal revisions reuse
                # the legacy `licence-no` id for another readonly control.
                break
            direct = self.page.locator(selector)
            try:
                if direct.count() and direct.first.is_visible():
                    return direct.first
            except Exception:
                pass
        if field == "Repairer licence number":
            for selector in ('input[placeholder*="TN/" i]:visible', 'input[name*="licen" i]:visible', 'input[id*="licen" i]:visible'):
                direct = self.page.locator(selector)
                try:
                    if direct.count() == 1 and direct.first.is_enabled() and direct.first.is_editable():
                        return direct.first
                except Exception:
                    pass
        return self._field_for(FIELD_LABELS.get(field, [field]))

    def _field_in_section(self, heading_pattern, label_pattern, expected_tag=None):
        scope = self._section_locator(heading_pattern)
        def accepted(control):
            if control is None:
                return False
            if expected_tag:
                try:
                    return control.evaluate("el => el.tagName.toLowerCase()") == expected_tag
                except Exception:
                    return False
            return True
        try:
            heading_tops = []
            for heading in self._section_headings(heading_pattern):
                try:
                    heading_tops.append(float(heading.evaluate("el => el.getBoundingClientRect().top")))
                except Exception:
                    continue
            heading_top = min(heading_tops) if heading_tops else float("-inf")
            candidates = []
            # Accessible labels are more reliable than assuming the portal
            # nests each label beside its control in a particular Bootstrap
            # layout. Restrict the result by the selected section's position
            # so duplicate address labels resolve to the correct block.
            try:
                for control in self.page.get_by_label(re.compile(label_pattern, re.I)).all():
                    if control.is_visible() and accepted(control):
                        top = float(control.evaluate("el => el.getBoundingClientRect().top"))
                        if top >= heading_top:
                            candidates.append((top, control))
            except Exception:
                pass
            if candidates:
                return min(candidates, key=lambda item: item[0])[1]
            for label in self.page.locator("label,.control-label,[class*=label]").all():
                if not label.is_visible():
                    continue
                label_text = self._norm(label.inner_text())
                if not re.fullmatch(label_pattern, label_text, re.I):
                    continue
                label_top = float(label.evaluate("el => el.getBoundingClientRect().top"))
                # A broad ancestor can contain repeated labels from the license
                # and manufacturer sections. Use the first matching control
                # below this section's heading to stay in Establishment Details.
                if label_top < heading_top:
                    continue
                target_id = label.get_attribute("for")
                if target_id:
                    control = self.page.locator(f"#{target_id}")
                    if control.count() and control.first.is_visible() and accepted(control.first):
                        candidates.append((label_top, control.first))
                        continue
                selector = f"{expected_tag}:not([type='hidden'])" if expected_tag else "input,select,textarea"
                nested = label.locator(selector).first
                if nested.count() and nested.is_visible() and accepted(nested):
                    candidates.append((label_top, nested))
                    continue
                nearby = self._control_near_label(label, self.page, selector)
                if nearby is not None and accepted(nearby):
                    candidates.append((label_top, nearby))
            if candidates:
                return min(candidates, key=lambda item: item[0])[1]
        except Exception:
            pass
        return None

    @staticmethod
    def _field_value_matches(locator, expected):
        try:
            actual = locator.input_value().strip()
            input_type = (locator.get_attribute("type") or "").lower()
        except Exception:
            return False
        expected = str(expected).strip()
        if input_type == "date":
            date_match = re.fullmatch(r"(\d{1,2})[-/](\d{1,2})[-/](\d{4})", expected)
            if date_match:
                day, month, year = date_match.groups()
                expected = f"{year}-{int(month):02d}-{int(day):02d}"
        compact = lambda value: re.sub(r"[^a-z0-9]", "", value.lower())
        return bool(actual) and compact(actual) == compact(expected)

    def _detect_current_workflow_step(self):
        """Use the visible portal page so retry resumes where the user is."""
        page = self.page
        try:
            if not self._logged_in():
                return None
            body = self._norm(page.locator("body").inner_text(timeout=1500))
            if (self._find_visible_submit() is not None and self._find_visible_edit() is not None
                    and ("previous verification certificate information" in body or "stamping confirmation" in body)):
                return 3
            for table in page.locator("table:visible").all():
                headers = self._norm(" ".join(table.locator("tr").all_inner_texts()[:3]))
                if ("machine no" in headers or "machine number" in headers) and table.locator("input:visible,select:visible").count():
                    return 2
            if page.locator("#newgood:visible").count():
                return 1
            if re.search(r"items to be verified", body):
                # Page 2 repeats the Items to be verified heading, but has an
                # editable instrument table with machine-specific columns.
                for table in page.locator("table:visible").all():
                    headers = self._norm(" ".join(table.locator("tr").all_inner_texts()[:3]))
                    if (re.search(r"denomination|weight", headers)
                            and re.search(r"max", headers)
                            and re.search(r"machine", headers)
                            and table.locator("input:visible,select:visible").count()):
                        return 2
            if re.search(r"establishment details|previous information", body) and not re.search(
                    r"items to be verified.*machine no|previous verification certificate information", body):
                return 1
        except Exception:
            pass
        return None

    def _fill_form(self, payload):
        if not self._logged_in():
            raise RuntimeError("The portal session is no longer signed in. Log in again before continuing the machine details review.")
        current_step = self._detect_current_workflow_step()
        if current_step is not None:
            self.workflow_step = current_step
        elif self.workflow_step < 2:
            # Only navigate from a known dashboard. An unidentified page may
            # be a step the user reached manually, so leave it untouched.
            try:
                body = self._norm(self.page.locator("body").inner_text(timeout=1500))
            except Exception:
                body = ""
            dashboard = bool(re.search(
                r"the legal metrology act.{0,100}verification and stamping", body
            )) and not re.search(r"establishment details|previous information|items to be verified", body)
            if dashboard:
                self._navigate_to_stamping_form()
                current_step = self._detect_current_workflow_step()
                if current_step is not None:
                    self.workflow_step = current_step
                else:
                    raise RuntimeError("The stamping form did not open. The current page was left unchanged; open New Stamping manually and retry.")
            else:
                raise RuntimeError("Could not identify the current portal step. The page was left unchanged; retry after confirming the visible page, or use its Next button manually.")
        else:
            raise RuntimeError("Could not identify the current portal step. Leave the page open and retry so the assistant can resume without navigating away.")
        self.ready_for_submit = False
        if self.workflow_step <= 1:
            self.final_edit_retry_used = False
        report = {"filled": [], "skipped": [], "uploaded": [], "required_blank": [], "workflow_step": self.workflow_step}
        fields = payload["fields"]
        machines = payload.get("machine_rows") or [fields]
        groups = payload.get("item_groups") or self._group_items(machines)

        if self.workflow_step <= 1:
            self.messages.put(("progress", "Filling first-page sections in order: top to bottom, left to right"))
            self._fill_establishment_page(fields, machines, payload, report)
            # The first-page controls must be completed in sequence before the
            # app touches Items or Previous Information lower on that page.
            # Returning here also makes Fill now / retry resume at the first
            # missing field instead of racing ahead and replaying later rows.
            if report["required_blank"]:
                return report
        if self.workflow_step <= 1:
            self.messages.put(("progress", "First-page address and license fields are complete; preparing item and certificate rows"))
            # Items and Previous Information are lower sections on this same
            # first portal page. Fill them before validating or clicking Next.
            self._fill_items_and_previous_information(
                groups, machines, report["skipped"], report["filled"],
                fallback_application_number=fields.get("Application number", ""),
            )
            company_name = fields.get("Applicant / establishment name", "").strip()
            manufacturer_name_marker = "Manufacturer / Trader establishment name"
            if company_name and not self._ensure_manufacturer_company_name(company_name):
                report["filled"] = [item for item in report["filled"] if item != manufacturer_name_marker]
                report["skipped"].append(
                    f"{manufacturer_name_marker} changed while filling the first page and could not be restored to {company_name}"
                )
                missing_marker = "Portal field not filled: Manufacturer / Trader establishment name"
                if missing_marker not in report["required_blank"]:
                    report["required_blank"].append(missing_marker)
            filled_items = set(report["filled"])
            for index, _group in enumerate(groups, 1):
                if f"Item category {index}" not in filled_items:
                    report["required_blank"].append(f"Item category {index} was not selected")
                if not any(entry.startswith(f"Item quantity {index}:") for entry in filled_items):
                    report["required_blank"].append(f"Item quantity {index} total was not confirmed")
            for index, _machine in enumerate(machines, 1):
                if f"Previous Information Online {index}" not in filled_items:
                    report["required_blank"].append(f"Previous Information Online option for machine {index} was not selected")
                if f"Previous Information Application number {index}" not in filled_items:
                    report["required_blank"].append(f"Previous Information Application number for machine {index} was not filled")
                if f"Previous Information Certificate number {index}" not in filled_items:
                    report["required_blank"].append(f"Previous Information Certificate number for machine {index} was not filled")
                if f"Previous Information Certificate date {index}" not in filled_items:
                    report["required_blank"].append(f"Previous Information Certificate date for machine {index} was not populated by the portal")
            self._collect_visible_required(report)
            if report["required_blank"]:
                return report
            self._click_next("machine-details page")
            self.workflow_step = 2

        if self.workflow_step <= 2:
            self.messages.put(("progress", "Filling machine details on page 2"))
            self._fill_machine_detail_tables(groups, machines, report["skipped"], report["filled"])
            filled_machine_cvs = {
                item for item in report["filled"]
                if re.fullmatch(r"Machine \d+ Previous CV number", item)
            }
            for index, machine in enumerate(machines, 1):
                expected_cv = str(machine.get("Previous CV number", "")).strip()
                marker = f"Machine {index} Previous CV number"
                if len(machines) > 1 and expected_cv and marker not in filled_machine_cvs:
                    report["required_blank"].append(
                        f"Previous CV dropdown for machine {index} was not confirmed as {expected_cv}"
                    )
            self._collect_visible_required(report)
            if report["required_blank"]:
                return report
            self._click_next("final application page")
            self.workflow_step = 3
        if self.workflow_step >= 3:
            final_issue_start = len(report["required_blank"])
            self._verify_final_review_cvs(machines, report["required_blank"])
            machine_review_issues = report["required_blank"][final_issue_start:]
            if machine_review_issues and not self.final_edit_retry_used:
                edit = self._find_visible_edit()
                if edit is not None:
                    self.final_edit_retry_used = True
                    previous_signature = self._visible_form_signature()
                    edit.click(timeout=10000)
                    try:
                        self.page.wait_for_load_state("domcontentloaded", timeout=12000)
                    except Exception:
                        pass
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline:
                        self.page.wait_for_timeout(250)
                        if self._visible_form_signature() != previous_signature:
                            break
                    self.workflow_step = 2
                    retry_report = self._fill_form(payload)
                    retry_report["skipped"].insert(
                        0, "Final machine review failed once; the portal Edit control was used to refill page 2 and review again"
                    )
                    return retry_report
                report["skipped"].append(
                    "Automatic Edit control was not available on the final review page; the application was left unsubmitted for manual review"
                )
            self._verify_final_review_total(machines, report["required_blank"])
        self._collect_visible_required(report)
        report["final_submit_visible"] = self._find_visible_submit() is not None
        return report

    def _verify_final_review_total(self, machines, required_blank):
        expected_total = sum(_item_count(row.get("Quantity", "")) for row in machines)
        if not expected_total:
            return
        try:
            summaries = self.page.locator("table").all()
            for table in summaries:
                summary_text = self._norm(table.inner_text())
                if not re.search(r"total\s+(?:opted\s+)?quantity", summary_text):
                    continue
                header_cells = []
                for row in table.locator("tr").all():
                    cells = row.locator("th,td").all()
                    labels = [self._norm(cell.inner_text()) for cell in cells]
                    quantity_index = next((
                        index for index, label in enumerate(labels)
                        if re.fullmatch(r"total\s+(?:opted\s+)?quantity", label)
                    ), None)
                    if quantity_index is not None:
                        header_cells = labels
                        header_quantity_index = quantity_index
                        continue
                    if not header_cells or len(cells) <= header_quantity_index:
                        continue
                    actual = re.sub(r"\D", "", cells[header_quantity_index].inner_text())
                    if actual and int(actual) == expected_total:
                        return
                    if actual:
                        required_blank.append(
                            f"Final review total quantity is {actual}; expected {expected_total}"
                        )
                        return
            # Some portal versions render the final summary as divs instead
            # of a semantic table. Read a labeled total from the visible page
            # before marking the review incomplete.
            body_text = re.sub(r"\s+", " ", self.page.locator("body").inner_text())
            match = re.search(r"total\s+(?:opted\s+)?quantity\s*[:\-]?\s*(\d+)\b", body_text, re.I)
            if match:
                actual = int(match.group(1))
                if actual == expected_total:
                    return
                required_blank.append(
                    f"Final review total quantity is {actual}; expected {expected_total}"
                )
                return
            if len(machines) == 1:
                # A single-machine confirmation can omit the aggregate fee
                # table; the machine row itself is checked separately.
                return
            required_blank.append("Final review did not show the expected total quantity summary")
        except Exception as exc:
            required_blank.append(f"Final review total quantity could not be confirmed: {exc}")

    def _verify_final_review_cvs(self, machines, required_blank):
        """Confirm the final review table retains each machine's own CV reference."""
        try:
            rows = [
                re.sub(r"\s+", " ", row.inner_text()).strip()
                for row in self.page.locator("table tr").all()
            ]
        except Exception:
            rows = []
        normalized_rows = [self._norm(row) for row in rows]
        for index, machine in enumerate(machines, 1):
            cv_number = str(machine.get("Previous CV number", "")).strip()
            if not cv_number:
                continue
            machine_number = str(machine.get("Machine number", "")).strip()
            cv_norm = self._norm(cv_number)
            machine_norm = self._norm(machine_number)
            matched_row = next((row for row in normalized_rows
                                if cv_norm in row and (not machine_norm or machine_norm in row)), None)
            if matched_row is None and len(machines) == 1:
                # A single machine has one possible CV, so the portal may not
                # expose a selectable CV value in the machine row/review.
                # Locate its final row by machine number and still validate
                # the other captured machine details.
                matched_row = next((row for row in normalized_rows
                                    if machine_norm and machine_norm in row), None)
                if matched_row is None:
                    item_norm = self._norm(machine.get("Instrument description", ""))
                    matched_row = next((row for row in normalized_rows
                                        if item_norm and item_norm in row), None)
            if matched_row is None:
                if len(machines) == 1:
                    required_blank.append(f"Final review did not confirm the single machine row for {machine_number or machine.get('Instrument description', '(unavailable)')}")
                else:
                    required_blank.append(
                        f"Final review did not confirm CV {cv_number} for machine {index}"
                    )
                continue

            # Confirm the final table retained the machine values parsed from
            # its certificate, not just a CV number that could belong to a
            # different row. Quantity is aggregated by item type, so it is
            # checked on the item summary instead of per-machine rows.
            detail_fields = (
                ("Denomination", "Weights"), ("Class",),
                ("Maximum capacity",), ("Minimum capacity",),
                ("Verification interval (e/d)",), ("Instrument make",),
                ("Instrument model",), ("Machine number",),
            )
            for aliases in detail_fields:
                expected = next((str(machine.get(key, "")).strip() for key in aliases
                                 if str(machine.get(key, "")).strip()), "")
                if not expected:
                    continue
                expected_norm = re.sub(r"[^a-z0-9]+", "", expected.lower())
                if expected_norm and expected_norm not in re.sub(r"[^a-z0-9]+", "", matched_row):
                    required_blank.append(
                        f"Final review machine {index} did not confirm {aliases[0]}: {expected}"
                    )

    @staticmethod
    def _group_items(machines):
        groups = {}
        for row in machines:
            description = row.get("Instrument description", "")
            key = PortalWorker._norm(description)
            if not key:
                continue
            group = groups.setdefault(key, {"description": description, "quantity": 0, "machines": []})
            group["quantity"] += _item_count(row.get("Quantity", ""))
            group["machines"].append(row)
        return list(groups.values())

    def _save_address_option_snapshot(self, section_pattern, field, locator):
        """Persist authoritative dropdown options observed in the live portal."""
        field = str(field or "").removeprefix("Manufacturer ").strip()
        hierarchy = ["State", "District", "Taluk", "Town / Village", "Street"]
        if field not in hierarchy or locator is None:
            return
        try:
            options = []
            for option in locator.locator("option").all():
                label = re.sub(r"\s+", " ", option.inner_text()).strip()
                value = str(option.evaluate("el => el.value") or "")
                if (not label or not value or self._norm(label) in {"select", "please select"}
                        or option.evaluate("el => el.disabled")):
                    continue
                options.append({"label": label, "value": str(value)})
            if not options:
                return

            parents = {}
            for parent_field in hierarchy[:hierarchy.index(field)]:
                pattern = {
                    "State": r"^state$", "District": r"^district$",
                    "Taluk": r"^taluk$", "Town / Village": r"^town\s*/?\s*village$",
                }[parent_field]
                parent = self._field_in_section(section_pattern, pattern)
                if parent is None or not parent.count():
                    continue
                try:
                    selected = parent.locator("option:checked").first
                    parents[parent_field] = {
                        "label": re.sub(r"\s+", " ", selected.inner_text()).strip(),
                        "value": str(parent.input_value()),
                    }
                except Exception:
                    continue

            block = "manufacturer" if re.search(r"manufacturer", section_pattern, re.I) else "establishment"
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            key = json.dumps([block, field, parents], ensure_ascii=False, sort_keys=True)
            record = {
                "key": key,
                "section": block,
                "field": field,
                "parents": parents,
                "options": options,
                "captured_at": stamp,
                "source": "live Tamil Nadu Labour Department stamping form",
            }

            exe_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
            candidate_dirs = [exe_dir / "address_comparison", APP_DIR / "address_comparison", FALLBACK_APP_DIR / "address_comparison"]
            with ADDRESS_CACHE_LOCK:
                target = None
                for directory in candidate_dirs:
                    try:
                        directory.mkdir(parents=True, exist_ok=True)
                        target = directory / "location_options.json"
                        break
                    except Exception:
                        continue
                if target is None:
                    return
                data = {"schema_version": 1, "portal": STAMPING_URL, "snapshots": []}
                if target.exists():
                    try:
                        with target.open("r", encoding="utf-8") as stream:
                            loaded = json.load(stream)
                        if isinstance(loaded, dict):
                            data.update(loaded)
                    except Exception:
                        pass
                snapshots = data.setdefault("snapshots", [])
                existing_index = next((i for i, item in enumerate(snapshots) if item.get("key") == key), None)
                if existing_index is not None and snapshots[existing_index].get("options") == options:
                    return
                if existing_index is None:
                    snapshots.append(record)
                else:
                    snapshots[existing_index] = record
                data["updated_at"] = stamp
                temporary = target.with_suffix(".tmp")
                with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                    json.dump(data, stream, ensure_ascii=False, indent=2)
                temporary.replace(target)
        except Exception:
            # Address snapshots are a local aid; they must never interrupt a
            # portal application if the directory is unavailable.
            return

    def _fill_establishment_page(self, fields, machines, payload, report):
        page = self.page
        # The choice made in the app is authoritative. Previous certificates
        # can have been stamped at a different location from the new request;
        # their page labels describe history, not the current application.
        # Use the PDF label only as a fallback for callers that did not supply
        # a valid Office/Site choice at all.
        selected_place = str(fields.get("Stamping office/site", "")).strip()
        if selected_place.casefold() not in {"office", "site"}:
            page_stamping_modes = {
                normalize_text(row.get("Stamping office/site", ""))
                for row in machines
                if str(row.get("Stamping office/site", "")).strip()
            }
            if len(page_stamping_modes) == 1:
                mode = next(iter(page_stamping_modes))
                fields["Stamping office/site"] = "Site" if mode == "site" else "Office" if mode == "office" else ""
            elif len(page_stamping_modes) > 1:
                labels = ", ".join(sorted(mode.title() for mode in page_stamping_modes))
                report["skipped"].append(f"Stamping office/site (select Office or Site in the app; certificate pages conflict: {labels})")

        # Order first-page inputs, choices, and uploads by visible position.
        machine_descriptions = [str(row.get("Instrument description", "")).strip().lower() for row in machines]
        all_electronic = bool(machine_descriptions) and all("electronic" in description for description in machine_descriptions)
        new_goods_choice = "Electronic weighing machine" if all_electronic else "Others"
        new_goods = page.locator("#newgood")
        denomination_kg = [
            self._capacity_kg(str(row.get("Weights") or row.get("Denomination") or ""))
            for row in machines
        ]
        capacity_choice = "Above 3 tonnes" if any(weight >= 3000 for weight in denomination_kg) else "Below 3 tonnes"
        actions = []
        establishment_labels = {
            "Applicant / establishment name": r"name",
            "State": r"state",
            "District": r"district",
            "Taluk": r"taluk",
            "Town / Village": r"town\s*/?\s*village",
            "Street": r"street",
            "Door number": r"door\s+number",
            "Pincode": r"pincode|pin\s+code",
        }
        excluded = set(LOCAL_ONLY_FIELDS) | {"Applicant business name", "Applicant contact name", "Used by / trader contact", "Trader / establishment number"}
        deferred_actions = []

        def wait_for_location_option(locator, value, timeout=10):
            target = self._norm(value)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    for option in locator.locator("option").all():
                        label = self._norm(option.inner_text())
                        option_value = str(option.evaluate("el => el.value") or "")
                        explicitly_empty = option.get_attribute("value") == ""
                        if (label == target and option_value and not explicitly_empty
                                and not option.evaluate("el => el.disabled")):
                            return True
                except Exception:
                    pass
                page.wait_for_timeout(100)
            return False

        def location_option_signature(locator):
            """Return the enabled option list so cascading selects can be observed settling."""
            try:
                control = locator.first if hasattr(locator, "first") else locator
                return tuple(
                    (self._norm(option.inner_text()), str(option.evaluate("el => el.value") or ""))
                    for option in control.locator("option").all()
                    if not option.evaluate("el => el.disabled")
                )
            except Exception:
                return ()

        def wait_for_dependent_option(locator, value, previous_signature, require_refresh, timeout=20):
            """Wait for the dependent select to refresh, contain the target, and settle."""
            deadline = time.monotonic() + timeout
            last_signature = None
            stable_since = None
            while time.monotonic() < deadline:
                signature = location_option_signature(locator)
                has_target = any(
                    label == self._norm(value) and option_value
                    for label, option_value in signature
                )
                refreshed = not require_refresh or signature != previous_signature
                if has_target and refreshed:
                    if signature != last_signature:
                        last_signature = signature
                        stable_since = time.monotonic()
                    elif stable_since is not None and time.monotonic() - stable_since >= 0.35:
                        return True
                else:
                    stable_since = None
                    last_signature = signature
                page.wait_for_timeout(100)
            return False

        def wait_for_location_list(locator, timeout=10):
            """Wait until a dependent address select has populated and settled."""
            deadline = time.monotonic() + timeout
            last_signature = None
            stable_since = None
            while time.monotonic() < deadline:
                try:
                    if locator is None or not locator.count() or not locator.first.is_visible():
                        page.wait_for_timeout(100)
                        continue
                    control = locator.first
                    if not control.is_enabled():
                        page.wait_for_timeout(100)
                        continue
                    signature = tuple(
                        (self._norm(option.inner_text()), option.evaluate("el => el.value"))
                        for option in control.locator("option").all()
                        if not option.evaluate("el => el.disabled")
                    )
                    useful = [
                        label for label, value in signature
                        if label and value and label not in {"select", "please select"}
                    ]
                    if useful:
                        if signature != last_signature:
                            last_signature = signature
                            stable_since = time.monotonic()
                        elif stable_since is not None and time.monotonic() - stable_since >= 0.3:
                            return True
                except Exception:
                    pass
                page.wait_for_timeout(100)
            return False

        def selected_option_label(locator):
            try:
                return self._norm(locator.locator("option:checked").first.inner_text())
            except Exception:
                return ""

        def control_matches_value(locator, value):
            try:
                if locator.evaluate("el => el.tagName.toLowerCase()") == "select":
                    actual = selected_option_label(locator)
                    expected = self._norm(value)
                    return bool(actual) and (actual == expected or expected in actual or actual in expected)
                return self._field_value_matches(locator, value)
            except Exception:
                return False

        def establishment_control(field, section_pattern=r"Establishment\s+Details"):
            # Page-wide IDs are unsafe for duplicated address controls: the
            # portal's #trader-state-id is the manufacturer address State.
            # Always scope applicant address/name controls to Establishment
            # Details so this sequence cannot jump into the second address.
            if field in establishment_labels:
                expected_tag = "input" if field in {"Applicant / establishment name", "Door number", "Pincode"} else None
                control = self._field_in_section(section_pattern, establishment_labels[field], expected_tag)
                if control is not None:
                    return control
                # Some portal builds render unassociated labels as plain text.
                # Search the smaller address section by input metadata and its
                # nearby field group so Door Number does not silently stay blank.
                if field == "Door number":
                    scope = self._section_locator(section_pattern)
                    for candidate in scope.locator("input:visible").all():
                        try:
                            meta = " ".join(str(candidate.get_attribute(key) or "") for key in ("id", "name", "placeholder", "aria-label", "title"))
                            group_text = candidate.evaluate("el => { const g=el.closest('.form-group,.mb-3,.field,.col,td') || el.parentElement; return g ? (g.innerText || g.textContent || '') : ''; }")
                            if re.search(r"door\s*(?:number|no\b)", self._norm(meta + " " + group_text), re.I):
                                return candidate
                        except Exception:
                            continue
                return None
            return self._portal_field(field)

        for field, value in fields.items():
            if not value or field in excluded:
                continue
            # "Name" appears in several portal sections. Resolve the applicant
            # name only inside Establishment Details, never by a page-wide ID.
            locator = establishment_control(field)
            try:
                if locator is None or not locator.count() or not locator.first.is_visible():
                    # Some controls are inserted only after the preceding
                    # stamping choices are made. Re-resolve them after the
                    # preceding entries have loaded. Keep a placeholder in the
                    # ordered queue so later fields cannot leapfrog it.
                    deferred_actions.append((field, None, value))
                    continue
                # Dependent controls (licence number, address dropdowns and
                # invoice fields) can be disabled until earlier choices load.
                # Keep them in the top-to-bottom queue and recheck at fill time.
                top = locator.first.evaluate("el => el.getBoundingClientRect().top")
                actions.append((float(top), field, locator.first, value, "field"))
            except Exception as exc:
                report["skipped"].append(f"{field} (could not locate control: {exc})")

        if new_goods.count():
            try:
                actions.append((float(new_goods.first.evaluate("el => el.getBoundingClientRect().top")), "New goods / machine type choice", new_goods.first, new_goods_choice, "field"))
            except Exception as exc:
                report["skipped"].append(f"New goods / machine type choice: {exc}")
        else:
            report["skipped"].append("New goods / machine type choice (control not found)")

        checkbox = self._same_details_checkbox()
        if checkbox is not None:
            try:
                top = checkbox.evaluate("el => el.getBoundingClientRect().top")
                actions.append((float(top), "Same Details for Manufacturer / Trader / Establishment", checkbox, True, "checkbox"))
            except Exception as exc:
                report["skipped"].append(f"Same Details checkbox: {exc}")
        else:
            report["skipped"].append("Same Details for Manufacturer / Trader / Establishment (checkbox not found)")

        applicant_name = fields.get("Applicant / establishment name", "")
        manufacturer_scope = self._section_locator(r"Manufacturer\s*/\s*Trader\s*/\s*Establishment")
        manufacturer_establishment_name = self._field_in_section(
            r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"establishment\s*name"
        )
        if applicant_name and manufacturer_establishment_name is not None:
            control = manufacturer_establishment_name
            try:
                actions.append((float(control.evaluate("el => el.getBoundingClientRect().top")), "Manufacturer / Trader establishment name", control, applicant_name, "field"))
            except Exception as exc:
                report["skipped"].append(f"Manufacturer / Trader establishment name: {exc}")
        elif applicant_name:
            deferred_actions.append(("Manufacturer / Trader establishment name", None, applicant_name))

        # The certificate address belongs to both address blocks. Checking
        # "Same Details" copies values only partially on some portal versions,
        # so explicitly fill the second block too, after the checkbox action.
        manufacturer_address_fields = {
            "State": r"state",
            "District": r"district",
            "Taluk": r"taluk",
            "Town / Village": r"town\s*/?\s*village",
            "Street": r"street",
            "Door number": r"door\s+number",
            "Pincode": r"pincode|pin\s*code",
        }
        manufacturer_labels = {
            "State": "Manufacturer State",
            "District": "Manufacturer District",
            "Taluk": "Manufacturer Taluk",
            "Town / Village": "Manufacturer Town / Village",
            "Street": "Manufacturer Street",
            "Door number": "Manufacturer Door number",
            "Pincode": "Manufacturer Pincode",
        }
        for field, pattern in manufacturer_address_fields.items():
            value = fields.get(field, "")
            if not value:
                continue
            control = self._field_in_section(
                r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", pattern,
                "input" if field in {"Door number", "Pincode"} else None,
            )
            if control is None or not control.count() or not control.is_visible():
                deferred_actions.append((manufacturer_labels[field], None, value))
                continue
            try:
                actions.append((
                    float(control.evaluate("el => el.getBoundingClientRect().top")),
                    manufacturer_labels[field], control, value, "field",
                ))
            except Exception as exc:
                report["skipped"].append(f"{manufacturer_labels[field]}: {exc}")

        used_by = page.locator("#trader-name")
        if used_by.count() and used_by.first.is_visible():
            try:
                actions.append((float(used_by.first.evaluate("el => el.getBoundingClientRect().top")), "Repaired by / Used by", used_by.first, fields.get("Used by / trader contact", ""), "license-establishment"))
            except Exception as exc:
                report["skipped"].append(f"Repaired by / Used by: {exc}")
        else:
            deferred_actions.append(("Repaired by / Used by", None, ""))

        special_choices = [
            ("Stamping purpose: Re-verification", "#stamping-intend", "Re-verification"),
            ("Applicant licence type: Repairer", "#applicant-licence-id", "Repairer"),
        ]
        for label, selector, value in special_choices:
            locator = page.locator(selector)
            try:
                if locator.count() and locator.first.is_visible():
                    top = locator.first.evaluate("el => el.getBoundingClientRect().top")
                    actions.append((float(top), label, locator.first, value, "field"))
                else:
                    report["skipped"].append(f"{label} (control not found or not visible)")
            except Exception as exc:
                report["skipped"].append(f"{label} (could not locate control: {exc})")

        attachments = [
            ("Upload the purchase Invoice/Previous CV", "#pur-invo-file", payload.get("certificate")),
            ("Upload the Authorisation Letter from the user/owner", "#repairerletter", payload.get("authorization")),
            ("Upload copy of PAN card", "#pancard-file", payload.get("pan_image_data")),
        ]
        for label, selector, file_path in attachments:
            if not file_path:
                continue
            locator = page.locator(selector)
            try:
                if not locator.count():
                    report["skipped"].append(f"Upload: {label} (control not found)")
                    continue
                top = locator.first.evaluate("""el => {
                    const label = el.id ? document.querySelector('label[for="' + CSS.escape(el.id) + '"]') : null;
                    const container = el.closest('.form-group,.form-row,.row') || el.parentElement;
                    return (label || container || el).getBoundingClientRect().top;
                }""")
                actions.append((float(top), label, locator.first, file_path, "upload"))
            except Exception as exc:
                report["skipped"].append(f"Upload: {label}: {exc}")

        same_details_checked = False
        ordered_fields = [
            "New goods / machine type choice", "Weighing machine capacity range",
            "Stamping office/site",
            "Stamping purpose: Re-verification", "Applicant licence type: Repairer",
            "Repairer name", "Site Dormant / Other choice", "Repairer licence number",
            "Repairer licence date", "Licensed valid Up To", "Applicant business name",
            "Registered name", "Registered email", "Registered mobile",
            "Previous CV number", "Previous CV date",
            "Upload the purchase Invoice/Previous CV",
            "Upload the Authorisation Letter from the user/owner",
            "Applicant / establishment name", "State", "District", "Taluk",
            "Town / Village", "Street", "Door number", "Pincode",
            "Same Details for Manufacturer / Trader / Establishment",
            "Manufacturer / Trader establishment name", "Repaired by / Used by",
            "Manufacturer State", "Manufacturer District", "Manufacturer Taluk",
            "Manufacturer Town / Village", "Manufacturer Street",
            "Manufacturer Door number", "Manufacturer Pincode",
            "PAN number", "PAN date", "Upload copy of PAN card",
        ]
        order_index = {name: index for index, name in enumerate(ordered_fields)}
        # Fill in visual reading order: top row to bottom row, and left to
        # right within each row. The field list only breaks equal-position ties.
        for field, locator, value in deferred_actions:
            if locator is None:
                # Unknown/conditional controls go after already visible
                # controls; resolving one must not make it jump to the top of
                # the page ahead of fields with known screen coordinates.
                actions.append((float("inf"), field, None, value, "field"))
        deferred_actions = [(field, locator, value) for field, locator, value in deferred_actions if locator is not None]
        row_tops = []
        for row_top in sorted(float(action[0]) for action in actions):
            if not row_tops or row_top - row_tops[-1] > 14:
                row_tops.append(row_top)

        def action_order(action):
            top, name, locator = action[0], action[1], action[2]
            sequence = order_index.get(name, len(order_index))
            if locator is None:
                return (float(top), float("inf"), sequence)
            # Cluster nearby control tops into a visual row, then order that
            # row by x. This keeps label/control alignment differences from
            # moving a right-hand field ahead of the left cell in the same row.
            nearest_row = min(range(len(row_tops)), key=lambda idx: abs(row_tops[idx] - float(top))) if row_tops else 0
            row_key = nearest_row if row_tops and abs(row_tops[nearest_row] - float(top)) <= 14 else len(row_tops) + round(float(top) / 14)
            try:
                left = locator.evaluate("""el => {
                    let rect = el.getBoundingClientRect();
                    if (rect.width && rect.height) return rect.left;
                    const label = el.id ? document.querySelector('label[for="' + CSS.escape(el.id) + '"]') : null;
                    const host = label || el.closest('.form-group,.form-row,.row') || el.parentElement;
                    return host ? host.getBoundingClientRect().left : Number.POSITIVE_INFINITY;
                }""")
                if left is not None:
                    return (row_key, float(left), sequence)
            except Exception:
                pass
            return (row_key, float("inf"), sequence)

        def select_location(field, locator, value):
            if field.startswith("Manufacturer "):
                section_pattern = r"Manufacturer\s*/\s*Trader\s*/\s*Establishment"
                base_field = field.removeprefix("Manufacturer ")
            else:
                section_pattern = r"Establishment\s+Details"
                base_field = field
            self._save_address_option_snapshot(section_pattern, field, locator)
            if field in {"District", "Taluk", "Town / Village", "Street",
                         "Manufacturer District", "Manufacturer Taluk",
                         "Manufacturer Town / Village", "Manufacturer Street"} and \
                    selected_option_label(locator) != self._norm(value):
                # Each dependent select is populated by the preceding choice.
                # An enabled select can still contain only its placeholder, so
                # wait for the exact address value before attempting selection.
                if not wait_for_location_option(locator, value, timeout=20):
                    return False
            if field in {"Street", "Manufacturer Street"}:
                return self._select_exact_option(locator, value)
            if field in {"Town / Village", "Manufacturer Town / Village"}:
                # Check repeated town names against each town's Street options.
                if selected_option_label(locator) == self._norm(value):
                    street_locator = self._field_in_section(section_pattern, r"street")
                    street_target = self._norm(fields.get("Street", ""))
                    try:
                        existing_streets = [
                            self._norm(option.inner_text())
                            for option in street_locator.locator("option").all()
                            if option.get_attribute("value") and not option.evaluate("el => el.disabled")
                        ] if street_locator is not None else []
                    except Exception:
                        existing_streets = []
                    if street_target and any(label == street_target for label in existing_streets):
                        return True
            else:
                next_field = {
                    "State": r"district", "District": r"taluk",
                    "Taluk": r"town\s*/?\s*village", "Town / Village": r"street",
                }.get(base_field)
                dependent = self._field_in_section(section_pattern, next_field) if next_field else None
                expected_child = {
                    "State": fields.get("District", ""),
                    "District": fields.get("Taluk", ""),
                    "Taluk": fields.get("Town / Village", ""),
                    "Town / Village": fields.get("Street", ""),
                }.get(base_field, "")
                before_signature = location_option_signature(dependent) if dependent is not None else ()
                current_label = selected_option_label(locator)
                already_selected = current_label == self._norm(value)
                if already_selected:
                    if next_field and expected_child and dependent is not None:
                        if not wait_for_dependent_option(dependent, expected_child, before_signature, False, timeout=20):
                            available = self._option_label_preview(dependent)
                            dependent_name = {
                                r"district": "District", r"taluk": "Taluk",
                                r"town\s*/?\s*village": "Town / Village", r"street": "Street",
                            }.get(next_field, base_field)
                            report["skipped"].append(
                                f"{field} is already correct, but {dependent_name} has not loaded {expected_child}; available options: {available}"
                            )
                            return False
                    self._save_address_option_snapshot(section_pattern, field, locator)
                    return True
                if not self._select_best(locator, value):
                    return False
                if next_field:
                    # Enabled controls can still contain the old list while an
                    # asynchronous dependent dropdown refresh is in progress. Wait
                    # for a new settled option list after an actual parent change;
                    # a value already selected by the portal must not be reselected,
                    # since doing so can clear its dependent lists.
                    if (dependent is not None and expected_child
                            and not wait_for_dependent_option(
                                dependent, expected_child, before_signature,
                                require_refresh=not already_selected, timeout=20,
                            )):
                        available = self._option_label_preview(dependent)
                        dependent_name = {
                            r"district": "District", r"taluk": "Taluk",
                            r"town\s*/?\s*village": "Town / Village", r"street": "Street",
                        }.get(next_field, base_field)
                        report["skipped"].append(
                            f"{field} selected, but {dependent_name} did not load an enabled option for {expected_child}; available options: {available}"
                        )
                        return False
                    if dependent is not None:
                        next_name = {
                            r"district": "District", r"taluk": "Taluk",
                            r"town\s*/?\s*village": "Town / Village", r"street": "Street",
                        }.get(next_field)
                        if next_name:
                            self._save_address_option_snapshot(section_pattern, next_name, dependent)
                self._save_address_option_snapshot(section_pattern, field, locator)
                return True
            street_locator = self._field_in_section(section_pattern, r"street")
            resolved = self._select_town_matching_street(
                locator, street_locator, value, fields.get("Business address", ""), section_pattern
            )
            if resolved is None:
                return False
            fields["Street"] = resolved["street"]
            fields["Door number"] = resolved["door_number"]
            self._save_address_option_snapshot(section_pattern, field, locator)
            self._save_address_option_snapshot(section_pattern, "Street", street_locator)
            return True

        pending_actions = sorted(actions, key=action_order)
        progress_index = 0
        while pending_actions:
            _top, field, locator, value, action_type = pending_actions.pop(0)
            progress_index += 1
            if progress_index == 1 or progress_index % 4 == 0:
                self.messages.put(("progress", f"Filling first page, field {progress_index}: {field}"))
            if locator is None:
                try:
                    if field == "Manufacturer / Trader establishment name":
                        locator = self._field_in_section(r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"establishment\s*name")
                    elif field == "Repaired by / Used by":
                        locator = page.locator("#trader-name")
                        if not locator.count() or not locator.is_visible():
                            locator = self._field_in_section(r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"repaired\s*by\s*/?\s*used\s*by")
                    elif field.startswith("Manufacturer "):
                        original = field.removeprefix("Manufacturer ")
                        pattern = manufacturer_address_fields.get(original)
                        locator = self._field_in_section(
                            r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", pattern,
                            "input" if original in {"Door number", "Pincode"} else None,
                        ) if pattern else None
                    else:
                        locator = establishment_control(field) or self._portal_field(field)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and (locator is None or not locator.count() or not locator.first.is_visible()):
                        page.wait_for_timeout(100)
                        if field.startswith("Manufacturer "):
                            original = field.removeprefix("Manufacturer ")
                            pattern = manufacturer_address_fields.get(original)
                            locator = self._field_in_section(
                                r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", pattern,
                                "input" if original in {"Door number", "Pincode"} else None,
                            ) if pattern else None
                        else:
                            locator = establishment_control(field) or self._portal_field(field)
                    if locator is None or not locator.count() or not locator.first.is_visible():
                        report["skipped"].append(f"{field} (control still unavailable at its sequence position)")
                        break
                    locator = locator.first
                except Exception as exc:
                    report["skipped"].append(f"{field} (control lookup failed at its sequence position: {exc})")
                    break
            if field in {"Street", "Manufacturer Street"}:
                value = fields.get("Street", value)
            elif field in {"Door number", "Manufacturer Door number"}:
                value = fields.get("Door number", value)
            try:
                # Form entry uses fill/select/check APIs; Enter is never sent to the portal.
                if field == "New goods / machine type choice":
                    if self._select_best(locator, value):
                        report["filled"].append(field)
                        if new_goods_choice == "Electronic weighing machine":
                            capacity = page.locator("#tonnes")
                            try:
                                capacity.wait_for(state="visible", timeout=2500)
                            except Exception:
                                pass
                            if capacity.count() and capacity.first.is_visible():
                                top = float(capacity.first.evaluate("el => el.getBoundingClientRect().top"))
                                pending_actions.append((top, "Weighing machine capacity range", capacity.first, capacity_choice, "field"))
                                pending_actions.sort(key=action_order)
                    else:
                        report["skipped"].append(field)
                    continue
                if action_type == "checkbox":
                    if not locator.is_checked():
                        locator.check()
                    same_details_checked = locator.is_checked()
                    if same_details_checked:
                        report["filled"].append(field)
                    else:
                        report["skipped"].append(field)
                    continue
                if action_type not in {"upload", "checkbox"} and control_matches_value(locator, value):
                    # Retries are idempotent: retain confirmed entries instead
                    # of replaying their change handlers and disturbing later
                    # dependent fields.
                    if field not in report["filled"]:
                        report["filled"].append(field)
                    continue
                if field in {"Registered name", "Registered email", "Registered mobile",
                             "Repairer licence date", "Licensed valid Up To"}:
                    deadline = time.monotonic() + 20
                    # These controls are populated by the portal after the
                    # licence number is accepted. Saved profile values can be
                    # stale or belong to a different licence, so compare only
                    # against emptiness here; the portal's own read-only value
                    # is authoritative and must not block later form fields.
                    def portal_value_loaded():
                        try:
                            return bool(locator.input_value().strip())
                        except Exception:
                            return False

                    while time.monotonic() < deadline and not portal_value_loaded():
                        page.wait_for_timeout(150)
                    if portal_value_loaded():
                        report["filled"].append(field)
                        continue
                    report["skipped"].append(f"{field} (portal has not populated the expected value yet)")
                    break
                if action_type == "license-establishment":
                    value = str(value or fields.get("Used by / trader contact", "")).strip()
                    if not value:
                        license_establishment = page.locator("#establishmentname")
                        license_name = license_establishment.input_value().strip() if license_establishment.count() else ""
                        value = license_name
                    if not value:
                        report["skipped"].append("Repaired by / Used by (license establishment name unavailable)")
                        continue
                if action_type == "upload":
                    if isinstance(value, dict):
                        if len(value.get("buffer", b"")) > 1024 * 1024:
                            report["skipped"].append(f"{field} exceeds the portal's 1 MB file limit")
                        else:
                            locator.set_input_files(value); report["uploaded"].append(field)
                    elif Path(value).stat().st_size > 1024 * 1024:
                        report["skipped"].append(f"{field} exceeds the portal's 1 MB file limit")
                    else:
                        locator.set_input_files(value); report["uploaded"].append(field)
                    continue
                deferred_fields = {"Repairer name", "Repairer licence number", "Previous CV number",
                                   "Previous CV date", "District", "Taluk", "Town / Village", "Street",
                                   "Manufacturer District", "Manufacturer Taluk",
                                   "Manufacturer Town / Village", "Manufacturer Street"}
                if field in deferred_fields and not locator.is_editable():
                    # Wait at this field's position in the visible row order.
                    # Dependent controls often enable as soon as the preceding
                    # dropdown's change request completes.
                    deadline = time.monotonic() + 6
                    while time.monotonic() < deadline and not locator.is_editable():
                        page.wait_for_timeout(100)
                    if not locator.is_editable():
                        if control_matches_value(locator, value):
                            if field not in report["filled"]:
                                report["filled"].append(field)
                            continue
                        report["skipped"].append(f"{field} (still disabled at its sequence position)")
                        break
                if locator.evaluate("el => el.tagName.toLowerCase()") == "select":
                    selected = select_location(field, locator, value)
                    if not selected:
                        report["skipped"].append(f"{field} (no matching enabled option for {value})")
                        break
                    if field.startswith("Manufacturer ") and applicant_name:
                        self._ensure_manufacturer_company_name(applicant_name, stable_for=0.1)
                elif not self._fill_control(locator, value):
                    report["skipped"].append(f"{field} (could not select {value})")
                    break
                # The portal inserts the site fee selector only after Site has
                # been selected. Resolve it then, before moving further down.
                if field == "Stamping office/site" and str(value).lower() == "site":
                    dormant = None
                    deadline = time.monotonic() + 4
                    while time.monotonic() < deadline and dormant is None:
                        candidate = self._field_for(["Dormant / Other", "Dormant / other", "Dormant"])
                        if candidate is None:
                            # Some portal revisions render an unlabelled select
                            # for the site fee choice. Identify it from its actual
                            # option labels instead of guessing a selector ID.
                            for choice in page.locator("select:visible").all():
                                try:
                                    labels = [self._norm(option.inner_text()) for option in choice.locator("option").all()]
                                    if any("dormant" in label for label in labels) and any("other" in label for label in labels):
                                        candidate = choice
                                        break
                                except Exception:
                                    continue
                        if candidate is not None and candidate.count() and candidate.first.is_visible():
                            dormant = candidate.first
                            break
                        page.wait_for_timeout(100)
                    if dormant is not None and dormant.count() and dormant.first.is_visible():
                        dormant_top = float(dormant.first.evaluate("el => el.getBoundingClientRect().top"))
                        pending_actions.append((dormant_top, "Site Dormant / Other choice", dormant.first, fields.get("Dormant / Other", "Other"), "field"))
                        pending_actions.sort(key=action_order)
                    else:
                        report["skipped"].append("Site Dormant / Other choice (control not found after selecting Site)")
                if field in {"Repairer licence number", "Previous CV number", "Previous CV date"} and not self._field_value_matches(locator, value):
                    report["skipped"].append(f"{field} (portal value did not persist after filling)")
                    break
                report["filled"].append(field)
            except Exception as exc:
                report["skipped"].append(f"{field}: {exc}")
                # Do not let later fields overtake a field that failed at its
                # place in the requested top-to-bottom sequence. The user can
                # correct the first failure and retry from that point.
                break

        # Revisit fields that started disabled after their prerequisite choices
        # or uploads have now been applied. This keeps the main pass top-to-bottom
        # while still handling the portal's delayed Town/Street and licence fields.
        def deferred_action_order(action):
            name, locator, _value = action
            try:
                box = locator.bounding_box() if locator is not None else None
                if box:
                    return (round(box["y"] / 8), box["x"], order_index.get(name, len(order_index)))
            except Exception:
                pass
            return (float("inf"), float("inf"), order_index.get(name, len(order_index)))

        deferred_actions.sort(key=deferred_action_order)
        for field, locator, value in deferred_actions:
            if field in {"Street", "Manufacturer Street"}:
                value = fields.get("Street", value)
            elif field in {"Door number", "Manufacturer Door number"}:
                value = fields.get("Door number", value)
            try:
                if locator is None:
                    if field == "Manufacturer / Trader establishment name":
                        locator = self._field_in_section(
                            r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"establishment\s*name"
                        )
                    elif field == "Repaired by / Used by":
                        locator = page.locator("#trader-name")
                        if not locator.count() or not locator.is_visible():
                            locator = self._field_in_section(
                                r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"repaired\s*by\s*/?\s*used\s*by"
                            )
                        value = str(fields.get("Used by / trader contact", "")).strip()
                        if not value:
                            license_establishment = page.locator("#establishmentname")
                            license_name = license_establishment.input_value().strip() if license_establishment.count() else ""
                            value = license_name
                    elif field.startswith("Manufacturer "):
                        original_field = field.removeprefix("Manufacturer ")
                        pattern = manufacturer_address_fields.get(original_field)
                        locator = self._field_in_section(
                            r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", pattern,
                            "input" if original_field in {"Door number", "Pincode"} else None,
                        ) if pattern else None
                    else:
                        locator = establishment_control(field)
                if locator is None or not locator.count() or not locator.is_visible():
                    report["skipped"].append(f"{field} (control not found or not visible after prerequisite fields loaded)")
                    continue
                if field in {"Registered name", "Registered email", "Registered mobile",
                             "Repairer licence date", "Licensed valid Up To"}:
                    # These controls are read-only and populated asynchronously
                    # after the repairer licence number is accepted. Check them
                    # after prerequisite fields have been processed.
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if self._field_value_matches(locator, value):
                            if field not in report["filled"]:
                                report["filled"].append(field)
                            break
                        page.wait_for_timeout(150)
                    else:
                        try:
                            actual = locator.input_value().strip()
                        except Exception:
                            actual = ""
                        report["skipped"].append(
                            f"{field} (portal did not populate expected value; current value: {actual or 'blank'})"
                        )
                    continue
                if control_matches_value(locator, value):
                    if field not in report["filled"]:
                        report["filled"].append(field)
                    continue
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and not locator.is_editable():
                    page.wait_for_timeout(100)
                if not locator.is_editable():
                    report["skipped"].append(f"{field} (still disabled after prerequisite fields loaded)")
                    continue
                if control_matches_value(locator, value):
                    if field not in report["filled"]:
                        report["filled"].append(field)
                    continue
                if locator.evaluate("el => el.tagName.toLowerCase()") == "select":
                    selected = select_location(field, locator, value)
                    if not selected:
                        available = self._option_label_preview(locator)
                        report["skipped"].append(f"{field} (no matching enabled option for {value} after prerequisites loaded; available options: {available})")
                        continue
                    if field.startswith("Manufacturer ") and applicant_name:
                        self._ensure_manufacturer_company_name(applicant_name, stable_for=0.1)
                elif not self._fill_control(locator, value):
                    report["skipped"].append(f"{field} (could not select {value} after prerequisites loaded)")
                    continue
                if field in {"Repairer licence number", "Previous CV number", "Previous CV date"} and not self._field_value_matches(locator, value):
                    report["skipped"].append(f"{field} (portal value did not persist after deferred fill)")
                    continue
                report["filled"].append(field)
            except Exception as exc:
                report["skipped"].append(f"{field} (deferred fill failed: {exc})")

        # Final, idempotent address pass. The first pass can encounter an
        # AJAX-backed select before the prior dropdown's change callback has
        # populated it. Recheck in the portal's actual top-to-bottom sequence
        # and touch only values that are still missing or incorrect.
        address_sequence = [] if pending_actions else [
            ("Applicant / establishment name", r"Establishment\s+Details", r"name", "Applicant / establishment name"),
            ("State", r"Establishment\s+Details", r"state", "State"),
            ("District", r"Establishment\s+Details", r"district", "District"),
            ("Taluk", r"Establishment\s+Details", r"taluk", "Taluk"),
            ("Town / Village", r"Establishment\s+Details", r"town\s*/?\s*village", "Town / Village"),
            ("Street", r"Establishment\s+Details", r"street", "Street"),
            ("Door number", r"Establishment\s+Details", r"door\s+number", "Door number"),
            ("Pincode", r"Establishment\s+Details", r"pincode|pin\s*code", "Pincode"),
            ("Manufacturer / Trader establishment name", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"establishment\s*name", "Applicant / establishment name"),
            ("Manufacturer State", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"state", "State"),
            ("Manufacturer District", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"district", "District"),
            ("Manufacturer Taluk", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"taluk", "Taluk"),
            ("Manufacturer Town / Village", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"town\s*/?\s*village", "Town / Village"),
            ("Manufacturer Street", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"street", "Street"),
            ("Manufacturer Door number", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"door\s+number", "Door number"),
            ("Manufacturer Pincode", r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"pincode|pin\s*code", "Pincode"),
        ]
        for report_name, section_pattern, label_pattern, source_field in address_sequence:
            value = fields.get(source_field, "")
            if not value:
                continue
            try:
                expected_tag = "input" if source_field in {"Applicant / establishment name", "Door number", "Pincode"} else None
                locator = self._field_in_section(section_pattern, label_pattern, expected_tag)
                if locator is None or not locator.count() or not locator.is_visible():
                    report["skipped"].append(f"{report_name} (control not found during address recovery)")
                    continue
                if control_matches_value(locator, value):
                    if report_name not in report["filled"]:
                        report["filled"].append(report_name)
                    continue
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline and not locator.is_enabled():
                    page.wait_for_timeout(100)
                if not locator.is_enabled():
                    report["skipped"].append(f"{report_name} (still disabled during address recovery)")
                    continue
                if locator.evaluate("el => el.tagName.toLowerCase()") == "select":
                    if not select_location(report_name, locator, value):
                        # One last bounded wait lets the last AJAX response
                        # finish without replaying already-confirmed controls.
                        page.wait_for_timeout(700)
                        if not control_matches_value(locator, value) and not select_location(report_name, locator, value):
                            report["skipped"].append(f"{report_name} (could not select {value} after dependent options loaded)")
                            continue
                elif not self._fill_control(locator, value):
                    report["skipped"].append(f"{report_name} (could not fill {value})")
                    continue
                if control_matches_value(locator, value):
                    if report_name not in report["filled"]:
                        report["filled"].append(report_name)
                else:
                    report["skipped"].append(f"{report_name} (value did not persist: {value})")
            except Exception as exc:
                report["skipped"].append(f"{report_name} (address recovery failed: {exc})")

        # Dependent address selects can refresh the Manufacturer / Trader block
        # and overwrite its Establishment Name after the earlier top-to-bottom
        # entry. Reassert the company name after those lists finish loading.
        if applicant_name and not pending_actions:
            marker = "Manufacturer / Trader establishment name"
            report["filled"] = [entry for entry in report["filled"] if entry != marker]
            if self._ensure_manufacturer_company_name(applicant_name):
                report["filled"].append(marker)
            else:
                report["skipped"].append(
                    f"{marker} (could not persist the PDF company name: {applicant_name})"
                )

        if "Site Dormant / Other choice (control not found)" in report["skipped"]:
            pass
        elif fields.get("Stamping office/site", "").lower() == "site" and "Site Dormant / Other choice" not in report["filled"]:
            report["skipped"].append("Site Dormant / Other choice")

        critical_fields = (
            "Applicant / establishment name", "Stamping office/site", "Repairer licence number", "Repairer name",
            "Previous CV number", "Previous CV date", "State", "District", "Taluk", "Town / Village",
            "Street", "Door number", "Pincode", "PAN number", "PAN date",
        )
        filled_names = set(report["filled"])
        for field in ("New goods / machine type choice", "Stamping office/site", "Stamping purpose: Re-verification", "Applicant licence type: Repairer"):
            if field not in filled_names:
                report["required_blank"].append(f"Portal choice not selected: {field}")
        if new_goods_choice == "Electronic" and "Weighing machine capacity range" not in filled_names:
            report["required_blank"].append("Portal choice not selected: Weighing machine capacity range")
        if fields.get("Stamping office/site", "").lower() == "site" and "Site Dormant / Other choice" not in filled_names:
            report["required_blank"].append("Portal choice not selected: Site Dormant / Other")
        for field in critical_fields:
            if fields.get(field) and field not in filled_names:
                report["required_blank"].append(f"Portal field not filled: {field}")
        if applicant_name and "Manufacturer / Trader establishment name" not in filled_names:
            report["required_blank"].append("Portal field not filled: Manufacturer / Trader establishment name")
        if used_by.count() and "Repaired by / Used by" not in filled_names:
            report["required_blank"].append("Portal field not filled: Repaired by / Used by")
        if not same_details_checked:
            report["required_blank"].append("Portal checkbox not selected: Same Details for Manufacturer / Trader / Establishment")
        for label, _selector, file_path in attachments:
            if file_path and label not in report["uploaded"]:
                report["required_blank"].append(f"Portal upload not completed: {label}")

    def _ensure_manufacturer_company_name(self, company_name, stable_for=1.5):
        """Reassert the PDF company name after delayed portal address callbacks."""
        if not company_name:
            return False
        control = self._field_in_section(
            r"Manufacturer\s*/\s*Trader\s*/\s*Establishment", r"establishment\s*name"
        )
        if control is None or not control.count() or not control.is_visible() or control.is_disabled():
            return False
        stable_since = None
        # The portal's dependent-select callbacks can arrive after the select
        # appears ready and replace this input (sometimes with the State text).
        # Hold the final value stable long enough to catch and repair that race.
        deadline = time.monotonic() + max(6.0, stable_for + 4.0)
        attempts = 0
        while time.monotonic() < deadline:
            try:
                if self._field_value_matches(control, company_name):
                    if stable_since is None:
                        stable_since = time.monotonic()
                    elif time.monotonic() - stable_since >= stable_for:
                        return True
                else:
                    stable_since = None
                    if attempts >= 10:
                        return False
                    if control.is_editable():
                        if not self._fill_control(control, company_name):
                            return False
                    else:
                        # Some portal builds mark the same-details text input
                        # readonly even though its value is submitted. Set its
                        # native value and notify the portal's bindings.
                        control.evaluate("""(el, value) => {
                            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                            setter.call(el, value);
                            el.dispatchEvent(new Event('input', {bubbles: true}));
                            el.dispatchEvent(new Event('change', {bubbles: true}));
                            el.dispatchEvent(new Event('blur', {bubbles: true}));
                        }""", company_name)
                    attempts += 1
                self.page.wait_for_timeout(100)
            except Exception:
                return False
        return self._field_value_matches(control, company_name)

    @staticmethod
    def _capacity_kg(value: str) -> float:
        numbers = [float(n.replace(",", "")) for n in re.findall(r"\d[\d,]*(?:\.\d+)?", value or "")]
        if not numbers:
            return 0
        number = max(numbers)
        low = (value or "").lower()
        if re.search(r"\b(tonnes?|tons?|t)\b", low):
            return number * 1000
        if re.search(r"\bgrams?|\bg\b", low):
            return number / 1000
        return number

    def _same_details_checkbox(self):
        try:
            checkbox = self.page.get_by_label(re.compile(r"Same Details for Manufacturer\s*/\s*Trader\s*/\s*Establishment", re.I)).first
            if checkbox.count():
                return checkbox
        except Exception:
            pass
        # Playwright may return zero matches without raising when the label wraps
        # across lines or its whitespace differs from the accessible name.
        for label in self.page.locator("label").all():
            try:
                text = re.sub(r"\s+", " ", label.inner_text()).strip()
                if re.search(r"Same Details for Manufacturer\s*/\s*Trader\s*/\s*Establishment", text, re.I):
                    control = label.locator("input[type=checkbox]").first
                    if control.count(): return control
                    target_id = label.get_attribute("for")
                    if target_id:
                        control = self.page.locator(f"#{target_id}")
                        if control.count() and control.get_attribute("type") == "checkbox":
                            return control.first
                    nearby = self._control_near_label(label, selector="input[type=checkbox]")
                    if nearby is not None:
                        return nearby
            except Exception:
                continue
        try:
            text_match = self.page.get_by_text(re.compile(r"Same Details for Manufacturer\s*/\s*Trader\s*/\s*Establishment", re.I)).first
            if text_match.count():
                for depth in range(1, 5):
                    scope = text_match.locator("xpath=" + "/".join([".."] * depth))
                    checkbox = scope.locator('input[type="checkbox"]:visible').first
                    if checkbox.count():
                        return checkbox
        except Exception:
            pass
        return None

    def _check_same_details(self):
        checkbox = self._same_details_checkbox()
        if checkbox is None:
            return False
        if not checkbox.is_checked():
            checkbox.check()
        return checkbox.is_checked()

    def _click_next(self, expected_page):
        page = self.page
        next_button = None
        visible_labels = []
        for candidate in page.locator("button:visible,input[type='button']:visible,input[type='submit']:visible,[role='button']:visible,a:visible").all():
            try:
                label = " ".join(filter(None, [candidate.inner_text(timeout=500), candidate.get_attribute("value"), candidate.get_attribute("aria-label")])).strip()
                if label:
                    visible_labels.append(label)
                if re.search(r"\bnext\b", label, re.I) and candidate.is_enabled():
                    next_button = candidate
            except Exception:
                continue
        if next_button is None:
            raise RuntimeError(f"Could not find the Next control for the {expected_page}. Review the current portal page.")
        previous_url = page.url
        previous_signature = self._visible_form_signature()
        # The portal's Next handler can finish the click and start a slow
        # navigation that exceeds Playwright's click navigation wait. Do not
        # make the click itself wait for that navigation; the URL/form-step
        # check below is the authoritative confirmation that the page moved.
        next_button.click(timeout=10000, no_wait_after=True)
        try:
            page.wait_for_load_state("domcontentloaded", timeout=12000)
        except Exception:
            pass
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            page.wait_for_timeout(100)
            if page.url != previous_url or self._visible_form_signature() != previous_signature:
                return
        # A click can be accepted by the browser while portal validation keeps
        # the user on the same step. Never advance the automation state then.
        self._collect_visible_required({"required_blank": [], "skipped": []})
        raise RuntimeError(
            f"The portal did not advance to the {expected_page}. Its current page still appears incomplete; "
            "review the highlighted required fields in the app browser."
        )

    def _visible_form_signature(self):
        """Return a compact signature of the currently visible form step."""
        try:
            return tuple(self.page.locator(
                "input:visible,select:visible,textarea:visible,button:visible,[role='button']:visible,h1:visible,h2:visible,h3:visible,h4:visible"
            ).evaluate_all("els => els.map(e => [e.tagName, e.id || e.name || '', e.type || '', (e.innerText || e.value || e.getAttribute('aria-label') || '').trim().slice(0,80)])"))
        except Exception:
            return ()

    def _collect_visible_required(self, report):
        try:
            blank = self.page.locator("input:visible,select:visible,textarea:visible").evaluate_all(r"""els => els.filter(e => {
                if (e.disabled || e.readOnly) return false;
                const label = [...(e.labels || [])].map(x => x.innerText || '').join(' ');
                const group = e.closest('.form-group,.form-row,.mb-3,.field,td') || e.parentElement;
                const nearby = group ? [...group.querySelectorAll('label,.control-label,[class*=label]')].map(x => x.innerText || '').join(' ') : '';
                const required = e.required || e.getAttribute('aria-required') === 'true' || /\*/.test(label + ' ' + nearby) || e.classList.contains('is-invalid');
                if (!required) return false;
                if (e.type === 'checkbox' || e.type === 'radio') return !e.checked;
                if (e.tagName === 'SELECT') {
                    const selected = e.options[e.selectedIndex];
                    return !selected || !e.value || /^(select|choose|--|please select)/i.test((selected.textContent || '').trim());
                }
                return !String(e.value || '').trim();
            }).map(e => e.id || e.name || e.type || e.tagName)""")
            report["required_blank"] = list(dict.fromkeys(report["required_blank"] + blank))
            report["skipped"].extend(f"Required field left blank: {name}" for name in blank if f"Required field left blank: {name}" not in report["skipped"])
        except Exception:
            pass

    def _section_locator(self, heading_text):
        page = self.page
        headings = self._section_headings(heading_text)
        heading = headings[0] if headings else page.get_by_text(re.compile(heading_text, re.I)).first
        try:
            if heading.count():
                for depth in range(1, 8):
                    scope = heading.locator("xpath=" + "/".join([".."] * depth))
                    if scope.locator("input,select,textarea,button,a,[role='button']").count():
                        return scope
        except Exception:
            pass
        return page.locator("body")

    def _section_headings(self, heading_pattern):
        """Prefer exact section titles over labels that merely contain the title."""
        matches = []
        try:
            for candidate in self.page.get_by_text(re.compile(heading_pattern, re.I)).all():
                try:
                    if candidate.is_visible():
                        matches.append(candidate)
                except Exception:
                    continue
        except Exception:
            return []
        exact = []
        for candidate in matches:
            try:
                text = re.sub(r"\s+", " ", candidate.inner_text()).strip()
                if re.fullmatch(heading_pattern, text, re.I):
                    exact.append(candidate)
            except Exception:
                continue
        return exact or matches

    def _add_button(self, scope):
        try:
            for control in scope.locator("button,a,[role='button'],input[type='button']").all():
                if not control.is_visible():
                    continue
                label = " ".join(filter(None, [control.inner_text(timeout=500), control.get_attribute("value"), control.get_attribute("aria-label"), control.get_attribute("title")]))
                if re.fullmatch(r"\s*(?:\+\s*)?(?:add|add more|add another|add new|add new item|add more item|add row)\s*", label, re.I):
                    return control
        except Exception:
            pass
        return None

    def _ensure_repeater_count(self, count_fn, desired, scope, description, skipped):
        current = count_fn()
        while current < desired:
            add = self._add_button(scope)
            if add is None:
                break
            try:
                # Add is an AJAX repeater action. Do not let Playwright wait
                # for a document navigation that the portal never performs.
                add.click(no_wait_after=True)
                deadline = time.monotonic() + 5
                updated = current
                while time.monotonic() < deadline and updated <= current:
                    self.page.wait_for_timeout(75)
                    updated = count_fn()
            except Exception:
                break
            if updated <= current:
                break
            current = updated
        if current < desired:
            skipped.append(f"{description}: portal has {current} row(s), needs {desired}; add missing row(s) manually")

    def _repeater_section_scope(self, heading_pattern, control_selector):
        """Find the smallest section ancestor containing both rows and its Add button."""
        heading = self.page.get_by_text(re.compile(heading_pattern, re.I)).first
        try:
            if heading.count():
                for depth in range(1, 10):
                    scope = heading.locator("xpath=" + "/".join([".."] * depth))
                    if scope.locator(control_selector).count() and self._add_button(scope) is not None:
                        return scope
        except Exception:
            pass
        return self._section_locator(heading_pattern)

    def _controls_matching(self, scope, pattern):
        matches = []
        try:
            # Prefer the browser's accessible label association where present.
            try:
                for control in scope.get_by_label(re.compile(pattern, re.I)).all():
                    if control.is_visible() and control not in matches:
                        matches.append(control)
            except Exception:
                pass
            for control in scope.locator("input,select,textarea").all():
                if not control.is_visible():
                    continue
                metadata = control.evaluate(r"""el => {
                    const own = [...(el.labels || [])].map(label => label.innerText || '');
                    if (own.length) return own.join(' ');
                    const visibleLabel = label => label.getClientRects().length &&
                        (label.innerText || label.textContent || '').trim();
                    // Match labels by visual proximity. Repeater rows often put
                    // several labels and controls under one Bootstrap row, so
                    // ancestor-wide label text makes every input look like
                    // Application Number, Certificate Number, and Date at once.
                    const box = el.getBoundingClientRect();
                    const candidates = [...el.ownerDocument.querySelectorAll('label,.control-label,[class*=label]')]
                        .filter(visibleLabel).map(label => {
                            const r = label.getBoundingClientRect();
                            const verticalGap = box.top - r.bottom;
                            const horizontalGap = Math.max(0, r.left - box.right, box.left - r.right);
                            return {label, score: Math.abs(verticalGap) + horizontalGap * 2,
                                plausible: verticalGap >= -8 && verticalGap <= 90 && horizontalGap <= 120};
                        }).filter(item => item.plausible).sort((a, b) => a.score - b.score);
                    if (candidates.length) return candidates[0].label.innerText || candidates[0].label.textContent || '';
                    // Last resort: a label explicitly targeting this control.
                    const id = el.id;
                    if (id) {
                        const label = el.ownerDocument.querySelector(`label[for="${CSS.escape(id)}"]`);
                        if (label) return label.innerText || label.textContent || '';
                    }
                    return '';
                }""")
                metadata = " ".join(filter(None, [metadata, control.get_attribute("id"), control.get_attribute("name"), control.get_attribute("placeholder"), control.get_attribute("aria-label"), control.get_attribute("title")]))
                metadata = re.sub(r"[_-]+", " ", metadata)
                metadata = re.sub(r"\s+", " ", metadata).strip()
                if re.search(pattern, metadata, re.I) and control not in matches:
                    matches.append(control)
        except Exception:
            pass
        return matches

    @staticmethod
    def _option_label_preview(locator, limit=24):
        try:
            labels = [
                re.sub(r"\s+", " ", option.inner_text()).strip()
                for option in locator.locator("option").all()
            ]
            labels = [label for label in labels if label and label.lower() not in {"select", "please select"}]
            return ", ".join(labels[:limit]) or "none"
        except Exception:
            return "unavailable"

    def _fill_control(self, control, value):
        tag, kind = control.evaluate("el => [el.tagName.toLowerCase(), (el.getAttribute('type') || '').toLowerCase()]")
        if tag == "select":
            return self._select_best(control, value)
        if kind in {"radio", "checkbox"}:
            name = control.get_attribute("name")
            candidates = self.page.locator(f"input[name='{name}']") if name else control.locator("xpath=..").locator("input[type=radio],input[type=checkbox]")
            target = self._norm(value)
            for candidate in candidates.all():
                label_text = ""
                try:
                    label_text = candidate.evaluate("el => [...(el.labels || [])].map(x => x.innerText).join(' ')")
                    option = " ".join(filter(None, [label_text, candidate.get_attribute("value"), candidate.get_attribute("aria-label")]))
                    if target in self._norm(option) or self._norm(option) in target:
                        candidate.check()
                        return True
                except Exception:
                    continue
            return False
        if kind == "date":
            date_match = re.fullmatch(r"(\d{1,2})[-/](\d{1,2})[-/](\d{4})", str(value).strip())
            if date_match:
                day, month, year = date_match.groups()
                value = f"{year}-{int(month):02d}-{int(day):02d}"
        control.fill(value)
        # Some portal fields trigger dependent values (notably certificate
        # dates) on change/blur rather than on the programmatic fill alone.
        control.dispatch_event("input")
        control.dispatch_event("change")
        control.evaluate("el => el.blur()")
        return True

    def _fill_items_and_previous_information(self, groups, machines, skipped, filled, fallback_application_number=""):
        page = self.page
        category_selector = "select[id*='stampinglabourmeasures'][id$='stamping-type-id']:visible"
        item_scope = self._repeater_section_scope(r"Items\s+to\s+be\s+verified", category_selector)
        categories = page.locator(category_selector)
        self._ensure_repeater_count(lambda: categories.count(), len(groups), item_scope, "Item categories", skipped)
        category_controls = categories.all()
        for index, group in enumerate(groups):
            if index >= len(category_controls):
                break
            try:
                if self._fill_control(category_controls[index], group["description"]):
                    filled.append(f"Item category {index + 1}")
                    # Category changes can reset quantity asynchronously; wait
                    # for that update before applying the sum of its PDF rows.
                    if _is_weights_item(group["description"]):
                        weight = next((machine.get("Weights", "") or machine.get("Denomination", "") for machine in group.get("machines", []) if machine.get("Weights") or machine.get("Denomination")), "")
                        if weight:
                            try:
                                row_scope = category_controls[index].locator("xpath=ancestor::tr[1]")
                                weight_controls = self._controls_matching(row_scope, r"weight|denomination") if row_scope.count() else []
                                weight_control = next((control for control in weight_controls if control != category_controls[index] and control.is_visible()), None)
                                if weight_control and self._fill_control(weight_control, weight):
                                    filled.append(f"Item weights {index + 1}: {weight}")
                            except Exception:
                                pass
                else:
                    skipped.append(f"Item category {index + 1}: {group['description']}")
                element_id = category_controls[index].get_attribute("id") or ""
                row_match = re.search(r"stampinglabourmeasures-(\d+)-", element_id)
                row_index = int(row_match.group(1)) if row_match else index
                quantity = page.locator(f"#stampinglabourmeasures-{row_index}-quantity")
                if quantity.count():
                    total_quantity = sum(_item_count(machine.get("Quantity", "")) for machine in group.get("machines", []))
                    quantity.fill(str(total_quantity))
                    if quantity.input_value().strip() != str(total_quantity):
                        quantity.fill(str(total_quantity))
                    if quantity.input_value().strip() == str(total_quantity):
                        filled.append(f"Item quantity {index + 1}: {total_quantity}")
                    else:
                        skipped.append(f"Item quantity {index + 1}: expected total {total_quantity}, portal shows {quantity.input_value().strip()}")
                else:
                    skipped.append(f"Item quantity {index + 1}")
            except Exception:
                skipped.append(f"Item category/quantity {index + 1}")

        previous_scope = self._repeater_section_scope(r"Previous\s+Information", "select:visible")
        app_pattern = r"(?:application|app)\s*(?:number|no\b|num\b)"
        cv_pattern = r"(?:certificate|previous\s*cv|cv)\s*(?:number|no\b)"
        model_pattern = r"\bmodel\s*(?:name)?\b"

        def row_inputs(state_control):
            """Locate identifier inputs in this Online row, never in another row."""
            for depth in range(1, 10):
                scope = state_control.locator("xpath=" + "/".join([".."] * depth))
                scoped_selects = scope.locator("select:visible").all()
                if len(scoped_selects) != 1:
                    if len(scoped_selects) > 1:
                        break
                    continue
                inputs = scope.locator("input:visible:not([type='hidden']):not([type='button']):not([type='submit']):not([type='file']),textarea:visible").all()
                if len(inputs) != 3:
                    continue
                # In the portal's Previous Information row DOM order is Date,
                # Application Number, Certificate Number. The row-local
                # structure is stable; avoid a document-wide accessible-label
                # scan for every machine (quadratic on long certificates).
                return inputs[1], inputs[2], inputs[0]
            return None

        def wait_for_row_inputs(state_control):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                result = row_inputs(state_control)
                if result is not None:
                    return result
                page.wait_for_timeout(50)
            return None

        select_snapshot_cache = {"at": 0.0, "rows": []}

        def select_snapshot():
            now = time.monotonic()
            if now - select_snapshot_cache["at"] < 0.2:
                return select_snapshot_cache["rows"]
            locator = previous_scope.locator("select:visible")
            try:
                rows = locator.evaluate_all(r"""selects => {
                    const text = el => (el?.innerText || el?.textContent || '').replace(/\s+/g,' ').trim();
                    return selects.map((select, index) => {
                      let labelText = [...(select.labels || [])].map(text).filter(Boolean).join(' ');
                      if (!labelText) labelText = text(select.closest('label'));
                      if (!labelText) {
                        const host = select.closest('.form-group,.form-row,.field,.col,.row') || select.parentElement;
                        const label = host?.querySelector('label,.control-label,[class*=label]');
                        labelText = text(label);
                      }
                      const options = [...select.options].map(option => ({
                        label: text(option), value: option.value, disabled: option.disabled
                      }));
                      return { index, label: labelText, options };
                    });
                }""")
                select_snapshot_cache["rows"] = [(locator.nth(row["index"]), row) for row in rows]
                select_snapshot_cache["at"] = now
            except Exception:
                select_snapshot_cache["rows"] = []
                select_snapshot_cache["at"] = now
            return select_snapshot_cache["rows"]

        def online_info(row):
            meaningful = [self._norm(option["label"]) for option in row["options"]
                          if self._norm(option["label"]) not in {"", "select", "please select"}]
            return bool(meaningful) and all(
                label in {"online", "other state", "online/other state", "online other state"}
                or label.startswith("online/other state") for label in meaningful
            )

        def online_controls():
            return [control for control, row in select_snapshot() if online_info(row)]

        def is_online_state_control(control):
            """Identify the portal's Online/Other State select even if it was
            briefly mistaken for a Model Name select while rows are rerendering."""
            try:
                labels = control.locator("option").evaluate_all("options => options.map(option => (option.innerText || option.textContent || '').replace(/\\s+/g,' ').trim())")
                labels = [self._norm(label) for label in labels]
                meaningful = [label for label in labels if label not in {"", "select", "please select"}]
                return bool(meaningful) and all(
                    label in {"online", "other state", "online/other state", "online other state"}
                    or label.startswith("online/other state")
                    for label in meaningful
                )
            except Exception:
                return False

        def model_controls():
            # Previous Information contains one select per row. Any select
            # whose options are not the Online/Other State choices is still a
            # Model Name row, even while the portal is loading its options.
            return [control for control, row in select_snapshot() if not online_info(row)]

        def model_option_matches(option_label, item_label):
            """Allow portal dash/spacing variants while preserving item type/class."""
            option_norm = self._norm(option_label)
            item_norm = self._norm(item_label)
            if not option_norm or not item_norm:
                return False
            if option_norm == item_norm or option_norm in item_norm or item_norm in option_norm:
                return True
            # Electronic and mechanical instruments must never cross-match.
            for kind in ("electronic", "mechanical"):
                if kind in item_norm and kind not in option_norm:
                    return False
            item_classes = re.findall(r"\b(?:iii|iiii|iv|ii)\b", item_norm)
            option_classes = re.findall(r"\b(?:iii|iiii|iv|ii)\b", option_norm)
            if item_classes and not set(item_classes).issubset(set(option_classes)):
                return False
            item_tokens = set(item_norm.split())
            option_tokens = set(option_norm.split())
            overlap = len(item_tokens & option_tokens) / max(1, len(item_tokens))
            return overlap >= 0.72 or SequenceMatcher(None, item_norm, option_norm).ratio() >= 0.72

        def model_option_values(control):
            try:
                return control.locator("option").evaluate_all(r"""options => options.map(option => ({
                    label: (option.innerText || option.textContent || '').replace(/\s+/g,' ').trim(),
                    value: option.value || '', disabled: !!option.disabled
                })).filter(option => option.label && option.value && !option.disabled &&
                    !/^(select|please select)$/i.test(option.label))
                  .map(option => [option.label, option.value])""")
            except Exception:
                return []

        model_choice_cache = {}

        def choose_model(control, item_label):
            # The portal fills the model list asynchronously after Add. Keep
            # checking for the requested item instead of failing on the first,
            # often still-empty, snapshot of the options.
            cache_key = self._norm(item_label)
            cached_value = model_choice_cache.get(cache_key)
            if cached_value:
                try:
                    if self._choose_select_option(control, cached_value):
                        selected_label = re.sub(r"\s+", " ", control.locator("option:checked").first.inner_text()).strip()
                        if model_option_matches(selected_label, item_label):
                            return True
                except Exception:
                    pass
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline:
                choices = []
                for option_label, value in model_option_values(control):
                    if model_option_matches(option_label, item_label):
                        score = SequenceMatcher(None, self._norm(option_label), self._norm(item_label)).ratio()
                        if self._norm(option_label) in self._norm(item_label) or self._norm(item_label) in self._norm(option_label):
                            score = 1.0
                        choices.append((score, value))
                if choices:
                    _score, value = max(choices, key=lambda item: item[0])
                    if self._choose_select_option(control, value):
                        model_choice_cache[cache_key] = value
                        return True
                page.wait_for_timeout(100)
            return False

        def model_options_summary(control):
            labels = [label for label, _value in model_option_values(control)]
            return ", ".join(labels[:12]) if labels else "none loaded"

        def previous_add_button():
            """Choose the Add beside Previous Information, not another repeater's Add."""
            candidates = []
            states_now = online_controls()
            anchor = float(states_now[-1].evaluate("el => el.getBoundingClientRect().top")) if states_now else None
            locator = previous_scope.locator("button:visible,a:visible,[role='button']:visible,input[type='button']:visible")
            try:
                descriptions = locator.evaluate_all(r"""els => els.map(el => ({
                    label: (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '').replace(/\s+/g,' ').trim(),
                    top: el.getBoundingClientRect().top
                }))""")
            except Exception:
                descriptions = []
            for index, item in enumerate(descriptions):
                if re.fullmatch(r"\s*(?:\+\s*)?(?:add|add more|add another|add new|add row)\s*", item.get("label", ""), re.I):
                    top = float(item.get("top", 0))
                    candidates.append((abs(top - anchor) if anchor is not None else 0, index))
            return locator.nth(min(candidates, key=lambda item: item[0])[1]) if candidates else None

        def previous_row_count():
            # One select is rendered for each Previous Information row, even
            # while its Model Name options are still loading. Counting all
            # section selects avoids missing a slow-loading placeholder row.
            try:
                count = previous_scope.locator("select:visible").count()
                if count:
                    return count
            except Exception:
                pass
            return max(1, 1 + len(delete_buttons()))

        def delete_buttons():
            buttons = []
            try:
                for control in previous_scope.locator("button,a,[role='button'],input[type='button']").all():
                    if not control.is_visible():
                        continue
                    label = " ".join(filter(None, [
                        control.inner_text(timeout=500), control.get_attribute("value"),
                        control.get_attribute("aria-label"), control.get_attribute("title"),
                    ]))
                    if re.fullmatch(r"\s*(?:delete|remove)\s*", label, re.I):
                        buttons.append(control)
            except Exception:
                pass
            return buttons

        def select_online_when_ready(control, timeout=4):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    if control.is_visible() and control.is_enabled():
                        selected_label = self._norm(control.locator("option:checked").first.inner_text())
                        if selected_label == "online" or selected_label.startswith("online other state"):
                            return True
                        if self._select_best(control, "Online"):
                            return True
                except Exception:
                    pass
                page.wait_for_timeout(50)
            return False

        def wait_for_count(getter, required, timeout=8):
            deadline = time.monotonic() + timeout
            current = getter()
            while len(current) < required and time.monotonic() < deadline:
                page.wait_for_timeout(50)
                current = getter()
            return current

        states = wait_for_count(online_controls, 1)
        if not states:
            skipped.append("Previous Information: Online/Other State control not found")
            return
        # The portal may ignore Add while the first row is still set to its
        # placeholder. Confirm Online before measuring rows or clicking Add.
        if not select_online_when_ready(states[0]):
            skipped.append("Previous Information: first Online/Other State option could not be selected; Add was not attempted")
            return

        desired_rows = len(machines)
        # Repeated attempts can leave surplus rows in the open portal form.
        # Trim those first, then click Add exactly once per missing row.
        current_rows = previous_row_count()
        while current_rows > desired_rows:
            removes = delete_buttons()
            if not removes:
                skipped.append(f"Previous Information: portal has {current_rows} rows; could not remove extras to reach {desired_rows}")
                break
            try:
                removes[-1].click()
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    updated = previous_row_count()
                    if updated < current_rows:
                        current_rows = updated
                        break
                    page.wait_for_timeout(50)
                else:
                    skipped.append("Previous Information: Delete did not remove the extra row")
                    break
            except Exception as exc:
                skipped.append(f"Previous Information: could not remove extra row: {exc}")
                break
        shared_application_number = next((
            str(row.get("Application number", "")).strip()
            for row in machines if str(row.get("Application number", "")).strip()
        ), "") or str(fallback_application_number or "").strip()

        # First create every Previous Information row. Only if the portal
        # refuses another Add until a Model Name is selected, select one model
        # to unlock the next Add and continue. This avoids interleaving input
        # entry with slow row creation on large certificates.
        while current_rows < desired_rows:
            add = previous_add_button()
            if add is None:
                skipped.append(f"Previous Information: Add control not found; portal has {current_rows} rows, needs {desired_rows}")
                return
            try:
                before_count = previous_row_count()
                # The portal updates this repeater asynchronously in the same
                # document; waiting for a navigation here needlessly stalls
                # every row on large certificates.
                add.click(no_wait_after=True)
                select_snapshot_cache["at"] = 0
                add_deadline = time.monotonic() + 5
                updated_count = before_count
                while time.monotonic() < add_deadline:
                    updated_count = previous_row_count()
                    if updated_count > before_count:
                        break
                    page.wait_for_timeout(50)
                if updated_count > before_count:
                    current_rows = updated_count
                    if current_rows == desired_rows or current_rows % 3 == 0:
                        self.messages.put(("progress", f"Preparing Previous Information rows: {current_rows}/{desired_rows}"))
                    continue

                # Some portal versions add an empty repeater placeholder but
                # enable the next Add only after the current model is chosen.
                # Unlock that one row, then resume the add-only phase.
                models = model_controls()
                states_now = online_controls()
                if models:
                    row_index = len(states_now)
                    if row_index >= desired_rows:
                        break
                    model_control = models[0]
                    model_value = machines[row_index].get("Instrument description", "")
                    try:
                        model_control.click()
                        selected = choose_model(model_control, model_value)
                    except Exception:
                        selected = False
                    if not selected and is_online_state_control(model_control):
                        selected = select_online_when_ready(model_control)
                    if not selected:
                        skipped.append(f"Previous Information Model for machine {row_index + 1} (item option not available: {model_value}; available model options: {model_options_summary(model_control)})")
                        return
                    select_snapshot_cache["at"] = 0
                    transform_deadline = time.monotonic() + 5
                    while time.monotonic() < transform_deadline:
                        states_now = online_controls()
                        if len(states_now) > row_index or is_online_state_control(model_control):
                            break
                        page.wait_for_timeout(50)
                    current_rows = previous_row_count()
                    filled.append(f"Previous Information Model {row_index + 1}")
                    if current_rows == desired_rows:
                        break
                    continue
                else:
                    skipped.append(f"Previous Information: Add did not create row {current_rows + 1} within 5 seconds; prepared {current_rows} of {desired_rows}")
                    return
                if current_rows == desired_rows or current_rows % 3 == 0:
                    self.messages.put(("progress", f"Preparing Previous Information rows: {current_rows}/{desired_rows}"))
            except Exception as exc:
                skipped.append(f"Previous Information: could not create row {current_rows + 1}: {exc}")
                return

        # Finish converting every pre-existing Model Name row to Online before
        # entering any identifiers. This keeps row creation/setup as a strict
        # first phase and application/certificate/date entry as the second.
        states = online_controls()
        models = model_controls()
        while models:
            row_index = len(states)
            if row_index >= desired_rows:
                break
            model_control = models[0]
            model_value = machines[row_index].get("Instrument description", "")
            selected_model = False
            try:
                model_control.click()
                selected_model = choose_model(model_control, model_value)
            except Exception:
                selected_model = False
            if not selected_model:
                if is_online_state_control(model_control) and select_online_when_ready(model_control):
                    states = online_controls()
                    models = model_controls()
                    filled.append(f"Previous Information Online {row_index + 1}")
                    continue
                skipped.append(f"Previous Information Model for machine {row_index + 1} (item option not available after waiting: {model_value}; available model options: {model_options_summary(model_control)})")
                return
            transform_deadline = time.monotonic() + 5
            while time.monotonic() < transform_deadline:
                select_snapshot_cache["at"] = 0
                states = online_controls()
                models = model_controls()
                if len(states) > row_index or not models:
                    break
                page.wait_for_timeout(40)
            else:
                skipped.append(f"Previous Information row {row_index + 1} did not finish loading after model selection")
                return
            filled.append(f"Previous Information Model {row_index + 1}")
        if len(online_controls()) < desired_rows:
            skipped.append(f"Previous Information: prepared {len(online_controls())} Online row(s), needs {desired_rows}; no identifiers were entered")
            return

        date_rows = []
        states = online_controls()
        for index, machine in enumerate(machines):
            if index >= len(states):
                skipped.append(f"Previous Information: row {index + 1} is missing; remaining available machine rows will still be filled")
                continue
            state_control = states[index]

            if state_control is None or not select_online_when_ready(state_control):
                skipped.append(f"Previous Information Online option for machine {index + 1}")
                continue
            filled.append(f"Previous Information Online {index + 1}")
            identifiers = wait_for_row_inputs(state_control)
            if identifiers is None:
                skipped.append(f"Previous Information row {index + 1}: identifier inputs did not load in this row")
                continue
            app_control, cv_control, date_control = identifiers
            app_no = machine.get("Application number", "") or shared_application_number
            cv_no = machine.get("Previous CV number", "")
            row_value_controls = []
            identifier_ok = True
            for label, control, value in (("Application number", app_control, app_no), ("Certificate number", cv_control, cv_no)):
                if not value:
                    reason = "source PDF application number unavailable" if label == "Application number" and not value else "control not found or source value unavailable"
                    skipped.append(f"Previous Information {label} for machine {index + 1} ({reason})")
                    identifier_ok = False
                    continue
                try:
                    row_value_controls.append(control)
                    persisted = self._field_value_matches(control, value)
                    if persisted:
                        filled.append(f"Previous Information {label} {index + 1}")
                        continue
                    ready_deadline = time.monotonic() + 2.5
                    while time.monotonic() < ready_deadline:
                        try:
                            if control.is_visible() and control.is_enabled() and control.is_editable():
                                break
                        except Exception:
                            pass
                        page.wait_for_timeout(50)
                    try:
                        ready = control.is_visible() and control.is_enabled() and control.is_editable()
                    except Exception:
                        ready = False
                    if not ready:
                        skipped.append(f"Previous Information {label} for machine {index + 1} (field remained disabled)")
                        continue
                    persisted = False
                    for _attempt in range(2):
                        try:
                            if self._fill_control(control, value):
                                deadline = time.monotonic() + 0.8
                                while time.monotonic() < deadline:
                                    if self._field_value_matches(control, value):
                                        persisted = True
                                        break
                                    page.wait_for_timeout(50)
                            if persisted:
                                break
                        except Exception:
                            page.wait_for_timeout(75)
                    if persisted:
                        filled.append(f"Previous Information {label} {index + 1}")
                    else:
                        identifier_ok = False
                        try:
                            actual = control.input_value().strip()
                        except Exception:
                            actual = "unavailable"
                        skipped.append(f"Previous Information {label} for machine {index + 1} (value did not persist; field shows: {actual or 'blank'})")
                except Exception as exc:
                    skipped.append(f"Previous Information {label} for machine {index + 1}: {exc}")
                    identifier_ok = False
            if identifier_ok:
                try:
                    date_handle = date_control.element_handle()
                except Exception:
                    date_handle = None
                date_rows.append((index, date_control, row_value_controls, False, date_handle))
            if (index + 1) % 3 == 0 or index + 1 == len(machines):
                self.messages.put(("progress", f"Filling Previous Information identifiers: {index + 1}/{len(machines)}"))

        # The portal looks up Certificate Dates asynchronously. Do not wait up
        # to 30 seconds after each machine: all identifier pairs are entered
        # first, then all dates share one lookup window.
        pending_dates = {index: (control, identifiers, refreshed, handle)
                         for index, control, identifiers, refreshed, handle in date_rows}
        # Large applications can trigger dozens of asynchronous certificate
        # lookups at once. Give the portal a scaled batch window instead of
        # declaring later rows blank after the same short deadline used for a
        # small certificate.
        date_wait_seconds = min(120, max(30, len(date_rows) * 2))
        date_deadline = time.monotonic() + date_wait_seconds
        next_date_progress = time.monotonic() + 5
        while pending_dates and time.monotonic() < date_deadline:
            pending_items = list(pending_dates.items())
            handles = [item[1][3] for item in pending_items]
            batch_values = None
            if handles and all(handle is not None for handle in handles):
                try:
                    batch_values = page.evaluate("elements => elements.map(element => element?.value || '')", handles)
                except Exception:
                    batch_values = None
            for offset, (index, (date_control, identifiers, refreshed, handle)) in enumerate(pending_items):
                try:
                    date_value = batch_values[offset].strip() if batch_values is not None else date_control.input_value().strip()
                    if date_value:
                        filled.append(f"Previous Information Certificate date {index + 1}")
                        pending_dates.pop(index, None)
                        continue
                    if not refreshed:
                        for identifier in identifiers:
                            try:
                                identifier.dispatch_event("input")
                                identifier.dispatch_event("change")
                                identifier.evaluate("el => el.blur()")
                            except Exception:
                                pass
                        pending_dates[index] = (date_control, identifiers, True, handle)
                except Exception:
                    pending_dates.pop(index, None)
                    skipped.append(f"Previous Information Certificate date for machine {index + 1} (control not found)")
            if pending_dates:
                if time.monotonic() >= next_date_progress:
                    self.messages.put((
                        "progress",
                        f"Waiting for portal certificate dates: {len(pending_dates)} of {len(date_rows)} still loading",
                    ))
                    next_date_progress = time.monotonic() + 5
                page.wait_for_timeout(200)
        for index in pending_dates:
            skipped.append(f"Previous Information Certificate date for machine {index + 1} (portal did not populate it within {date_wait_seconds} seconds)")

    def _select_first_available(self, control):
        try:
            for option in control.locator("option").all():
                label = re.sub(r"\s+", " ", option.inner_text()).strip()
                value = option.get_attribute("value")
                if not label or value is None or label.lower() in {"select", "please select"} or option.get_attribute("disabled") is not None:
                    continue
                try:
                    control.select_option(value=value)
                    return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    def _fill_machine_detail_tables(self, groups, machines, skipped, filled):
        page = self.page
        weights_only = bool(machines) and all(_is_weights_item(row.get("Instrument description", "")) for row in machines)
        tables = []
        table_selector = page.locator("table")
        try:
            table_candidates = table_selector.all()
        except Exception:
            table_candidates = []
        header_signals = (
            r"denomination|weight", r"\bclass\b", r"\bmax(?:imum)?\b",
            r"\bmin(?:imum)?\b", r"e\s*/?\s*d|division|interval",
            r"make|manufacturer|brand", r"\bmodel\b", r"machine|serial",
            r"previous\s*cv|certificate\s*(?:no|number)|cv\s*(?:no|number)",
        )
        table_previews = []
        for table in table_candidates:
            try:
                if not table.is_visible():
                    continue
                rows = table.locator("tr").all()
                header_candidates = []
                for row in rows[:8]:
                    cells = row.locator("th,td").all_inner_texts()
                    if not cells:
                        continue
                    joined = self._norm(" ".join(cells))
                    score = sum(bool(re.search(pattern, joined, re.I)) for pattern in header_signals)
                    header_candidates.append((score, row, cells))
                if not header_candidates:
                    continue
                score, header_row, headers = max(header_candidates, key=lambda item: item[0])
                has_weight_column = any(re.search(r"denomination|weight", self._norm(cell), re.I) for cell in headers)
                # Portal revisions sometimes split the machine header across
                # two header rows. Combine column labels as a fallback while
                # keeping their original positions for the editable rows.
                if score < 3 and len(rows) >= 2:
                    header_rows = []
                    for row in rows[:8]:
                        if row.locator("input,select,textarea").count() and not row.locator("th").count():
                            continue
                        cells = row.locator("th,td").all_inner_texts()
                        if cells and any(str(cell).strip() for cell in cells):
                            header_rows.append(cells)
                    width = max((len(cells) for cells in header_rows), default=0)
                    combined = [" ".join(cells[col].strip() for cells in header_rows if col < len(cells) and cells[col].strip()) for col in range(width)]
                    combined_score = sum(bool(re.search(pattern, self._norm(" ".join(combined)), re.I)) for pattern in header_signals)
                    if combined_score > score:
                        score, headers = combined_score, combined
                if score < 3 and not (weights_only and has_weight_column):
                    if len(table_previews) < 4:
                        table_previews.append(" / ".join(re.sub(r"\s+", " ", str(cell)).strip() for cell in headers if str(cell).strip())[:180])
                    continue
                data_rows = [row for row in rows if row.locator("input,select,textarea").count()]
                if not data_rows:
                    continue
                tables.append((table, headers, data_rows))
            except Exception:
                # A detached unrelated table must not erase machine tables
                # already recognized elsewhere on the current page.
                continue
        if not tables:
            details = f"; visible table headers: {' | '.join(table_previews)}" if table_previews else ""
            skipped.append("Machine details: could not identify the portal table columns" + details + "; review and enter machine rows manually")
            return

        grouped_rows = [group.get("machines", []) for group in groups]
        flat_rows = [row for group in grouped_rows for row in group]
        flat_row_indices = {id(row): index for index, row in enumerate(machines)}
        def data_rows_for(table):
            rows = table.locator("tr").all()
            return [row for row in rows if row.locator("input,select,textarea").count()]

        expanded = []
        for table_index, (table, headers, _old_rows) in enumerate(tables):
            expected = len(flat_rows) if len(tables) == 1 else len(grouped_rows[table_index]) if table_index < len(grouped_rows) else 0
            if expected:
                if len(tables) == 1:
                    scope = self._section_locator(r"Items\s+to\s+be\s+verified")
                else:
                    group_text = groups[table_index].get("description", "") if table_index < len(groups) else "Items to be verified"
                    scope = self._section_locator(re.escape(group_text)) if group_text else self._section_locator(r"Items\s+to\s+be\s+verified")
                current_rows = data_rows_for(table)
                while len(current_rows) < expected:
                    add = self._add_button(scope)
                    if add is None:
                        break
                    try:
                        previous_count = len(current_rows)
                        # New machine rows are inserted in place; don't wait
                        # for a navigation after the Add click.
                        add.click(no_wait_after=True)
                    except Exception:
                        break
                    row_deadline = time.monotonic() + 5
                    updated = current_rows
                    while time.monotonic() < row_deadline:
                        updated = data_rows_for(table)
                        if len(updated) > previous_count:
                            break
                        page.wait_for_timeout(75)
                    if len(updated) <= previous_count:
                        break
                    current_rows = updated
                    if len(current_rows) == expected or len(current_rows) % 3 == 0:
                        self.messages.put(("progress", f"Preparing machine detail rows: {len(current_rows)}/{expected}"))
            else:
                current_rows = data_rows_for(table)
            if len(current_rows) < expected:
                skipped.append(f"Machine details: portal table has {len(current_rows)} row(s), needs {expected}")
            expanded.append((table, headers, current_rows))
        tables = expanded
        pattern_map = {
            "Quantity (As Per Specification)": r"quantity\s*\(?\s*as\s*per\s*(?:specification|spec)",
            "Denomination": r"denomination|weight\b",
            "Class": r"\bclass\b",
            "Maximum capacity": r"\bmax(?:imum)?\b",
            "Minimum capacity": r"\bmin(?:imum)?\b",
            "Verification interval (e/d)": r"e\s*/?\s*d|division|interval",
            "Instrument make": r"make|manufacturer|brand",
            "Instrument model": r"\bmodel\b",
            "Machine number": r"machine\s*(?:no|number)|serial",
            "Previous CV number": r"previous\s*cv|certificate\s*(?:no|number)|cv\s*(?:no|number)",
        }

        def fill_row(row_locator, headers, machine, machine_index):
            cells = row_locator.locator("th,td").all()
            found = set()
            for col, cell in enumerate(cells):
                header = headers[col] if col < len(headers) else ""
                field = next((name for name, pattern in pattern_map.items() if re.search(pattern, header, re.I)), None)
                if field is None:
                    # Some responsive portal layouts keep the visible column
                    # heading outside the data row. Use the control's own
                    # labels/metadata as a safe field-name fallback.
                    try:
                        controls_in_cell = cell.locator("input,select,textarea")
                        for control in controls_in_cell.all():
                            metadata = control.evaluate("""el => [
                                ...(el.labels || []).map(label => label.innerText || label.textContent || ''),
                                el.id || '', el.name || '', el.placeholder || '',
                                el.getAttribute('aria-label') || '', el.title || ''
                            ].join(' ')""")
                            field = next((name for name, pattern in pattern_map.items() if re.search(pattern, metadata or "", re.I)), None)
                            if field:
                                break
                    except Exception:
                        field = None
                if not field:
                    continue
                value = machine.get("Weights", "") or machine.get("Denomination", "") if field == "Denomination" else machine.get(field, "")
                if field == "Quantity (As Per Specification)":
                    value = machine.get("Quantity", "") or "1"
                if field == "Previous CV number":
                    value = machine.get("Previous CV number", "")
                if _is_weights_item(machine.get("Instrument description", "")) and field not in {
                    "Denomination", "Previous CV number", "Quantity (As Per Specification)"
                }:
                    continue
                controls = cell.locator("input,select,textarea")
                if not value or not controls.count():
                    continue
                try:
                    if field == "Previous CV number":
                        if len(machines) == 1:
                            continue
                        selected = self._select_previous_cv_option(controls.first, value)
                    else:
                        selected = self._fill_control(controls.first, value)
                    if selected:
                        found.add(field)
                        filled.append(f"Machine {machine_index + 1} {field}")
                    elif field == "Previous CV number":
                        skipped.append(
                            f"Machine {machine_index + 1} Previous CV dropdown did not select {value}"
                        )
                except Exception:
                    pass
            return found

        cursor = 0
        if len(tables) == 1:
            table, headers, data_rows = tables[0]
            for row_idx, row_locator in enumerate(data_rows[:len(flat_rows)]):
                source_index = flat_row_indices.get(id(flat_rows[row_idx]), row_idx)
                found = fill_row(row_locator, headers, flat_rows[row_idx], source_index)
                for key in pattern_map:
                    if key == "Previous CV number" and len(machines) == 1:
                        continue
                    if flat_rows[row_idx].get(key) and key not in found:
                        skipped.append(f"Machine {row_idx + 1} {key}")
            if len(data_rows) < len(flat_rows):
                skipped.append(f"Machine detail table has {len(data_rows)} row(s); needs {len(flat_rows)}")
            return

        for table, headers, data_rows in tables:
            group_rows = grouped_rows[cursor] if cursor < len(grouped_rows) else []
            for row_idx, row_locator in enumerate(data_rows[:len(group_rows)]):
                machine = group_rows[row_idx]
                global_index = flat_row_indices.get(id(machine), cursor + row_idx)
                found = fill_row(row_locator, headers, machine, global_index)
                for key in pattern_map:
                    if key == "Previous CV number" and len(machines) == 1:
                        continue
                    if machine.get(key) and key not in found:
                        skipped.append(f"Machine {global_index + 1} {key}")
            cursor += 1

    def _select_previous_cv_option(self, control, certificate_number, timeout=5):
        """Select and verify the exact certificate belonging to this machine row."""
        if control.evaluate("el => el.tagName.toLowerCase()") != "select":
            return False
        target = self._norm(str(certificate_number or ""))
        if not target:
            return False
        def contains_exact_cv(candidate):
            normalized = self._norm(str(candidate or ""))
            return bool(normalized) and re.search(
                rf"(?<![a-z0-9]){re.escape(target)}(?![a-z0-9])", normalized
            ) is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                options = control.locator("option").evaluate_all(r"""options => options.map(option => ({
                    label: (option.innerText || option.textContent || '').replace(/\s+/g,' ').trim(),
                    value: option.value || '', disabled: !!option.disabled
                }))""")
            except Exception:
                options = []
            choices = []
            for option in options:
                label, value = option["label"], option["value"]
                if not label or not value or option["disabled"] or label.lower() in {"select", "please select"}:
                    continue
                # The portal appends a certificate date to each dropdown
                # label (and some builds prefix metadata). Match the exact CV
                # token sequence anywhere without accepting a longer CV.
                if contains_exact_cv(label) or contains_exact_cv(value):
                    choices.append((label, value))
            # Require one exact certificate match; partial CV matches can pick
            # the wrong machine when the certificates differ only at the end.
            if len(choices) == 1 and self._choose_select_option(control, choices[0][1]):
                try:
                    selected_label = re.sub(
                        r"\s+", " ", control.locator("option:checked").first.inner_text()
                    ).strip()
                    selected_value = control.input_value().strip()
                    if contains_exact_cv(selected_label) or contains_exact_cv(selected_value):
                        return True
                except Exception:
                    pass
            self.page.wait_for_timeout(100)
        return False

    def _fill_machine_rows(self, rows, skipped):
        """Fill indexed machine rows when the portal exposes matching controls."""
        if not rows:
            return
        page = self.page

        def available_indices():
            indices = set()
            try:
                ids = page.locator("input[id],select[id],textarea[id]").evaluate_all("els => els.map(el => el.id)")
                for element_id in ids:
                    match = re.search(r"stampinglabourmeasures-(\d+)-", element_id or "", re.I)
                    if match:
                        indices.add(int(match.group(1)))
            except Exception:
                pass
            return indices

        indices = available_indices()
        while len(indices) < len(rows):
            add_control = None
            try:
                for control in page.locator("button,a,[role='button']").all():
                    if not control.is_visible():
                        continue
                    label = " ".join(filter(None, [control.inner_text(timeout=500), control.get_attribute("aria-label"), control.get_attribute("title")]))
                    if re.search(r"\badd\b.*\b(machine|instrument|item|measure|row)\b|\badd another\b", label, re.I):
                        add_control = control
                        break
            except Exception:
                add_control = None
            if add_control is None:
                break
            try:
                add_control.click()
                page.wait_for_timeout(450)
            except Exception:
                break
            updated = available_indices()
            if len(updated) <= len(indices):
                break
            indices = updated

        if len(indices) < len(rows):
            skipped.append(f"Portal machine rows: found {len(indices)} for {len(rows)} PDF machine(s); add the remaining row(s) manually")

        field_patterns = {
            "Weights": r"\b(weight|denomination)\b",
            "Instrument make": r"\b(make|manufacturer|brand)\b",
            "Maximum capacity": r"\b(max(?:imum)?|capacity max)\b",
            "Minimum capacity": r"\b(min(?:imum)?|capacity min)\b",
            "Verification interval (e/d)": r"\b(e\s*/?\s*d|division|interval)\b",
            "Instrument model": r"\bmodel\b",
            "Machine number": r"\b(machine\s*(?:no|number)|serial\s*(?:no|number))\b",
            "Class": r"\b(class|accuracy)\b",
        }
        ordered_indices = sorted(indices)
        for position, row in enumerate(rows[:len(ordered_indices)]):
            index = ordered_indices[position]
            category = page.locator(f"#stampinglabourmeasures-{index}-stamping-type-id")
            if row.get("Instrument description") and not self._select_best(category, row["Instrument description"]):
                skipped.append(f"Machine {position + 1}: item category")
            quantity = page.locator(f"#stampinglabourmeasures-{index}-quantity")
            if row.get("Quantity"):
                try:
                    if quantity.count():
                        quantity.fill(row["Quantity"])
                    else:
                        skipped.append(f"Machine {position + 1}: quantity")
                except Exception:
                    skipped.append(f"Machine {position + 1}: quantity")
            try:
                controls = page.locator(f"input[id*='stampinglabourmeasures-{index}-'],select[id*='stampinglabourmeasures-{index}-'],textarea[id*='stampinglabourmeasures-{index}-']").all()
            except Exception:
                controls = []
            for control in controls:
                try:
                    element_id = control.get_attribute("id") or ""
                    if element_id.endswith(("-quantity", "-stamping-type-id")):
                        continue
                    label = control.evaluate("el => [...(el.labels || [])].map(x => x.innerText).join(' ')")
                    metadata = self._norm(" ".join(filter(None, [element_id, control.get_attribute("name"), control.get_attribute("placeholder"), control.get_attribute("aria-label"), label])))
                    field = next((key for key, pattern in field_patterns.items() if re.search(pattern, metadata, re.I)), None)
                    if field == "Weights" and not _is_weights_item(row.get("Instrument description", "")):
                        field = None
                    if _is_weights_item(row.get("Instrument description", "")) and field not in {"Weights", None}:
                        continue
                    value = row.get(field, "") if field else ""
                    if not value:
                        continue
                    if control.evaluate("el => el.tagName.toLowerCase()") == "select":
                        self._select_best(control, value)
                    else:
                        control.fill(value)
                except Exception:
                    continue

    @staticmethod
    def _number(value: str) -> float | None:
        match = re.search(r"[\d,.]+", value or "")
        try:
            return float(match.group(0).replace(",", "")) if match else None
        except ValueError:
            return None

    def _select_best(self, locator, target: str) -> bool:
        """Select a matching visible option; leave the current choice untouched on ambiguity."""
        if not target:
            return False
        options = []
        for option in locator.locator("option").all():
            try:
                label = re.sub(r"\s+", " ", option.inner_text()).strip()
                value = str(option.evaluate("el => el.value") or "")
                if label and value and label.lower() != "select" and not option.evaluate("el => el.disabled"):
                    options.append((label, value))
            except Exception:
                pass
        if not options:
            return False
        norm = self._norm(target)
        exact = [o for o in options if self._norm(o[0]) == norm]
        if len(exact) == 1:
            return self._choose_select_option(locator, exact[0][1])
        partial = [o for o in options if norm in self._norm(o[0]) or self._norm(o[0]) in norm]
        if len(partial) == 1:
            return self._choose_select_option(locator, partial[0][1])
        scored = sorted(((SequenceMatcher(None, norm, self._norm(label)).ratio(), label, value) for label, value in options), reverse=True)
        if scored and scored[0][0] >= 0.62 and (len(scored) == 1 or scored[0][0] - scored[1][0] >= 0.08):
            return self._choose_select_option(locator, scored[0][2])
        return False

    @staticmethod
    def _choose_select_option(locator, value) -> bool:
        """Open a native dropdown, choose its option, and confirm it persisted."""
        try:
            if not locator.is_visible() or not locator.is_enabled():
                return False
            # Several portal controls (Tamil Nadu state selectors in
            # particular) are already set when a new form opens. Selecting the
            # same native option again fires a change handler that can clear
            # all downstream address lists. Preserve the existing selection.
            if str(locator.input_value()).strip() == str(value).strip():
                return True
            # The portal attaches dependent-list refresh handlers to mouse
            # interaction. Open the control before selecting and verify the
            # value instead of assuming the change event was accepted.
            locator.click(timeout=2500)
            locator.select_option(value=value, timeout=5000)
            return str(locator.input_value()).strip() == str(value).strip()
        except Exception:
            return False

    def _select_town_matching_street(self, town_control, street_control, town_target, address, section_pattern):
        """Choose a matching town by exact suffix matches against its Street options."""
        if not town_target or street_control is None:
            return None
        location = _locality_components(address)
        prefix = location["prefix_parts"]
        if not prefix:
            return None

        # Candidate streets are contiguous suffixes immediately to the left of
        # Town/Village, tried from longest to shortest. This supports streets
        # split across several comma-separated address components.
        candidate_streets = []
        first_prefix_is_door = bool(
            len(prefix) > 1 and re.fullmatch(r"\d+[/-]\d+[A-Za-z]?(?:\s+.*)?", prefix[0])
        )
        for start in range(len(prefix)):
            if start == 0 and first_prefix_is_door:
                continue
            candidate = ", ".join(prefix[start:])
            if candidate:
                candidate_streets.append((start, candidate, self._norm(candidate)))
        candidate_streets.sort(key=lambda item: (item[0], -len(item[2])))

        town_matches = []
        target_norm = self._norm(town_target)
        try:
            for option in town_control.locator("option").all():
                label = re.sub(r"\s+", " ", option.inner_text()).strip()
                value = str(option.evaluate("el => el.value") or "")
                if (value and label and label.lower() not in {"select", "please select"}
                        and not option.evaluate("el => el.disabled")):
                    if self._norm(label) == target_norm:
                        town_matches.append((label, value))
        except Exception:
            return None

        if not town_matches:
            if not self._select_best(town_control, town_target):
                return None
            try:
                selected = town_control.locator("option:checked").first
                town_matches = [(selected.inner_text().strip(), str(selected.evaluate("el => el.value") or ""))]
            except Exception:
                return None

        def street_options():
            result = []
            for option in street_control.locator("option").all():
                label = re.sub(r"\s+", " ", option.inner_text()).strip()
                value = str(option.evaluate("el => el.value") or "")
                if label and value and label.lower() not in {"select", "please select"} and not option.evaluate("el => el.disabled"):
                    result.append((label, value, self._norm(label)))
            return result

        for _town_label, town_value in town_matches:
            try:
                previous_signature = tuple((norm, value) for _label, value, norm in street_options())
                already_selected = town_control.input_value() == town_value
                if not self._choose_select_option(town_control, town_value):
                    continue
            except Exception:
                continue

            deadline = time.monotonic() + 8
            last_signature = previous_signature
            stable_since = None
            while time.monotonic() < deadline:
                try:
                    options = street_options()
                    signature = tuple((norm, value) for _label, value, norm in options)
                    matches = [
                        (start, candidate, option_label, option_value)
                        for start, candidate, candidate_norm in candidate_streets
                        for option_label, option_value, option_norm in options
                        if candidate_norm == option_norm
                    ]
                    # For repeated town labels, require the dependent Street
                    # list to refresh before trusting a match from that row.
                    refreshed = (
                        signature != previous_signature
                        or len(town_matches) == 1
                        or already_selected
                    )
                    if signature != previous_signature and options:
                        self._save_address_option_snapshot(section_pattern, "Street", street_control)
                    if refreshed and matches:
                        start, _candidate, street_label, _street_value = min(
                            matches, key=lambda item: (item[0], -len(self._norm(item[1])))
                        )
                        return {
                            "street": street_label,
                    # A literal hyphen in the Locality slot means the
                    # certificate has no numbered door; the portal still
                    # requires the submitted value to be "-".
                    "door_number": ", ".join(prefix[:start]) or (prefix[0] if prefix and prefix[0] == "-" else ""),
                        }
                    if signature != last_signature:
                        last_signature = signature
                        stable_since = time.monotonic()
                    elif signature != previous_signature and stable_since is not None and time.monotonic() - stable_since >= 0.3:
                        break
                except Exception:
                    pass
                self.page.wait_for_timeout(100)

        return None

    def _select_exact_option(self, locator, target) -> bool:
        """Select the first exact option when a dependent dropdown repeats labels."""
        norm = self._norm(target)
        if not norm:
            return False
        try:
            for option in locator.locator("option").all():
                label = re.sub(r"\s+", " ", option.inner_text()).strip()
                value = str(option.evaluate("el => el.value") or "")
                if value and label and self._norm(label) == norm and not option.evaluate("el => el.disabled"):
                    if self._choose_select_option(locator, value):
                        return True
        except Exception:
            return False
        return self._select_best(locator, target)

    def _file_input_for(self, section_text):
        page = self.page
        # Search the labelled section and its immediate ancestors; never guess file input order.
        matches = page.get_by_text(re.compile(re.escape(section_text), re.I)).all()
        for match in matches:
            for depth in range(1, 7):
                candidate = match.locator("xpath=" + "/".join([".."] * depth)).locator('input[type="file"]').first
                try:
                    if candidate.count():
                        return candidate
                except Exception:
                    pass
        # Associate explicit label[for] to file input.
        for label in page.locator("label").all():
            try:
                if section_text.lower() in label.inner_text().lower():
                    target_id = label.get_attribute("for")
                    if target_id:
                        return page.locator(f"#{target_id}")
            except Exception:
                pass
        return None

    def _find_visible_submit(self):
        page = self.page
        for candidate in page.locator("button:visible,input[type='submit']:visible,input[type='button']:visible,[role='button']:visible,a:visible").all():
            try:
                label = " ".join(filter(None, [candidate.inner_text(timeout=500), candidate.get_attribute("value"), candidate.get_attribute("aria-label"), candidate.get_attribute("title")])).strip()
                if re.search(r"\bsubmit\b", label, re.I) and candidate.is_enabled():
                    return candidate
            except Exception:
                continue
        return None

    def _find_visible_edit(self):
        page = self.page
        for candidate in page.locator("button:visible,input[type='button']:visible,input[type='submit']:visible,[role='button']:visible,a:visible").all():
            try:
                label = " ".join(filter(None, [candidate.inner_text(timeout=500), candidate.get_attribute("value"), candidate.get_attribute("aria-label"), candidate.get_attribute("title")])).strip()
                if re.fullmatch(r"edit", label, re.I) and candidate.is_enabled():
                    return candidate
            except Exception:
                continue
        return None

    def _submit(self):
        page = self.page
        payment_text = re.compile(r"make payment|proceed to payment|pay now|payment gateway|payment successful", re.I)
        if re.search(r"payment|receipt|checkout", page.url, re.I) or page.get_by_text(payment_text).count():
            self.messages.put(("payment", "The portal is already at a payment step. The assistant will not interact with payment."))
            return False
        if not self.ready_for_submit:
            raise RuntimeError("The application has not reached a verified final review page. Use Fill now / retry to complete the visible page first.")
        submit = self._find_visible_submit()
        if submit is None:
            raise RuntimeError("No visible Submit control is present on the current portal page. The application was not submitted; continue filling the current page.")
        page.once("dialog", lambda dialog: dialog.accept())
        submit.click(timeout=10000)
        try:
            page.wait_for_load_state("domcontentloaded", timeout=15000)
        except Exception:
            pass
        try:
            page.get_by_text(payment_text).first.wait_for(state="visible", timeout=15000)
        except Exception:
            pass
        if re.search(r"payment|receipt|checkout", page.url, re.I) or page.get_by_text(payment_text).count():
            self.messages.put(("payment", "The application was submitted and the payment page is ready. Review the amount and complete payment yourself."))
        else:
            self.messages.put(("submitted", "The application was submitted. The portal did not clearly identify the next page as payment; review the app browser. No payment was made."))
        self.ready_for_submit = False
        return True


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        minimum_width = min(760, screen_width)
        minimum_height = min(600, screen_height)
        initial_width = max(minimum_width, min(1120, screen_width - 80))
        initial_height = max(minimum_height, min(850, screen_height - 100))
        self.geometry(f"{initial_width}x{initial_height}")
        self.minsize(minimum_width, minimum_height)
        self._machine_layout_columns = None
        self._root_resize_pending = False
        self.theme_is_dark = None
        self.theme_mode = "Auto"
        self._theme_widgets_applied = False
        self.msgq: queue.Queue = queue.Queue()
        self.pdf_msgq: queue.Queue = queue.Queue()
        self._pdf_reading = False
        self._pdf_read_generation = 0
        self.worker: PortalWorker | None = None
        self.profile = {}
        try:
            self.profile = load_vault()
        except Exception as e:
            self._show_copyable_error("Profile could not be opened", f"Encrypted profile could not be read. It may belong to another Windows user.\n\n{e}")
        self.files = {"certificate": "", "authorization": "", "address_source": "", "portal_upload": ""}
        self.file_buttons = {}
        self.vars = {}
        self.machine_rows = []
        self.machine_metadata = []
        self.application_part_states = []
        self.active_application_part = 0
        self._styles()
        self._build()
        self._theme_widgets_applied = False
        self._load_profile()
        self.after(250, self._poll)
        self._refresh_system_theme()

    def _styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        self._apply_theme(self._system_dark_mode())
        style.configure("TButton", font=("Segoe UI Semibold", 12), padding=(14, 10))

    @staticmethod
    def _copy_text_to_clipboard(value, widget):
        if os.name != "nt":
            widget.clipboard_clear()
            widget.clipboard_append(value)
            widget.update()
            return
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.EmptyClipboard.restype = wintypes.BOOL
        user32.SetClipboardData.argtypes = [wintypes.UINT, ctypes.c_void_p]
        user32.SetClipboardData.restype = ctypes.c_void_p
        user32.CloseClipboard.restype = wintypes.BOOL
        kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.restype = wintypes.BOOL
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.restype = ctypes.c_void_p

        # Use this window as clipboard owner. Passing NULL works on many
        # systems, but can fail when the app is launched from a packaged
        # Windows process or while another app briefly owns the clipboard.
        owner = widget.winfo_id() if widget and widget.winfo_exists() else None
        opened = False
        for _ in range(40):
            if user32.OpenClipboard(owner):
                opened = True
                break
            time.sleep(0.075)
        if not opened:
            raise ctypes.WinError(ctypes.get_last_error())
        handle = None
        transferred = False
        try:
            if not user32.EmptyClipboard():
                raise ctypes.WinError(ctypes.get_last_error())
            payload = (value + "\0").encode("utf-16-le")
            handle = kernel32.GlobalAlloc(0x0002, len(payload))  # GMEM_MOVEABLE
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                ctypes.memmove(pointer, payload, len(payload))
            finally:
                kernel32.GlobalUnlock(handle)
            if not user32.SetClipboardData(13, handle):  # CF_UNICODETEXT
                raise ctypes.WinError(ctypes.get_last_error())
            transferred = True
        finally:
            user32.CloseClipboard()
            if handle and not transferred:
                kernel32.GlobalFree(handle)

    @staticmethod
    def _copy_text_via_powershell(value):
        """Use the Windows clipboard cmdlet as a fallback for locked Tk/Win32 clipboard calls."""
        encoded = base64.b64encode(str(value).encode("utf-8")).decode("ascii")
        script = (
            "$b=[Console]::In.ReadToEnd().Trim();"
            "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));"
            "Set-Clipboard -Value $t"
        )
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-STA", "-Command", script],
            input=encoded + "\n", text=True, encoding="ascii", capture_output=True,
            timeout=12, creationflags=flags,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "PowerShell clipboard command failed").strip()
            raise RuntimeError(detail)

    def _show_copyable_error(self, title, message, parent=None):
        """Show an error in selectable text with a one-click copy action."""
        p = getattr(self, "palette", {"bg": "#f3f6fa", "card": "#ffffff", "fg": "#243247", "border": "#c5ccd6", "selection": "#b7d7f0"})
        dialog = tk.Toplevel(parent or self)
        dialog.title(title)
        dialog.configure(bg=p["bg"])
        dialog.transient(parent or self)
        width, height = 720, 460
        dialog.update_idletasks()
        owner = parent or self
        x = owner.winfo_rootx() + max(0, (owner.winfo_width() - width) // 2)
        y = owner.winfo_rooty() + max(0, (owner.winfo_height() - height) // 2)
        x = min(x, max(0, dialog.winfo_screenwidth() - width))
        y = min(y, max(0, dialog.winfo_screenheight() - height))
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        dialog.minsize(540, 300)
        body = ttk.Frame(dialog, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Select the message or use Copy error to paste it into an update.", wraplength=680).pack(anchor="w", pady=(0, 8))
        text_frame = ttk.Frame(body)
        text_frame.pack(fill="both", expand=True)
        text = tk.Text(text_frame, wrap="word", font=("Consolas", 12), bg=p["card"], fg=p["fg"], insertbackground=p["fg"], selectbackground=p["selection"], relief="solid", borderwidth=1, padx=10, pady=10)
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        text.insert("1.0", str(message))
        # Keep it read-only while allowing standard selection and copy keys.
        text.bind("<Key>", lambda event: None if event.state & 0x4 and event.keysym.lower() in {"a", "c"} else "break")
        text.tag_add("sel", "1.0", "end-1c")
        text.focus_set()
        feedback = tk.StringVar(value="")
        footer = ttk.Frame(body)
        footer.pack(fill="x", pady=(10, 0))
        ttk.Label(footer, textvariable=feedback).pack(side="left")
        def select_all(_event=None):
            text.tag_add("sel", "1.0", "end-1c")
            text.mark_set("insert", "1.0")
            text.focus_set()
            return "break"
        def copy_error(_event=None):
            copied = False
            native_exc = tk_exc = None
            try:
                self._copy_text_to_clipboard(str(message), dialog)
                feedback.set("Copied. Paste with Ctrl+V.")
                copied = True
            except Exception as exc:
                native_exc = exc
                try:
                    dialog.clipboard_clear()
                    dialog.clipboard_append(str(message))
                    dialog.update()
                    if dialog.clipboard_get() != str(message):
                        raise tk.TclError("Clipboard verification failed")
                    feedback.set("Copied. Paste with Ctrl+V.")
                    copied = True
                except Exception as exc:
                    tk_exc = exc
            if not copied:
                try:
                    self._copy_text_via_powershell(str(message))
                    feedback.set("Copied. Paste with Ctrl+V.")
                    copied = True
                except Exception as ps_exc:
                    select_all()
                    feedback.set(f"Copy failed ({native_exc}; {tk_exc}; {ps_exc}). The text is selected; choose Save error… to get a text file.")
            # On failure, let Tk's standard Text class binding handle Ctrl+C.
            # Returning "break" here used to swallow that fallback keystroke.
            return "break" if copied else None
        def save_error():
            path = filedialog.asksaveasfilename(parent=dialog, title="Save error message", defaultextension=".txt", initialfile="stamping_error.txt", filetypes=[("Text files", "*.txt")])
            if not path:
                return
            try:
                Path(path).write_text(str(message), encoding="utf-8")
                feedback.set(f"Saved error text to {path}")
            except OSError as exc:
                feedback.set(f"Could not save error text: {exc}")
        tk.Button(footer, text="Copy error", command=copy_error, bg=p.get("accent", "#1261a0"), fg="#ffffff", activebackground=p.get("accent_active", p.get("accent", "#1261a0")), activeforeground="#ffffff", font=("Segoe UI Semibold", 12), padx=16, pady=9, relief="flat", borderwidth=0, highlightthickness=0).pack(side="left")
        tk.Button(footer, text="Select all", command=select_all, bg=p.get("card", "#ffffff"), fg=p.get("fg", "#243247"), activebackground=p.get("border", "#c5ccd6"), font=("Segoe UI Semibold", 12), padx=16, pady=9, relief="solid", borderwidth=1, highlightthickness=0).pack(side="left", padx=(8, 0))
        tk.Button(footer, text="Save error…", command=save_error, bg=p.get("card", "#ffffff"), fg=p.get("fg", "#243247"), activebackground=p.get("border", "#c5ccd6"), font=("Segoe UI Semibold", 12), padx=16, pady=9, relief="solid", borderwidth=1, highlightthickness=0).pack(side="left", padx=(8, 0))
        tk.Button(footer, text="Close", command=dialog.destroy, bg=p.get("card", "#ffffff"), fg=p.get("fg", "#243247"), activebackground=p.get("border", "#c5ccd6"), font=("Segoe UI Semibold", 12), padx=16, pady=9, relief="solid", borderwidth=1, highlightthickness=0).pack(side="right")
        text.bind("<Control-a>", select_all)
        text.bind("<Control-A>", select_all)
        text.bind("<Control-c>", copy_error)
        text.bind("<Control-C>", copy_error)
        dialog.grab_set()
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)

    def _system_dark_mode(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
                return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
        except OSError:
            return False

    def _apply_theme(self, dark):
        if self.theme_is_dark == dark and self._theme_widgets_applied:
            return
        previous = getattr(self, "palette", {"bg": "#f3f6fa", "card": "#ffffff", "muted": "#62738a"})
        self.theme_is_dark = dark
        if dark:
            self.palette = {"bg": "#171a21", "card": "#222630", "fg": "#e6e9ef", "muted": "#aab3c2", "title": "#f3f5f8", "input": "#171a21", "border": "#485162", "accent": "#2478bd", "accent_active": "#1b6098", "selection": "#315b7d"}
        else:
            self.palette = {"bg": "#f3f6fa", "card": "#ffffff", "fg": "#243247", "muted": "#62738a", "title": "#172b4d", "input": "#ffffff", "border": "#c5ccd6", "accent": "#1261a0", "accent_active": "#0c4b7d", "selection": "#b7d7f0"}
        p = self.palette
        self.configure(bg=p["bg"])
        if hasattr(self, "scroll_canvas"):
            self.scroll_canvas.configure(bg=p["bg"])
        style = ttk.Style(self)
        style.configure("TFrame", background=p["bg"])
        style.configure("Card.TFrame", background=p["card"])
        style.configure("TLabel", background=p["bg"], foreground=p["fg"], font=("Segoe UI", 13))
        style.configure("Title.TLabel", background=p["bg"], foreground=p["title"], font=("Segoe UI Semibold", 24))
        style.configure("Sub.TLabel", background=p["bg"], foreground=p["muted"], font=("Segoe UI", 13))
        style.configure("Section.TLabel", background=p["card"], foreground=p["title"], font=("Segoe UI Semibold", 15))
        style.configure("Card.TLabel", background=p["card"], foreground=p["fg"], font=("Segoe UI", 13))
        style.configure("Muted.Card.TLabel", background=p["card"], foreground=p["muted"], font=("Segoe UI", 12))
        style.configure("TEntry", fieldbackground=p["input"], foreground=p["fg"], bordercolor=p["border"], font=("Segoe UI", 13), padding=5)
        style.configure("TCombobox", fieldbackground=p["input"], background=p["card"], foreground=p["fg"], arrowcolor=p["fg"], font=("Segoe UI", 13), padding=5)
        style.map("TCombobox", fieldbackground=[("readonly", p["input"])], foreground=[("readonly", p["fg"])], selectbackground=[("readonly", p["selection"])], selectforeground=[("readonly", p["fg"])])
        style.configure("TCheckbutton", background=p["card"], foreground=p["fg"], font=("Segoe UI", 13), padding=4)
        style.map("TCheckbutton", background=[("active", p["card"])], foreground=[("disabled", p["muted"])])
        style.configure("TButton", background=p["card"], foreground=p["fg"], font=("Segoe UI Semibold", 12), padding=(14, 10))
        style.map("TButton", background=[("active", p["border"]), ("disabled", p["bg"])], foreground=[("disabled", p["muted"])])
        style.configure("Primary.TButton", background=p["accent"], foreground="white", font=("Segoe UI Semibold", 12), padding=(14, 10))
        style.map("Primary.TButton", background=[("active", p["accent_active"])])
        style.configure("Vertical.TScrollbar", background=p["card"], troughcolor=p["bg"], arrowcolor=p["fg"])
        self.option_add("*TCombobox*Listbox.background", p["input"])
        self.option_add("*TCombobox*Listbox.foreground", p["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", p["selection"])
        self.option_add("*TCombobox*Listbox.selectForeground", p["fg"])
        for widget in self.winfo_children():
            self._retheme_widgets(widget, previous)

    def _retheme_widgets(self, widget, previous):
        p = self.palette
        try:
            if isinstance(widget, tk.Canvas):
                widget.configure(bg=p["bg"])
            elif isinstance(widget, tk.Toplevel):
                widget.configure(bg=p["bg"])
            elif isinstance(widget, tk.Label):
                current_bg = str(widget.cget("bg"))
                next_bg = p["card"] if current_bg.lower() == str(previous.get("card", "#ffffff")).lower() else p["bg"]
                old_fg = str(widget.cget("fg")).lower()
                if old_fg == str(previous.get("muted", "#62738a")).lower():
                    next_fg = p["muted"]
                elif old_fg == str(previous.get("title", "#172b4d")).lower():
                    next_fg = p["title"]
                else:
                    next_fg = p["fg"]
                widget.configure(bg=next_bg, fg=next_fg)
            elif isinstance(widget, tk.Text):
                widget.configure(bg=p["card"], fg=p["fg"], insertbackground=p["fg"], selectbackground=p["selection"], selectforeground=p["fg"])
            elif isinstance(widget, tk.Entry):
                widget.configure(bg=p["input"], fg=p["fg"], insertbackground=p["fg"], selectbackground=p["selection"], selectforeground=p["fg"])
            elif isinstance(widget, tk.Button):
                current_bg = str(widget.cget("bg")).lower()
                if current_bg == str(previous.get("accent", "#1261a0")).lower():
                    widget.configure(bg=p["accent"], activebackground=p["accent_active"], fg="#ffffff", activeforeground="#ffffff")
                else:
                    widget.configure(bg=p["card"], activebackground=p["border"], fg=p["fg"], activeforeground=p["fg"])
        except tk.TclError:
            pass
        for child in widget.winfo_children():
            self._retheme_widgets(child, previous)
        self._theme_widgets_applied = True

    def _refresh_system_theme(self):
        if self.theme_mode == "Auto":
            self._apply_theme(self._system_dark_mode())
        self.after(1600, self._refresh_system_theme)

    def _on_theme_selected(self, _event=None):
        mode = self.theme_mode_var.get().strip()
        self.theme_mode = mode if mode in {"Auto", "Light", "Dark"} else "Auto"
        self._apply_theme(self._system_dark_mode() if self.theme_mode == "Auto" else self.theme_mode == "Dark")

    def _mousewheel(self, event):
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None:
            if widget is self.scroll_canvas:
                if getattr(event, "num", None) == 4:
                    units = -1
                elif getattr(event, "num", None) == 5:
                    units = 1
                else:
                    delta = getattr(event, "delta", 0)
                    units = -int(delta / 120) if delta else 0
                    if delta and units == 0:
                        units = -1 if delta > 0 else 1
                if units:
                    self.scroll_canvas.yview_scroll(units, "units")
                return "break"
            widget = getattr(widget, "master", None)

    @staticmethod
    def _machine_columns_for_width(width):
        if width >= 1400:
            return 10
        if width >= 1000:
            return 5
        if width >= 780:
            return 3
        return 2

    def _on_root_configure(self, event):
        if event.widget is not self:
            return
        width = max(320, event.width - 56)
        if hasattr(self, "status_label"):
            wrap = max(340, width - 34)
            self.previous_info_label.configure(wraplength=wrap)
            self.status_label.configure(wraplength=wrap)
            self.application_part_info_label.configure(wraplength=max(320, width - 340))
            self.session_action_hint.configure(wraplength=max(260, width - 360))
            self.draft_confirmation_status_label.configure(wraplength=max(280, width - 260))
        columns = self._machine_columns_for_width(event.width)
        if columns != self._machine_layout_columns:
            self._machine_layout_columns = columns
            if not self._root_resize_pending:
                self._root_resize_pending = True
                self.after_idle(self._finish_responsive_resize)

    def _finish_responsive_resize(self):
        self._root_resize_pending = False
        if hasattr(self, "machine_rows") and hasattr(self, "machine_field_frame"):
            self._render_machine_fields()

    def _build(self):
        outer = ttk.Frame(self, padding=22)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="TN Stamping Assistant", style="Title.TLabel").pack(side="left", anchor="w")
        ttk.Label(header, text="Theme", style="TLabel").pack(side="right", padx=(10, 6))
        self.theme_mode_var = tk.StringVar(value="Auto")
        self.theme_selector = ttk.Combobox(header, textvariable=self.theme_mode_var, values=("Auto", "Light", "Dark"), state="readonly", width=10)
        self.theme_selector.pack(side="right")
        self.theme_selector.bind("<<ComboboxSelected>>", self._on_theme_selected)
        ttk.Label(outer, text="Read a Previous CV or stamping input transcription, prepare the stamping form, and review before submission.", style="Sub.TLabel").pack(anchor="w", pady=(2, 16))
        canvas = tk.Canvas(outer, bg=self.palette["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas)
        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        self.body_window_id = canvas.create_window((0, 0), window=body, anchor="nw", width=960)
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(self.body_window_id, width=max(320, event.width)))
        canvas.configure(yscrollcommand=scrollbar.set)
        self.scroll_canvas = canvas
        self.body_frame = body
        self.bind("<Configure>", self._on_root_configure, add="+")
        self.bind_all("<MouseWheel>", self._mousewheel)
        self.bind_all("<Button-4>", self._mousewheel)
        self.bind_all("<Button-5>", self._mousewheel)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        login = self._card(body, "Portal sign-in")
        row = ttk.Frame(login, style="Card.TFrame"); row.pack(fill="x", pady=(10, 8))
        self.user_var = tk.StringVar(); self.pass_var = tk.StringVar()
        self.account_var = tk.StringVar()
        self.business_var = tk.StringVar(); self.contact_var = tk.StringVar(); self.mobile_var = tk.StringVar(); self.trader_contact_var = tk.StringVar()
        self.account_combo = ttk.Combobox(row, textvariable=self.account_var, state="readonly", width=24)
        self.account_combo.pack(side="left", fill="x", expand=True)
        self.account_combo.bind("<<ComboboxSelected>>", self._on_account_selected)
        ttk.Button(row, text="Add account", command=self.add_account, style="Primary.TButton").pack(side="left", padx=(10, 0))
        ttk.Button(row, text="Edit credentials", command=self.edit_account).pack(side="left", padx=(8, 0))

        docs = self._card(body, "Documents")
        self._file_row(
            docs,
            "PDF to read machine data (Previous CV or stamping input transcription)",
            "certificate",
            ("PDF files", "*.pdf"),
        )
        self._file_row(docs, "Authorisation letter from user / owner", "authorization", ("PDF or image", "*.pdf *.jpg *.jpeg *.png"))
        self.use_separate_upload_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            docs,
            text="Upload a different PDF to the portal than the machine data PDF",
            variable=self.use_separate_upload_var,
            command=self._on_portal_upload_changed,
        ).pack(anchor="w", pady=(10, 0))
        self._file_row(
            docs,
            "PDF to upload as purchase invoice / Previous CV",
            "portal_upload",
            ("PDF files", "*.pdf"),
            enabled=False,
        )
        self.use_different_address_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            docs, text="Use different address", variable=self.use_different_address_var,
            command=self._on_address_source_changed,
        ).pack(anchor="w", pady=(10, 0))
        self._file_row(docs, "Address source PDF", "address_source", ("PDF files", "*.pdf"), enabled=False)
        ttk.Label(docs, text="PAN card image is uploaded from the selected account. Portal file uploads must be under 1 MB.", style="Muted.Card.TLabel").pack(anchor="w", pady=(8, 0))

        first_page = self._card(body, "Application review — applicant and first page")
        pdf_action_row = ttk.Frame(first_page, style="Card.TFrame")
        pdf_action_row.pack(fill="x", pady=(8, 6))
        self.read_pdf_button = ttk.Button(pdf_action_row, text="Read PDF and fill draft", command=self.read_pdf, style="Primary.TButton")
        self.read_pdf_button.pack(side="left", padx=(0, 8))
        ttk.Button(
            pdf_action_row, text="Clear previous application", command=self.clear_previous_application,
        ).pack(side="left")
        choice_row = ttk.Frame(first_page, style="Card.TFrame")
        choice_row.pack(fill="x", pady=(4, 8))
        self.stamping_place_var = tk.StringVar(value="Select")
        self.site_status_var = tk.StringVar(value="Select")
        ttk.Label(choice_row, text="Stamping Office or Site", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.stamping_place_combo = ttk.Combobox(choice_row, textvariable=self.stamping_place_var, values=("Select", "Office", "Site"), state="readonly", width=16)
        self.stamping_place_combo.grid(row=0, column=1, sticky="w", padx=(0, 18))
        ttk.Label(choice_row, text="Site Dormant / Other", style="Card.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
        self.site_status_combo = ttk.Combobox(choice_row, textvariable=self.site_status_var, values=("Select", "Dormant", "Other"), state="disabled", width=16)
        self.site_status_combo.grid(row=0, column=3, sticky="w")
        choice_row.columnconfigure(4, weight=1)
        self.stamping_place_combo.bind("<<ComboboxSelected>>", self._on_application_choice_changed)
        self.site_status_combo.bind("<<ComboboxSelected>>", self._on_application_choice_changed)
        self.first_page_field_frame = ttk.Frame(first_page, style="Card.TFrame")
        self.first_page_field_frame.pack(fill="x")

        machine = self._card(body, "Machine details — certificate table")
        ttk.Label(machine, text="Review or correct each machine row read from the certificate pages.", style="Muted.Card.TLabel").pack(anchor="w", pady=(4, 8))
        self.application_part_row = ttk.Frame(machine, style="Card.TFrame")
        ttk.Label(self.application_part_row, text="Application part", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.application_part_var = tk.StringVar(value="Part 1 of 1")
        self.application_part_combo = ttk.Combobox(
            self.application_part_row, textvariable=self.application_part_var,
            state="readonly", width=24,
        )
        self.application_part_combo.pack(side="left")
        self.application_part_combo.bind("<<ComboboxSelected>>", self._on_application_part_changed)
        self.application_part_status = tk.StringVar(value="")
        self.application_part_info_label = ttk.Label(self.application_part_row, textvariable=self.application_part_status,
                                                     style="Muted.Card.TLabel", wraplength=600)
        self.application_part_info_label.pack(side="left", padx=(10, 0))
        self.machine_field_frame = ttk.Frame(machine, style="Card.TFrame")
        self.machine_field_frame.pack(fill="x")
        previous_info = self._card(body, "Previous Information")
        self.previous_info_status = tk.StringVar(value="No Previous Information errors.")
        self.previous_info_label = ttk.Label(previous_info, textvariable=self.previous_info_status, style="Muted.Card.TLabel",
                                             wraplength=930, justify="left")
        self.previous_info_label.pack(anchor="w", pady=(8, 0))
        self.pan_name = tk.StringVar(); self.pan_number = tk.StringVar(); self.pan_date = tk.StringVar(); self.license_number = tk.StringVar()
        self.repairer_establishment_var = tk.StringVar()
        self._set_fields({})

        action = ttk.Frame(body, style="Card.TFrame", padding=14); action.pack(fill="x", pady=(12, 5))
        self.draft_confirmed = tk.BooleanVar(value=False)
        self.draft_confirmation_status = tk.StringVar(value="Review the PDF draft and confirm before starting.")
        confirm_row = ttk.Frame(action, style="Card.TFrame")
        confirm_row.pack(fill="x", pady=(0, 8))
        ttk.Button(confirm_row, text="Confirm draft is ready", command=self.confirm_draft).pack(side="left", padx=(0, 8))
        self.draft_confirmation_status_label = ttk.Label(confirm_row, textvariable=self.draft_confirmation_status, style="Muted.Card.TLabel", wraplength=680)
        self.draft_confirmation_status_label.pack(side="left", fill="x", expand=True, padx=(4, 12))
        action_buttons = ttk.Frame(action, style="Card.TFrame")
        action_buttons.pack(fill="x")
        ttk.Button(action_buttons, text="Start application", command=self.open_portal, style="Primary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(action_buttons, text="Fill now / retry", command=self.fill_application).pack(side="left", padx=8)
        ttk.Button(action_buttons, text="Submit application", command=self.submit_application).pack(side="left", padx=8)
        session_action = ttk.Frame(body, style="Card.TFrame", padding=(14, 0, 14, 10))
        session_action.pack(fill="x", pady=(0, 4))
        session_buttons_row = ttk.Frame(session_action, style="Card.TFrame")
        session_buttons_row.pack(fill="x")
        self.new_application_button = ttk.Button(
            session_buttons_row, text="New application (keep signed-in session)",
            command=self.start_new_application_in_session,
        )
        self.new_application_button.pack(side="left")
        self.session_action_hint = ttk.Label(
            session_action, text="Uses the current Chromium login and opens a fresh New Stamping form.",
            style="Muted.Card.TLabel", wraplength=600,
        )
        self.session_action_hint.pack(fill="x", anchor="w", pady=(6, 0))
        self.start_all_parts_button = ttk.Button(
            session_buttons_row, text="Start all parts (same login)",
            command=self.start_all_application_parts,
        )
        self.status = tk.StringVar(value="Ready. Choose documents, review the PDF draft, then open the portal.")
        self.status_label = ttk.Label(body, textvariable=self.status, style="Sub.TLabel", wraplength=930)
        self.status_label.pack(anchor="w", pady=(10, 0))

    def _card(self, parent, title):
        card = ttk.Frame(parent, style="Card.TFrame", padding=16)
        card.pack(fill="x", pady=(0, 12))
        ttk.Label(card, text=title, style="Section.TLabel").pack(anchor="w")
        return card

    def _file_row(self, parent, label, key, file_filter, enabled=True):
        frame = ttk.Frame(parent, style="Card.TFrame"); frame.pack(fill="x", pady=(8, 0))
        ttk.Label(frame, text=label, width=40, style="Card.TLabel").pack(side="left")
        display = tk.StringVar(value="No file selected")
        self.files[key + "_display"] = display
        ttk.Label(frame, textvariable=display, style="Muted.Card.TLabel").pack(side="left", fill="x", expand=True, padx=8)
        button = ttk.Button(frame, text="Choose file", command=lambda: self.choose_file(key, file_filter), state="normal" if enabled else "disabled")
        button.pack(side="right")
        self.file_buttons[key] = button

    def _portal_upload_path(self):
        if self.use_separate_upload_var.get():
            return self.files.get("portal_upload", "")
        return self.files.get("certificate", "")

    def _on_address_source_changed(self):
        enabled = bool(self.use_different_address_var.get())
        button = self.file_buttons.get("address_source")
        if button is not None:
            button.configure(state="normal" if enabled else "disabled")
        if hasattr(self, "draft_confirmed"):
            self.draft_confirmed.set(False)
            self.draft_confirmation_status.set("Address source changed; reread and confirm the draft.")
        if enabled and not self.files.get("address_source"):
            self.status.set("Choose an address PDF, then select Read PDF and fill draft to apply its address fields.")
        else:
            self.status.set("Address source changed. Select Read PDF and fill draft to refresh the address values.")

    def _on_portal_upload_changed(self):
        enabled = bool(self.use_separate_upload_var.get())
        button = self.file_buttons.get("portal_upload")
        if button is not None:
            button.configure(state="normal" if enabled else "disabled")
        if hasattr(self, "draft_confirmed"):
            self.draft_confirmed.set(False)
            self.draft_confirmation_status.set("Portal upload selection changed; review and confirm the draft again.")
        if enabled and not self.files.get("portal_upload"):
            self.status.set("Choose the separate PDF that the portal should receive, then review and confirm the draft.")
        elif enabled:
            self.status.set("The selected separate PDF will be uploaded in the portal's Previous CV / invoice field.")
        else:
            self.status.set("The machine data PDF will also be uploaded in the portal.")

    def choose_file(self, key, file_filter):
        path = filedialog.askopenfilename(filetypes=[file_filter, ("All files", "*.*")])
        if path:
            self.files[key] = path
            self.files[key + "_display"].set(Path(path).name)
            if key == "address_source":
                self._on_address_source_changed()
            elif key == "portal_upload":
                self._on_portal_upload_changed()

    def _set_fields(self, values, machine_data=None):
        for frame in (self.first_page_field_frame, self.machine_field_frame):
            for widget in frame.winfo_children(): widget.destroy()
        self.vars.clear()
        self.machine_rows = []
        self.machine_metadata = []
        if hasattr(self, "draft_confirmed"):
            self.draft_confirmed.set(False)
            if hasattr(self, "draft_confirmation_status"):
                self.draft_confirmation_status.set("PDF draft changed; confirm it again before starting.")
        if hasattr(self, "stamping_place_var"):
            # Keep the user's explicit choice across PDF rereads, but offer the
            # certificate value as the initial choice when nothing is selected.
            if self.stamping_place_var.get() not in {"Office", "Site"}:
                detected = str(values.get("Stamping office/site", "")).strip().title()
                self.stamping_place_var.set(detected if detected in {"Office", "Site"} else "Select")
            if self.site_status_var.get() not in {"Dormant", "Other"}:
                detected = str(values.get("Dormant / Other", "")).strip().title()
                self.site_status_var.set(detected if detected in {"Dormant", "Other"} else "Select")
            self._sync_site_choice()
        first_idx = 0
        machine_keys = [
            "Weights", "Instrument description", "Instrument make", "Maximum capacity", "Minimum capacity",
            "Verification interval (e/d)", "Instrument model", "Machine number", "Class", "Quantity",
        ]
        machine_headers = {
            "Weights": "Weights", "Instrument description": "Instrument type", "Instrument make": "Make",
            "Maximum capacity": "Max", "Minimum capacity": "Min",
            "Verification interval (e/d)": "e/d", "Instrument model": "Model",
            "Machine number": "Machine number", "Class": "Class", "Quantity": "Qty",
        }
        self.machine_display_keys = machine_keys
        self.machine_display_headers = machine_headers
        records = machine_data or [{name: values.get(name, "") for name in machine_keys}]
        for machine_index, record in enumerate(records):
            row_vars = {}
            for name in machine_keys:
                var = tk.StringVar(value=record.get(name, ""))
                row_vars[name] = var
                if machine_index == 0:
                    self.vars[name] = var
            self.machine_rows.append(row_vars)
            self.machine_metadata.append({key: value for key, value in record.items() if key not in machine_keys})
        self._render_machine_fields()
        for name in FIELD_LABELS:
            if name in MACHINE_REVIEW_FIELDS:
                continue
            frame = self.first_page_field_frame
            idx = first_idx
            var = tk.StringVar(value=values.get(name, ""))
            self.vars[name] = var
            ttk.Label(frame, text=name, style="Card.TLabel").grid(row=idx, column=0, sticky="w", pady=3, padx=(0, 10))
            ttk.Entry(frame, textvariable=var, width=48).grid(row=idx, column=1, sticky="ew", pady=3)
            first_idx += 1
        self.first_page_field_frame.columnconfigure(1, weight=1)
        if self.pan_name.get(): self.vars["PAN name"].set(self.pan_name.get())
        if self.pan_number.get(): self.vars["PAN number"].set(self.pan_number.get())
        if self.pan_date.get(): self.vars["PAN date"].set(self.pan_date.get())
        if self.license_number.get(): self.vars["Repairer licence number"].set(self.license_number.get())

    def clear_previous_application(self):
        if not messagebox.askyesno(
            "Clear previous application",
            "Clear the selected previous CV and the application draft read from it?\n\n"
            "Your saved account and sign-in session will be kept. An application already open in the portal will not be changed.",
            parent=self,
        ):
            return
        self._pdf_read_generation += 1
        self._pdf_reading = False
        for key in ("certificate", "authorization", "address_source", "portal_upload"):
            self.files[key] = ""
            self.files[key + "_display"].set("No file selected")
        self.use_separate_upload_var.set(False)
        self._on_portal_upload_changed()
        self.use_different_address_var.set(False)
        self._on_address_source_changed()
        self.read_pdf_button.configure(state="normal")
        self._set_fields({})
        self.stamping_place_var.set("Select")
        self.site_status_var.set("Select")
        self._sync_site_choice()
        self.application_part_states = []
        self.active_application_part = 0
        self.application_part_var.set("Part 1 of 1")
        self.application_part_combo.configure(values=("Part 1 of 1",))
        self.application_part_status.set("")
        self.previous_info_status.set("No Previous Information errors.")
        self.draft_confirmed.set(False)
        self.draft_confirmation_status.set("Previous application cleared. Read a new certificate to prepare another draft.")
        self.status.set("Previous application cleared. Your saved account and sign-in session remain available.")

    def _render_machine_fields(self):
        if not hasattr(self, "machine_field_frame") or not hasattr(self, "machine_display_keys"):
            return
        for widget in self.machine_field_frame.winfo_children():
            widget.destroy()
        columns = self._machine_layout_columns or self._machine_columns_for_width(self.winfo_width())
        keys = self.machine_display_keys
        headers = self.machine_display_headers
        for col in range(max(10, columns)):
            self.machine_field_frame.columnconfigure(col, weight=0, uniform="")
        for col in range(columns):
            self.machine_field_frame.columnconfigure(col, weight=1, uniform="machine-fields")
        compact = columns < len(keys)
        if not compact:
            for col, name in enumerate(keys):
                ttk.Label(
                    self.machine_field_frame, text=headers.get(name, name), style="Card.TLabel",
                    wraplength=max(75, int(self.winfo_width() / columns) - 12), anchor="center",
                ).grid(row=0, column=col, sticky="nsew", padx=3, pady=(0, 5))
            for machine_index, row_vars in enumerate(self.machine_rows):
                label_row = 1 + machine_index * 2
                field_row = label_row + 1
                metadata = self.machine_metadata[machine_index] if machine_index < len(self.machine_metadata) else {}
                machine_type = row_vars.get("Instrument description").get() if row_vars.get("Instrument description") else ""
                certificate_no = metadata.get("Previous CV number", "")
                title = f"Machine {machine_index + 1}" + (f" — {machine_type}" if machine_type else "")
                if certificate_no:
                    title += f" (CV {certificate_no})"
                ttk.Label(self.machine_field_frame, text=title, style="Muted.Card.TLabel", wraplength=max(500, self.winfo_width() - 100), justify="left").grid(row=label_row, column=0, columnspan=columns, sticky="w", padx=3, pady=(8, 1))
                for col, name in enumerate(keys):
                    ttk.Entry(self.machine_field_frame, textvariable=row_vars[name], width=11).grid(row=field_row, column=col, sticky="ew", padx=3, pady=3)
            return

        rows_per_machine = math.ceil(len(keys) / columns) * 2 + 1
        for machine_index, row_vars in enumerate(self.machine_rows):
            base_row = machine_index * rows_per_machine
            metadata = self.machine_metadata[machine_index] if machine_index < len(self.machine_metadata) else {}
            machine_type = row_vars.get("Instrument description").get() if row_vars.get("Instrument description") else ""
            certificate_no = metadata.get("Previous CV number", "")
            title = f"Machine {machine_index + 1}" + (f" — {machine_type}" if machine_type else "")
            if certificate_no:
                title += f" (CV {certificate_no})"
            ttk.Label(self.machine_field_frame, text=title, style="Muted.Card.TLabel", wraplength=max(350, self.winfo_width() - 100), justify="left").grid(row=base_row, column=0, columnspan=columns, sticky="w", padx=3, pady=(8, 2))
            for index, name in enumerate(keys):
                row_offset = 1 + (index // columns) * 2
                col = index % columns
                cell_width = max(160, int((self.winfo_width() - 100) / columns))
                ttk.Label(self.machine_field_frame, text=headers.get(name, name), style="Card.TLabel", wraplength=cell_width - 12).grid(row=base_row + row_offset, column=col, sticky="w", padx=3, pady=(3, 0))
                ttk.Entry(self.machine_field_frame, textvariable=row_vars[name], width=14).grid(row=base_row + row_offset + 1, column=col, sticky="ew", padx=3, pady=(0, 4))

    def read_pdf(self):
        path = self.files.get("certificate")
        if not path:
            messagebox.showerror("Previous certificate required", "Select the previous CV or purchase invoice PDF first.")
            return
        use_address_source = bool(self.use_different_address_var.get())
        address_path = self.files.get("address_source", "") if use_address_source else ""
        if use_address_source and not address_path:
            messagebox.showerror("Address PDF required", "Select an address source PDF or turn off Use different address.")
            return
        if self._pdf_reading:
            return
        self._pdf_reading = True
        self._pdf_read_generation += 1
        generation = self._pdf_read_generation
        self.read_pdf_button.configure(state="disabled")
        self.status.set(f"Reading {Path(path).name} in the background. You can continue scrolling while it is processed.")
        threading.Thread(
            target=self._read_pdf_background,
            args=(path, generation, address_path),
            name="CertificateReader",
            daemon=True,
        ).start()

    def _read_pdf_background(self, path, generation, address_path=""):
        """Parse the machine CV and optional address source off the Tk thread."""
        try:
            parsed = extract_certificate_document(path)
            if address_path:
                page_count, meaningful_page_count, values, machines = parsed
                address_fields = extract_address_document(address_path)
                # The selected address PDF also controls the applicant name.
                # Keep the main Previous CV as the source for machine and CV data.
                values.update(address_fields)
                parsed = page_count, meaningful_page_count, values, machines
            self.pdf_msgq.put(("parsed", (generation, path, address_path, parsed)))
        except Exception as exc:
            self.pdf_msgq.put(("error", (generation, path, address_path, str(exc))))

    def _finish_pdf_read(self, kind, result):
        generation, path, address_path, payload = result
        if generation != self._pdf_read_generation:
            return
        self._pdf_reading = False
        self.read_pdf_button.configure(state="normal")
        if path != self.files.get("certificate"):
            self.status.set("The selected certificate changed while it was being read. Select Read PDF and fill draft again.")
            return
        current_address_path = self.files.get("address_source", "") if self.use_different_address_var.get() else ""
        if address_path != current_address_path:
            self.status.set("The address source changed while the PDF was being read. Select Read PDF and fill draft again.")
            return
        if kind == "error":
            self._show_copyable_error("Could not read PDF", payload)
            return
        page_count, meaningful_page_count, values, machines = payload
        if not machines:
            messagebox.showerror("No selectable text found", "This PDF appears to be a scan. Use a text-searchable PDF; OCR is not included in this local build.")
            return
        account_index = self.account_combo.current()
        account = self.accounts[account_index] if 0 <= account_index < len(self.accounts) else {}
        repairer_company = str(account.get("repairer_company_name") or "").strip() or values.get("Repairer business name", "").strip()
        repairer_mobile = str(account.get("repairer_mobile") or "").strip() or values.get("Repairer mobile", "").strip()
        repairer_contact = ", ".join(part for part in (repairer_company, repairer_mobile) if part)
        if account_index >= 0 and account and (repairer_company or repairer_mobile):
            changed = False
            if repairer_company and not account.get("repairer_company_name"):
                account["repairer_company_name"] = repairer_company
                changed = True
            if repairer_mobile and not account.get("repairer_mobile"):
                account["repairer_mobile"] = repairer_mobile
                changed = True
            if changed:
                self.profile["portal_accounts"] = self.accounts
                try:
                    save_vault(self.profile)
                except Exception as exc:
                    self._show_copyable_error("Could not save repairer profile details", str(exc))
        values.update({"Applicant business name": values.get("Applicant / establishment name", ""), "Applicant contact name": self.contact_var.get(), "Registered name": self.contact_var.get(), "Registered email": self.user_var.get(), "Registered mobile": self.mobile_var.get(), "Used by / trader contact": repairer_contact, "PAN name": self.pan_name.get(), "PAN number": self.pan_number.get(), "PAN date": self.pan_date.get(), "Repairer name": self.pan_name.get(), "Repairer licence number": self.license_number.get()})
        self.repairer_establishment_var.set(repairer_contact)
        self.application_part_states = self._create_application_parts(values, machines)
        self.active_application_part = 0
        part_labels = [f"Part {index + 1} of {len(self.application_part_states)} ({len(part['machines'])} machines)"
                       for index, part in enumerate(self.application_part_states)]
        self.application_part_combo.configure(values=part_labels)
        self.application_part_var.set(part_labels[0] if part_labels else "Part 1 of 1")
        if len(self.application_part_states) > 1:
            self.application_part_row.pack(fill="x", pady=(0, 8))
            self.start_all_parts_button.pack(side="right")
            sizes = " + ".join(str(len(part["machines"])) for part in self.application_part_states)
            self.application_part_status.set(
                f"{len(machines)} machines split into {len(self.application_part_states)} separate applications ({sizes}). "
                "Complete and submit each part separately; choose the next part here and reuse the signed-in session."
            )
        else:
            self.application_part_row.pack_forget()
            self.start_all_parts_button.pack_forget()
            self.application_part_status.set("")
        if self.application_part_states:
            first_part = self.application_part_states[0]
            self._set_fields(first_part["fields"], first_part["machines"])
        else:
            self._set_fields(values, machines)
        ignored = page_count - meaningful_page_count
        address_note = f" Address fields read from {Path(address_path).name}." if address_path else " Address fields read from the machine data PDF."
        portal_upload_path = self._portal_upload_path()
        upload_note = (
            f" Portal upload uses {Path(portal_upload_path).name}."
            if portal_upload_path and portal_upload_path != path
            else " The machine data PDF will also be uploaded to the portal."
        )
        split_note = f" Split into {len(self.application_part_states)} application parts; review each part separately." if len(self.application_part_states) > 1 else ""
        self.status.set(f"Machine data read from {Path(path).name}: {page_count} pages, {len(machines)} machine(s), {ignored} blank/footer page(s) ignored.{split_note}{address_note}{upload_note} Review every value before filling the portal.")

    def _create_application_parts(self, values, machines):
        sizes = plan_machine_parts(len(machines))
        if not sizes:
            return []
        parts = []
        start = 0
        for size in sizes:
            records = [dict(record) for record in machines[start:start + size]]
            start += size
            part_values = dict(values)
            first_machine = records[0]
            # Each separate portal application must show the CV and date from
            # the first machine page included in that part.
            if first_machine.get("Previous CV number"):
                part_values["Previous CV number"] = first_machine["Previous CV number"]
            if first_machine.get("Previous CV date"):
                part_values["Previous CV date"] = first_machine["Previous CV date"]
            if first_machine.get("Application number"):
                part_values["Application number"] = first_machine["Application number"]
            parts.append({"fields": part_values, "machines": records})
        return parts

    def _store_active_application_part(self):
        if not self.application_part_states or not (0 <= self.active_application_part < len(self.application_part_states)):
            return
        state = self.application_part_states[self.active_application_part]
        state["fields"] = {
            key: variable.get().strip()
            for key, variable in self.vars.items()
            if key not in MACHINE_REVIEW_FIELDS
        }
        edited_machines = []
        for index, row in enumerate(self.machine_rows):
            record = dict(self.machine_metadata[index]) if index < len(self.machine_metadata) else {}
            record.update({key: variable.get().strip() for key, variable in row.items()})
            edited_machines.append(record)
        if edited_machines:
            state["machines"] = edited_machines

    def _on_application_part_changed(self, _event=None):
        if len(self.application_part_states) < 2:
            return
        selected = self.application_part_combo.current()
        if selected < 0 or selected >= len(self.application_part_states) or selected == self.active_application_part:
            return
        self._store_active_application_part()
        self.active_application_part = selected
        state = self.application_part_states[selected]
        self._set_fields(state["fields"], state["machines"])
        self.draft_confirmation_status.set("Application part changed; review its address and machine rows, then confirm it.")

    def _load_profile(self):
        self.accounts = list(self.profile.get("portal_accounts", []))
        legacy_pan = {
            "pan_name": self.profile.get("pan_name", ""),
            "pan_number": self.profile.get("pan_number", ""),
            "pan_date": self.profile.get("pan_date", ""),
            "pan_image_b64": self.profile.get("pan_image_b64", ""),
            "pan_image_name": self.profile.get("pan_image_name", ""),
        }
        migrated = False
        if not self.accounts and self.profile.get("username") and self.profile.get("password"):
            self.accounts = [{"username": self.profile["username"], "password": self.profile["password"], **legacy_pan}]
            migrated = True
        elif self.accounts and any(legacy_pan.values()):
            # Older builds stored one shared PAN profile. Attach it to the first
            # account once so it cannot leak across the other saved accounts.
            for key, value in legacy_pan.items():
                if value and not self.accounts[0].get(key):
                    self.accounts[0][key] = value
                    migrated = True
        for key in ("username", "password", "account_label", "pan_name", "pan_number", "pan_date", "pan_image_b64", "pan_image_name"):
            self.profile.pop(key, None)
        self.profile["portal_accounts"] = self.accounts
        self._refresh_accounts(0 if self.accounts else None)
        self.business_var.set(self.profile.get("applicant_business_name", ""))
        self.contact_var.set(self.profile.get("applicant_contact_name", ""))
        self.mobile_var.set(self.profile.get("applicant_mobile", ""))
        self.trader_contact_var.set(self.profile.get("trader_contact_name", ""))
        if migrated:
            try:
                save_vault(self.profile)
            except Exception as exc:
                self._show_copyable_error("Could not migrate saved account", str(exc))

    def _account_label(self, account):
        return account.get("username", "")

    def _refresh_accounts(self, select_index=None):
        self.account_combo["values"] = [self._account_label(account) for account in getattr(self, "accounts", [])]
        if self.accounts:
            index = select_index if select_index is not None and 0 <= select_index < len(self.accounts) else 0
            self.account_combo.current(index)
            self._on_account_selected()
        else:
            self.account_var.set("")
            self.user_var.set(""); self.pass_var.set("")
            self.pan_name.set(""); self.pan_number.set(""); self.pan_date.set("")
            self.license_number.set("")

    def _on_account_selected(self, _event=None):
        index = self.account_combo.current()
        if 0 <= index < len(getattr(self, "accounts", [])):
            account = self.accounts[index]
            self.user_var.set(account.get("username", ""))
            self.pass_var.set(account.get("password", ""))
            self.pan_name.set(account.get("pan_name", ""))
            self.pan_number.set(account.get("pan_number", ""))
            self.pan_date.set(account.get("pan_date", ""))
            self.license_number.set(account.get("license_number", ""))
            repairer_contact = ", ".join(
                part for part in (
                    str(account.get("repairer_company_name", "")).strip(),
                    str(account.get("repairer_mobile", "")).strip(),
                ) if part
            )
            self.repairer_establishment_var.set(repairer_contact)
            if self.vars:
                self.vars["PAN name"].set(self.pan_name.get())
                self.vars["PAN number"].set(self.pan_number.get())
                self.vars["PAN date"].set(self.pan_date.get())
                self.vars["Repairer licence number"].set(self.license_number.get())

    def edit_account(self):
        index = self.account_combo.current()
        if index < 0 or index >= len(self.accounts):
            messagebox.showerror("Choose an account", "Select an email from the dropdown before editing its credentials.")
            return
        self.add_account(edit_index=index)

    def add_account(self, edit_index=None):
        window = tk.Toplevel(self)
        window.title("Edit portal account" if edit_index is not None else "Add portal account")
        window.transient(self)
        window.grab_set()
        window.geometry("560x760")
        pad = ttk.Frame(window, padding=18); pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Portal sign-in and matching PAN profile", style="Section.TLabel").pack(anchor="w")
        ttk.Label(pad, text="Sign-in, company/mobile, license, and PAN details are encrypted together for this email account.", style="Sub.TLabel", wraplength=500).pack(anchor="w", pady=(4, 12))

        email_var = tk.StringVar(); password_var = tk.StringVar()
        pan_name_var = tk.StringVar(); pan_number_var = tk.StringVar(); pan_date_var = tk.StringVar()
        license_var = tk.StringVar(); image_label = tk.StringVar(value="No PAN image selected")
        repairer_company_var = tk.StringVar(); repairer_mobile_var = tk.StringVar()
        image_data = {"b64": "", "name": ""}
        loaded_email = {"value": ""}
        fields = ttk.Frame(pad); fields.pack(fill="x")
        entries = (
            ("Registered email address", email_var, ""), ("Portal password", password_var, "•"),
            ("Company name", repairer_company_var, ""), ("Mobile number", repairer_mobile_var, ""),
            ("Name on PAN card", pan_name_var, ""), ("PAN number", pan_number_var, ""),
            ("Date on PAN card", pan_date_var, ""), ("License Number", license_var, ""),
        )
        email_entry = None
        for row, (label, variable, show) in enumerate(entries):
            ttk.Label(fields, text=label).grid(row=row * 2, column=0, sticky="w", pady=(3, 1))
            entry = ttk.Entry(fields, textvariable=variable, show=show)
            entry.grid(row=row * 2 + 1, column=0, sticky="ew", pady=(0, 5))
            if variable is email_var:
                email_entry = entry
        fields.columnconfigure(0, weight=1)

        def choose_pan_image():
            path = filedialog.askopenfilename(parent=window, filetypes=[("PAN card image", "*.jpg *.jpeg *.png"), ("All files", "*.*")])
            if not path:
                return
            try:
                content = Path(path).read_bytes()
                if len(content) > 1024 * 1024:
                    messagebox.showerror("Image too large", "The portal accepts uploaded files up to 1 MB. Choose a smaller PAN image.", parent=window)
                    return
                image_data["b64"] = base64.b64encode(content).decode("ascii")
                image_data["name"] = Path(path).name
                image_label.set(Path(path).name)
            except OSError as exc:
                self._show_copyable_error("Could not read PAN image", str(exc), parent=window)

        ttk.Label(pad, text="PAN card image").pack(anchor="w", pady=(8, 2))
        image_row = ttk.Frame(pad); image_row.pack(fill="x")
        ttk.Label(image_row, textvariable=image_label, style="Sub.TLabel").pack(side="left", fill="x", expand=True)
        ttk.Button(image_row, text="Choose JPG / PNG", command=choose_pan_image).pack(side="right")

        def load_existing(_event=None):
            email = email_var.get().strip().casefold()
            existing = next((item for item in self.accounts if item.get("username", "").casefold() == email), None)
            if not existing:
                if edit_index is None and loaded_email["value"] and loaded_email["value"] != email:
                    password_var.set(""); repairer_company_var.set(""); repairer_mobile_var.set(""); pan_name_var.set(""); pan_number_var.set("")
                    pan_date_var.set(""); license_var.set("")
                    image_data["b64"] = ""; image_data["name"] = ""
                    image_label.set("No PAN image selected")
                    loaded_email["value"] = ""
                return
            loaded_email["value"] = email
            password_var.set(existing.get("password", ""))
            repairer_company_var.set(existing.get("repairer_company_name", ""))
            repairer_mobile_var.set(existing.get("repairer_mobile", ""))
            pan_name_var.set(existing.get("pan_name", ""))
            pan_number_var.set(existing.get("pan_number", ""))
            pan_date_var.set(existing.get("pan_date", ""))
            license_var.set(existing.get("license_number", ""))
            image_data["b64"] = existing.get("pan_image_b64", "")
            image_data["name"] = existing.get("pan_image_name", "")
            image_label.set(image_data["name"] or "No PAN image selected")

        email_entry.bind("<FocusOut>", load_existing)

        if edit_index is not None and 0 <= edit_index < len(self.accounts):
            current = self.accounts[edit_index]
            email_var.set(current.get("username", ""))
            password_var.set(current.get("password", ""))
            repairer_company_var.set(current.get("repairer_company_name", ""))
            repairer_mobile_var.set(current.get("repairer_mobile", ""))
            pan_name_var.set(current.get("pan_name", ""))
            pan_number_var.set(current.get("pan_number", ""))
            pan_date_var.set(current.get("pan_date", ""))
            license_var.set(current.get("license_number", ""))
            image_data["b64"] = current.get("pan_image_b64", "")
            image_data["name"] = current.get("pan_image_name", "")
            image_label.set(image_data["name"] or "No PAN image selected")
            loaded_email["value"] = current.get("username", "").casefold()

        def save_account():
            email, password = email_var.get().strip(), password_var.get()
            if not email or not password:
                messagebox.showerror("Missing sign-in", "Enter the registered email and portal password.", parent=window)
                return
            if not pan_name_var.get().strip() or not pan_number_var.get().strip() or not pan_date_var.get().strip() or not image_data["b64"]:
                messagebox.showerror("PAN profile incomplete", "Enter the PAN name, number, and date, and choose a PAN card image.", parent=window)
                return
            old_accounts = self.accounts
            match_index = next((i for i, item in enumerate(self.accounts) if item.get("username", "").casefold() == email.casefold()), None)
            if edit_index is not None:
                duplicate = match_index is not None and match_index != edit_index
                if duplicate:
                    messagebox.showerror("Email already saved", "That email belongs to another saved account. Use a unique email address.", parent=window)
                    return
                match_index = edit_index
            record = dict(self.accounts[match_index]) if match_index is not None else {}
            record.update({
                "username": email, "password": password,
                "repairer_company_name": repairer_company_var.get().strip(),
                "repairer_mobile": repairer_mobile_var.get().strip(),
                "pan_name": pan_name_var.get().strip(), "pan_number": pan_number_var.get().strip(),
                "pan_date": pan_date_var.get().strip(), "license_number": license_var.get().strip(),
                "pan_image_b64": image_data["b64"], "pan_image_name": image_data["name"],
            })
            self.accounts = list(self.accounts)
            if match_index is None:
                self.accounts.append(record); match_index = len(self.accounts) - 1
            else:
                self.accounts[match_index] = record
            self.profile["portal_accounts"] = self.accounts
            try:
                save_vault(self.profile)
            except Exception as exc:
                self.accounts = old_accounts
                self.profile["portal_accounts"] = old_accounts
                self._show_copyable_error("Could not save account", str(exc), parent=window)
                return
            self._refresh_accounts(match_index)
            self.status.set(f"Saved encrypted account for {email}.")
            if self.worker and self.worker.is_alive() and self.account_combo.current() == match_index:
                self.worker.send("credentials", {
                    "credentials": {"username": email, "password": password},
                    "application": self._application_payload(),
                })
            window.destroy()

        buttons = ttk.Frame(pad); buttons.pack(fill="x", pady=(16, 0))
        ttk.Button(buttons, text="Save changes" if edit_index is not None else "Save account", command=save_account, style="Primary.TButton").pack(side="left")
        ttk.Button(buttons, text="Cancel", command=window.destroy).pack(side="right")

    def open_portal(self):
        self._on_account_selected()
        if not self.user_var.get() or not self.pass_var.get():
            messagebox.showerror("Sign-in needed", "Choose an email from the dropdown or add an account.")
            return
        self._ensure_worker()
        has_draft = bool(self.machine_rows and self.files.get("certificate"))
        if has_draft and not self._validate_draft_confirmation():
            return
        try:
            self.worker.send("open", {"credentials": {"username": self.user_var.get(), "password": self.pass_var.get()}, "application": self._application_payload() if has_draft else None})
            self.status.set("Opening bundled Chromium and filling saved sign-in. Enter the CAPTCHA in that window; a reviewed PDF draft will continue automatically after login." if has_draft else "Opening bundled Chromium and filling saved sign-in. Enter the CAPTCHA there. Read the PDF draft, then choose Fill now / retry after login.")
        except Exception as exc:
            self.status.set(f"Could not start Chromium: {exc}")
            self._show_copyable_error("Could not start Chromium", str(exc))

    def _ensure_worker(self):
        if not self.worker or not self.worker.is_alive(): self.worker = PortalWorker(self.msgq)

    def fill_application(self):
        self._on_account_selected()
        if not self.user_var.get() or not self.pass_var.get():
            messagebox.showerror("Sign-in needed", "Choose an email from the dropdown or add an account.")
            return
        if not self.files.get("certificate") or not self.machine_rows:
            messagebox.showerror("PDF draft required", "Choose the previous CV PDF and select Read PDF and fill draft first.")
            return
        if not self._validate_draft_confirmation():
            return
        self._ensure_worker()
        payload = self._application_payload()
        payload["credentials"] = {"username": self.user_var.get(), "password": self.pass_var.get()}
        try:
            self.worker.send("fill", payload)
            self.status.set("Filling the application in bundled Chromium. If you are not signed in, the browser will open for CAPTCHA first.")
        except Exception as exc:
            self.status.set(f"Could not start Chromium: {exc}")
            self._show_copyable_error("Could not start Chromium", str(exc))

    def start_new_application_in_session(self):
        self._on_account_selected()
        if not self.user_var.get() or not self.pass_var.get():
            messagebox.showerror("Sign-in details needed", "Choose an email from the saved account dropdown first.")
            return
        if not self.files.get("certificate") or not self.machine_rows:
            messagebox.showerror("PDF draft required", "Choose the Previous CV PDF and select Read PDF and fill draft first.")
            return
        if not self._validate_draft_confirmation():
            return
        if not messagebox.askyesno(
            "Start another stamping application",
            "This will leave the current portal page and open a fresh New Stamping form in the already signed-in Chromium session. The current application will not be submitted. Continue?",
        ):
            return
        self._ensure_worker()
        payload = self._application_payload()
        payload["credentials"] = {"username": self.user_var.get(), "password": self.pass_var.get()}
        try:
            self.worker.send("new_application", payload)
            self.status.set("Reusing the current signed-in Chromium session and opening a fresh New Stamping form.")
        except Exception as exc:
            self.status.set(f"Could not start a new application in the current session: {exc}")
            self._show_copyable_error("Could not reuse signed-in session", str(exc))

    def start_all_application_parts(self):
        self._on_account_selected()
        if not self.user_var.get() or not self.pass_var.get():
            messagebox.showerror("Sign-in details needed", "Choose an email from the saved account dropdown first.")
            return
        if len(self.application_part_states) < 2:
            messagebox.showerror("No split parts", "Read a PDF with more than 40 machine records first.")
            return
        if self.active_application_part != 0:
            messagebox.showerror("Select Part 1", "Choose Part 1 and confirm its draft before starting the complete split application.")
            return
        if not self._validate_draft_confirmation():
            return
        if not messagebox.askyesno(
            "Apply all split parts",
            f"The {len(self.application_part_states)} parts will be opened in separate tabs in one signed-in Chromium session. Complete CAPTCHA once. Each part will stop at its final review and wait for your Submit confirmation; the next part opens after submission. Payment remains manual. Continue?",
        ):
            return
        try:
            applications = [self._application_payload(index) for index in range(len(self.application_part_states))]
            self._ensure_worker()
            self.worker.send("apply_all_parts", {
                "applications": applications,
                "credentials": {"username": self.user_var.get(), "password": self.pass_var.get()},
            })
            self.status.set("Preparing every application part in the same Chromium login session.")
        except Exception as exc:
            self.status.set(f"Could not start all application parts: {exc}")
            self._show_copyable_error("Could not start split applications", str(exc))

    def _application_payload(self, part_index=None):
        if part_index is not None and self.application_part_states:
            self._store_active_application_part()
            if part_index < 0 or part_index >= len(self.application_part_states):
                raise IndexError("Application part selection is invalid.")
            part = self.application_part_states[part_index]
            fields = dict(part["fields"])
            source_machine_rows = [dict(row) for row in part["machines"]]
        else:
            fields = {k: v.get().strip() for k, v in self.vars.items()}
            source_machine_rows = []
            for index, row in enumerate(self.machine_rows):
                item = {key: value.get().strip() for key, value in row.items()}
                if index < len(self.machine_metadata):
                    item.update(self.machine_metadata[index])
                source_machine_rows.append(item)
        fields["Stamping office/site"] = self.stamping_place_var.get().strip()
        fields["Dormant / Other"] = self.site_status_var.get().strip() if fields["Stamping office/site"].casefold() == "site" else ""
        # The portal's establishment name is the company name parsed/reviewed
        # from the certificate. PAN identity and repairer identity are separate.
        # The PDF's M/S line is the source of truth for the establishment
        # name; don't let a stale secondary entry replace it (for example with
        # the state value copied by the portal's same-details checkbox).
        company_name = fields.get("Applicant / establishment name", "").strip() or fields.get("Applicant business name", "").strip()
        if company_name:
            fields["Applicant business name"] = company_name
            fields["Applicant / establishment name"] = company_name
        fields["PAN name"] = fields.get("PAN name", "") or self.pan_name.get().strip()
        fields["PAN number"] = fields.get("PAN number", "") or self.pan_number.get().strip()
        fields["PAN date"] = fields.get("PAN date", "") or self.pan_date.get().strip()
        fields["Repairer licence number"] = self.license_number.get().strip() or fields.get("Repairer licence number", "")
        fields["Repairer name"] = self.pan_name.get().strip() or fields.get("Repairer name", "")
        fields["Applicant contact name"] = fields.get("Applicant contact name", "") or self.contact_var.get().strip()
        fields["Registered name"] = fields.get("Registered name", "") or self.contact_var.get().strip()
        fields["Registered email"] = self.user_var.get().strip() or fields.get("Registered email", "")
        fields["Registered mobile"] = fields.get("Registered mobile", "") or self.mobile_var.get().strip()
        account_index = self.account_combo.current()
        account = self.accounts[account_index] if 0 <= account_index < len(self.accounts) else {}
        repairer_company = account.get("repairer_company_name", "").strip() or fields.get("Repairer business name", "").strip()
        repairer_mobile = account.get("repairer_mobile", "").strip() or fields.get("Repairer mobile", "").strip()
        repairer_contact = ", ".join(part for part in (repairer_company, repairer_mobile) if part)
        fields["Used by / trader contact"] = repairer_contact or self.repairer_establishment_var.get().strip() or fields.get("Used by / trader contact", "")
        image_payload = None
        account_index = self.account_combo.current()
        account = self.accounts[account_index] if 0 <= account_index < len(self.accounts) else {}
        encoded = account.get("pan_image_b64")
        if encoded:
            image_bytes = base64.b64decode(encoded)
            image_name = account.get("pan_image_name", "pan-card.jpg")
            image_payload = {"name": image_name, "mimeType": mimetypes.guess_type(image_name)[0] or "image/jpeg", "buffer": image_bytes}
        machine_rows = source_machine_rows
        # Preserve certificate order independently of the item grouping used
        # for the portal's machine tables. Each row carries its own page CV.
        machine_rows.sort(key=lambda row: int(row.get("Source PDF page", 0)))
        grouped = {}
        for row in machine_rows:
            description = row.get("Instrument description", "")
            key = normalize_text(description)
            if not key:
                continue
            group = grouped.setdefault(key, {"description": description, "quantity": 0, "machines": []})
            group["quantity"] += _item_count(row.get("Quantity", ""))
            group["machines"].append(row)
        return {
            "fields": fields,
            "machine_rows": machine_rows,
            "item_groups": list(grouped.values()),
            "certificate": self._portal_upload_path(),
            "authorization": self.files.get("authorization"),
            "pan_image_data": image_payload,
        }

    def submit_application(self):
        if not self.worker or not self.worker.is_alive():
            messagebox.showerror("Sign in first", "Log in through the app browser and prepare the application first.")
            return
        if not self.worker.ready_for_submit:
            messagebox.showerror("Finish the review pages first", "Use Start application or Fill now / retry and complete the portal pages through the final review page before submitting.")
            return
        if not messagebox.askyesno("Submit application", "Submit this completed application to the Tamil Nadu Labour Department?\n\nReview the portal pages first. This is the final application submission; the app will not make a payment."):
            return
        self.worker.send("submit")
        self.status.set("Submitting the reviewed application. No payment will be made.")

    def _sync_site_choice(self):
        if not hasattr(self, "site_status_combo"):
            return
        is_site = self.stamping_place_var.get().strip().casefold() == "site"
        self.site_status_combo.configure(state="readonly" if is_site else "disabled")
        if not is_site:
            self.site_status_var.set("Select")

    def _on_application_choice_changed(self, _event=None):
        self.draft_confirmed.set(False)
        self.draft_confirmation_status.set("Choices changed; confirm the draft again.")
        self._sync_site_choice()

    def confirm_draft(self):
        if not self.files.get("certificate") or not self.machine_rows:
            messagebox.showerror("Read the PDF first", "Choose the certificate, then select Read PDF and fill draft before confirming.")
            return
        if self.use_separate_upload_var.get() and not self.files.get("portal_upload"):
            messagebox.showerror(
                "Portal upload PDF required",
                "Choose the separate PDF that should be uploaded to the portal, or turn off the separate-upload option.",
            )
            return
        place = self.stamping_place_var.get().strip().casefold()
        if place not in {"office", "site"}:
            messagebox.showerror("Choose Office or Site", "Select whether this application is for Office or Site stamping before confirming the draft.")
            return
        if place == "site" and self.site_status_var.get().strip().casefold() not in {"dormant", "other"}:
            messagebox.showerror("Choose Dormant or Other", "For Site stamping, select Dormant or Other before confirming the draft.")
            return
        if not messagebox.askyesno("Confirm application draft", "Have you reviewed the PDF values, machine details, stamping location, and site Dormant/Other choice? Confirm only when the draft is ready to fill the portal."):
            return
        self.draft_confirmed.set(True)
        self.draft_confirmation_status.set("Draft confirmed. You can start or resume filling.")

    def _validate_draft_confirmation(self, show_error=True):
        if not self.draft_confirmed.get():
            if show_error:
                messagebox.showerror("Confirm the draft first", "Review the PDF values and select the confirmation box before starting or filling the application.")
            return False
        if self.use_separate_upload_var.get() and not self.files.get("portal_upload"):
            if show_error:
                messagebox.showerror(
                    "Portal upload PDF required",
                    "Choose the separate PDF that should be uploaded to the portal, or turn off the separate-upload option.",
                )
            return False
        place = self.stamping_place_var.get().strip().casefold()
        if place not in {"office", "site"}:
            if show_error:
                messagebox.showerror("Choose Office or Site", "Select whether this application is for Office or Site stamping before confirming the draft.")
            return False
        if place == "site" and self.site_status_var.get().strip().casefold() not in {"dormant", "other"}:
            if show_error:
                messagebox.showerror("Choose Dormant or Other", "For Site stamping, select Dormant or Other before confirming the draft.")
            return False
        return True

    def _poll(self):
        try:
            while True:
                pdf_kind, pdf_value = self.pdf_msgq.get_nowait()
                self._finish_pdf_read(pdf_kind, pdf_value)
        except queue.Empty:
            pass
        try:
            while True:
                kind, value = self.msgq.get_nowait()
                if kind == "error":
                    self.status.set(value)
                    if hasattr(self, "previous_info_status"):
                        self.previous_info_status.set(value)
                    self._show_copyable_error("Automation stopped", value)
                elif kind == "details":
                    self.status.set(f"Filled: {', '.join(value['filled']) or 'none'}. Uploaded: {', '.join(value['uploaded']) or 'none'}. Needs manual review: {', '.join(value['skipped']) or 'no unmatched fields reported'}.")
                    if hasattr(self, "previous_info_status") and value.get("workflow_step", 0) >= 2:
                        self.previous_info_status.set("Machine details page checked. First page address fields were left unchanged.")
                elif kind == "payment":
                    self.status.set(value)
                elif kind == "submitted":
                    self.status.set(value)
                elif kind == "login_ok":
                    self.status.set("Sign-in complete.")
                elif kind == "login_failed":
                    self.status.set(value); self._show_copyable_error("Sign-in failed", value)
                elif kind == "ready_to_submit":
                    self.status.set(value)
                elif kind == "multi_part_started":
                    self.application_part_combo.configure(state="disabled")
                    self.start_all_parts_button.configure(state="disabled")
                    self.new_application_button.configure(state="disabled")
                    self.status.set(f"Multi-part run active: {value} applications will use this signed-in Chromium session. Confirm each Submit manually; payment remains manual.")
                elif kind == "multi_part_part":
                    part_index, total_parts = value
                    if 0 <= part_index < len(self.application_part_states) and part_index != self.active_application_part:
                        self.application_part_combo.configure(state="readonly")
                        self.application_part_combo.current(part_index)
                        self._on_application_part_changed()
                        self.application_part_combo.configure(state="disabled")
                    self.status.set(f"Filling split application part {part_index + 1} of {total_parts} in the existing signed-in session.")
                elif kind == "multi_part_done":
                    self.application_part_combo.configure(state="readonly")
                    self.start_all_parts_button.configure(state="normal")
                    self.new_application_button.configure(state="normal")
                    self.status.set(value)
                elif kind == "progress":
                    self.status.set(value)
                else:
                    self.status.set(value)
        except queue.Empty: pass
        self.after(250, self._poll)


if __name__ == "__main__":
    App().mainloop()

