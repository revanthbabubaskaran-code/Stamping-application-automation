"""Tamil Nadu weighing machine stamping application helper.

All document parsing and profile storage happens locally. Portal interactions are
performed in the Chromium browser bundled with the app using Playwright.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import queue
import re
import threading
import mimetypes
import sys
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
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TNStampingAssistant"
VAULT_FILE = APP_DIR / "profile.vault"
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
    "Applicant contact name": "#applicant-name",
    "Registered name": "#userlogname",
    "Registered email": "#userlogemail",
    "Registered mobile": "#userlogemobile",
    "Repairer licence date": "#licencedate",
    "Stamping office/site": "#is-office",
    "Instrument description": "#stampinglabourmeasures-0-stamping-type-id",
    "Trader / establishment number": "#uid-number",
    "Used by / trader contact": "#trader-name",
}

LOCAL_ONLY_FIELDS = {
    "Business address", "Denomination", "Instrument make", "Instrument model", "Machine number",
    "Maximum capacity", "Minimum capacity", "Verification interval (e/d)", "Class", "Application number", "Dormant / Other",
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
    if not VAULT_FILE.exists():
        return {}
    return json.loads(unprotect(VAULT_FILE.read_bytes()).decode("utf-8"))


def save_vault(data: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    temp = VAULT_FILE.with_suffix(".tmp")
    temp.write_bytes(protect(json.dumps(data, ensure_ascii=False).encode("utf-8")))
    os.replace(temp, VAULT_FILE)


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
    """Read page text and table cells, omitting pages with only the TCPDF footer."""
    try:
        import pdfplumber
    except ImportError as exc:
        raise RuntimeError("PDF reading module is missing. Reinstall using the included setup instructions.") from exc
    result = []
    with pdfplumber.open(path) as pdf:
        page_count = len(pdf.pages)
        for page_number, page in enumerate(pdf.pages, 1):
            text = page.extract_text() or ""
            tables = page.extract_tables() or []
            meaningful = re.sub(r"(?im)^\s*powered\s+by\s+tcpdf.*$", "", text).strip()
            meaningful = re.sub(r"(?m)^\s*\d+\s*/\s*\d+\s*$", "", meaningful).strip()
            if meaningful or any(str(cell or "").strip() for table in tables for row in table for cell in row):
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
                "Instrument model": _clean_cell(first(r"Model\s*:\s*(.+)$", model_cell)),
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
        "Instrument model": first(r"Model\s*:\s*([^\n]+)", text),
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


def _clean_cell(value: str) -> str:
    value = (value or "").replace("–", "-").replace("—", "-").replace("−", "-").replace("�", " ")
    cleaned = re.sub(r"\s+", " ", value).strip(" .,:;\n")
    cleaned = re.sub(r"(?i)\bnon-\s+automatic\b", "Non-Automatic", cleaned)
    cleaned = re.sub(r"\(\s+", "(", cleaned)
    return re.sub(r"\bweigh\s+t\b", "weight", cleaned, flags=re.I)


def extract_certificate_document(path: str) -> tuple[int, int, dict[str, str], list[dict[str, str]]]:
    page_count, pages = read_certificate_pages(path)
    machines = []
    first_machine_page = None
    for page in pages:
        machine = _extract_machine_record(page["text"], page["tables"])
        if machine.get("Machine number") or machine.get("Instrument make") or _is_weights_item(machine.get("Instrument description", "")):
            machine["Previous CV number"] = first(r"CV\s*No\.?\s*:\s*([^\n]+)", page["text"])
            machine["Application number"] = first(r"Application\s+Number\s*:\s*([^\n]+)", page["text"])
            machine["Additional fee"] = first(r"50%\s+Additional\s+Fee\s*:\s*([\d,.]+)", page["text"]) or machine.get("Additional fee", "")
            machine["Stamping office/site"] = first(r"Stamping\s+at\s+(Office|Site)", page["text"])
            if first_machine_page is None:
                first_machine_page = page
            machines.append(machine)
    if not machines or first_machine_page is None:
        raise RuntimeError("No machine table was found in the PDF. Use a text-searchable previous CV or check the document.")
    values = extract_certificate(first_machine_page["text"], first_machine_page["tables"])
    values.update(machines[0])
    values["Repairer name"] = ""  # Filled from the selected PAN profile in the UI.
    if values.get("Stamping office/site", "").lower() == "site":
        fees = [re.sub(r"[^\d.]", "", row.get("Additional fee", "")) for row in machines]
        values["Dormant / Other"] = "Dormant" if fees and all(fee and float(fee) == 0 for fee in fees) else "Other"
    else:
        values["Dormant / Other"] = ""
    return page_count, len(pages), values, machines


def extract_certificate(text: str, tables=None) -> dict[str, str]:
    """Best-effort extraction. Never invent a value; unresolved fields stay blank."""
    values = {
        "Previous CV number": first(r"CV\s*No\.?\s*:\s*([^\n]+)", text),
        "Previous CV date": first(r"Date\s*:\s*([^\n]+)", text),
        "Applicant / establishment name": first(r"belonging to\s+M/S\s+(.+?)(?:,\s*Locality|\n)", text),
        "Instrument description": first(r"((?:Non-)?Automatic\s+.+?Class\s+(?:III|II|IV))\s*(?:\(|\n)", text),
        "Instrument make": first(r"Make\s*:\s*([^\n]+?)(?:\s+Max\s*:|\s+Model\s*:|\s+Machine\s+No\.?\s*:|\n)", text),
        "Instrument model": first(r"Model\s*:\s*([^\n]+?)(?:\s+Machine\s+No\.?\s*:|\s+Stamping Fee|\n)", text),
        "Machine number": first(r"Machine\s+No\.?\s*:\s*([^\n]+)", text),
        "Maximum capacity": first(r"Max\s*:\s*([^\n]+?)(?:\s+Min\s*:|\s+e/d\s*:|\n)", text),
        "Minimum capacity": first(r"Min\s*:\s*([^\n]+?)(?:\s+e/d\s*:|\n)", text),
        "Verification interval (e/d)": first(r"e/d\s*:\s*([^\n]+)", text),
        "Class": first(r"Class\s+(III|IIII|II|I)\b", text),
        "Quantity": first(r"(?:\n|Items\s+)\s*(?:\d+\s+)?(\d{1,3})\s+\d+(?:\s*[a-zA-Z]+)?\s+-", text),
        "Repairer name": first(r"Repaired by\s+(.+?)(?:,\s*\d|\n)", text),
        "Repairer licence number": first(r"Licence Number\s*:\s*([^\n.]+)", text),
        "Stamping office/site": first(r"Stamping\s+at\s+(Office|Site)", text),
    }
    # Source certificate includes owner locality; preserve locality as its address draft.
    raw_address = first(r"Locality\s+(.+?)(?=\s+Items\s+Quant|$)", text)
    values["Business address"] = raw_address
    values["State"] = "Tamil Nadu" if re.search(r"Tamil\s*Nadu", text, re.I) else ""
    parts = [p.strip() for p in raw_address.split(",") if p.strip()]
    taluk_at = next((i for i, part in enumerate(parts) if re.search(r"\btaluk\b", part, re.I)), -1)
    values["Taluk"] = re.sub(r"\s*taluk\s*", "", parts[taluk_at], flags=re.I).strip() if taluk_at >= 0 else ""
    values["District"] = parts[taluk_at + 1] if taluk_at >= 0 and len(parts) > taluk_at + 1 else ""
    values["Town / Village"] = parts[taluk_at - 1] if taluk_at > 0 else ""
    values["Street"] = parts[taluk_at - 2] if taluk_at > 2 else ""
    values["Door number"] = ", ".join(parts[:taluk_at - 2]) if taluk_at > 2 else ""
    values["Pincode"] = first(r"\b(\d{6})\b", raw_address)
    if not values["Street"]:
        street_candidates = [p for p in parts[1:taluk_at - 1] if re.search(r"road|street|salai|main", p, re.I)] if taluk_at > 1 else []
        values["Street"] = street_candidates[-1] if street_candidates else ""
    values["Repairer licence date"] = first(r"Licence Number\s*:\s*[^\n]*?(\d{2}[-/]\d{2}[-/]\d{4})", text)
    values["Repairer business name"] = first(r"Repaired by\s+(.+?)(?:,\s*\d|\n)", text)
    values["Trader / establishment number"] = first(r"Trader\s+No\.?\s*:\s*\n\s*([^\n]+)", text)
    values.update(_extract_machine_record(text, tables))
    return values


class PortalWorker(threading.Thread):
    """Owns a persistent Playwright session; user handles CAPTCHA and payment."""
    def __init__(self, messages: queue.Queue):
        super().__init__(daemon=True)
        self.messages = messages
        self.commands: queue.Queue = queue.Queue()
        self.page = None
        self.ready = threading.Event()
        self.pending_application = None
        self.ready_for_submit = False
        self.workflow_step = 0
        self.waiting_for_login = False
        self.login_attempt_at = 0.0
        self.last_captcha_value = ""
        self.captcha_candidate_value = ""
        self.captcha_candidate_since = 0.0

    def run(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.ready.set()
            self.messages.put(("error", "Playwright is not installed. Follow README setup/build steps."))
            return
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=False)
            except Exception as e:
                self.ready.set()
                self.messages.put(("error", f"Could not start the app's Chromium browser. Rebuild the app with the bundled browser.\n{e}"))
                return
            context = browser.new_context()
            self.page = context.new_page()
            self.page.set_default_timeout(9000)
            self.page.set_default_navigation_timeout(20000)
            self.ready.set()
            while True:
                try:
                    cmd, payload = self.commands.get(timeout=0.5)
                except queue.Empty:
                    if self.waiting_for_login:
                        if self._logged_in():
                            self.waiting_for_login = False
                            self.login_attempt_at = 0.0
                            self.messages.put(("login_ok", "Portal sign-in succeeded. Continue with Fill now / retry when the PDF draft is ready."))
                        else:
                            self._submit_login_after_captcha()
                            self._report_login_failure_if_due()
                        continue
                    if self.pending_application is not None:
                        if not self._logged_in():
                            self._submit_login_after_captcha()
                            self._report_login_failure_if_due()
                            continue
                        application = self.pending_application
                        self.pending_application = None
                        self.login_attempt_at = 0.0
                        try:
                            report = self._fill_form(application)
                            report["automatic"] = True
                            self.messages.put(("details", report))
                            if report["required_blank"]:
                                self.messages.put(("error", "The form is filled, but required fields remain blank. Complete those fields in the app browser; the application was not submitted."))
                            elif not report.get("final_submit_visible"):
                                self.messages.put(("error", "The portal did not reach a page with a visible Submit control. Review the fields reported as skipped, then use Fill now / retry; nothing was submitted."))
                            else:
                                self.ready_for_submit = True
                                self.messages.put(("ready_to_submit", "The application pages are filled through the final review page. Review them in the app browser, then use Submit to complete the application."))
                        except Exception as e:
                            self.messages.put(("error", f"Login was detected, but the automatic form steps stopped safely: {e}"))
                    continue
                if cmd == "stop":
                    break
                try:
                    if cmd == "open":
                        self.pending_application = payload.get("application")
                        self.waiting_for_login = True
                        self.ready_for_submit = False
                        self.workflow_step = 0
                        self._open_login_page()
                        self._fill_login(payload["credentials"])
                        self.messages.put(("opened", "Portal opened in bundled Chromium and saved sign-in filled. Enter the CAPTCHA there; the application will continue automatically if a PDF draft is ready."))
                    elif cmd == "fill":
                        if not self._logged_in():
                            self.pending_application = payload
                            self.waiting_for_login = True
                            self._open_login_page()
                            self._fill_login(payload.get("credentials", {}))
                            self.messages.put(("opened", "Portal opened in bundled Chromium. Enter the CAPTCHA; login and application filling will continue automatically."))
                        else:
                            report = self._fill_form(payload)
                            self.messages.put(("details", report))
                            if report["required_blank"]:
                                self.messages.put(("error", "The form is filled, but required fields remain blank. Complete those fields in the app browser; the application was not submitted."))
                            elif not report.get("final_submit_visible"):
                                self.messages.put(("error", "The portal did not reach a page with a visible Submit control. Review the fields reported as skipped, then use Fill now / retry; nothing was submitted."))
                            else:
                                self.ready_for_submit = True
                                self.messages.put(("ready_to_submit", "The application pages are filled through the final review page. Review them in the app browser, then use Submit to complete the application."))
                    elif cmd == "submit":
                        self._submit()
                    elif cmd == "credentials":
                        if not self._logged_in():
                            if self.pending_application is None:
                                self.pending_application = payload.get("application")
                            self._fill_login(payload["credentials"])
                            self.messages.put(("status", "Updated the login form with the edited saved credentials. Complete the CAPTCHA again to retry."))
                except Exception as e:
                    self.messages.put(("error", f"Portal action stopped safely: {e}"))
            try:
                context.close()
                browser.close()
            except Exception:
                pass

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
        if not self.is_alive():
            self.start()
            if not self.ready.wait(8):
                raise RuntimeError("Browser automation could not start.")
            if not self.is_alive():
                raise RuntimeError("Browser automation exited before Chromium became ready. Check the error shown in the app.")
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
        if page.locator('input[type="password"]:visible').count():
            return False
        for pattern in (r"log\s*out", r"dashboard", r"inbox"):
            if page.get_by_text(re.compile(pattern, re.I)).count():
                return True
        if page.get_by_text(re.compile(r"THE LEGAL METROLOGY ACT", re.I)).count():
            return True
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

    def _navigate_to_stamping_form(self):
        page = self.page
        if not self._logged_in():
            raise RuntimeError("Login is not detected yet. Complete the CAPTCHA and click Login in the app browser.")
        if page.locator("#Stamping").count() and page.locator("#Stamping").first.is_visible():
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
            except Exception:
                continue
        return None

    def _portal_field(self, field):
        """Prefer a visible known ID, then fall back to the portal's visible label."""
        selector = PORTAL_IDS.get(field)
        if selector:
            direct = self.page.locator(selector)
            try:
                if direct.count() and direct.first.is_visible():
                    return direct.first
            except Exception:
                pass
        return self._field_for(FIELD_LABELS.get(field, [field]))

    def _field_in_section(self, heading_pattern, label_pattern):
        scope = self._section_locator(heading_pattern)
        try:
            for label in scope.locator("label").all():
                if not label.is_visible():
                    continue
                label_text = self._norm(label.inner_text())
                if not re.fullmatch(label_pattern, label_text, re.I):
                    continue
                target_id = label.get_attribute("for")
                if target_id:
                    control = self.page.locator(f"#{target_id}")
                    if control.count() and control.first.is_visible():
                        return control.first
                nested = label.locator("input,select,textarea").first
                if nested.count() and nested.is_visible():
                    return nested
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

    def _fill_form(self, payload):
        self._navigate_to_stamping_form()
        self.ready_for_submit = False
        report = {"filled": [], "skipped": [], "uploaded": [], "required_blank": []}
        fields = payload["fields"]
        machines = payload.get("machine_rows") or [fields]
        groups = payload.get("item_groups") or self._group_items(machines)

        if self.workflow_step <= 0:
            self._fill_establishment_page(fields, machines, payload, report)
            self._collect_visible_required(report)
            if report["required_blank"]:
                return report
            self._click_next("item and previous-information page")
            self.workflow_step = 1

        if self.workflow_step <= 1:
            self._fill_items_and_previous_information(groups, machines, report["skipped"], report["filled"])
            filled_items = set(report["filled"])
            for index, _group in enumerate(groups, 1):
                if f"Item category {index}" not in filled_items:
                    report["required_blank"].append(f"Item category {index} was not selected")
                if not any(entry.startswith(f"Item quantity {index}:") for entry in filled_items):
                    report["required_blank"].append(f"Item quantity {index} total was not confirmed")
                if f"Previous Information Online {index}" not in filled_items:
                    report["required_blank"].append(f"Previous Information Online option for machine {index} was not selected")
                if f"Previous Information Application number {index}" not in filled_items:
                    report["required_blank"].append(f"Previous Information Application number for machine {index} was not filled")
                if f"Previous Information Certificate number {index}" not in filled_items:
                    report["required_blank"].append(f"Previous Information Certificate number for machine {index} was not filled")
            self._collect_visible_required(report)
            if report["required_blank"]:
                return report
            self._click_next("machine-details page")
            self.workflow_step = 2

        if self.workflow_step <= 2:
            self._fill_machine_detail_tables(groups, machines, report["skipped"], report["filled"])
            self._collect_visible_required(report)
            if report["required_blank"]:
                return report
            self._click_next("final application page")
            self.workflow_step = 3
        self._collect_visible_required(report)
        report["final_submit_visible"] = self._find_visible_submit() is not None
        return report

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

    def _fill_establishment_page(self, fields, machines, payload, report):
        page = self.page
        # Order first-page inputs, choices, and uploads by visible position.
        machine_kinds = {
            "Electronic" if "electronic" in row.get("Instrument description", "").lower()
            else "Mechanical" if "mechanical" in row.get("Instrument description", "").lower()
            else "Other"
            for row in machines if row.get("Instrument description")
        }
        new_goods_choice = next(iter(machine_kinds)) if len(machine_kinds) == 1 else "Other"
        new_goods = page.locator("#newgood")
        electronic_max = max((self._capacity_kg(row.get("Maximum capacity", "")) for row in machines if "electronic" in row.get("Instrument description", "").lower()), default=0)
        capacity_choice = "Above 3 tonnes" if electronic_max > 3000 else "Below 3 tonnes"
        actions = []
        establishment_labels = {
            "Applicant / establishment name": r"name",
            "State": r"state",
            "District": r"district",
            "Taluk": r"taluk",
            "Town / Village": r"town\s+village",
            "Street": r"street",
            "Door number": r"door\s+number",
            "Pincode": r"pincode|pin\s+code",
        }
        excluded = set(LOCAL_ONLY_FIELDS) | {"Applicant business name", "Used by / trader contact"}
        for field, value in fields.items():
            if not value or field in excluded:
                continue
            locator = (self._field_in_section(r"Establishment\s+Details", establishment_labels[field])
                       if field in establishment_labels else self._portal_field(field))
            try:
                if locator is None or not locator.count() or not locator.first.is_visible():
                    report["skipped"].append(f"{field} (control not found or not visible)")
                    continue
                if not locator.first.is_editable():
                    report["skipped"].append(f"{field} (read-only; populated by the portal)")
                    continue
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
        establishment_controls = [control for control in self._controls_matching(manufacturer_scope, r"establishment\s*name")
                                  if (control.get_attribute("id") or "").lower() != "establishmentname"]
        if applicant_name and establishment_controls:
            control = establishment_controls[0]
            try:
                actions.append((float(control.evaluate("el => el.getBoundingClientRect().top")), "Manufacturer / Trader establishment name", control, applicant_name, "field"))
            except Exception as exc:
                report["skipped"].append(f"Manufacturer / Trader establishment name: {exc}")
        elif applicant_name:
            report["skipped"].append("Manufacturer / Trader establishment name (control not found)")

        used_by = page.locator("#trader-name")
        if used_by.count():
            try:
                actions.append((float(used_by.first.evaluate("el => el.getBoundingClientRect().top")), "Repaired by / Used by", used_by.first, "", "license-establishment"))
            except Exception as exc:
                report["skipped"].append(f"Repaired by / Used by: {exc}")
        else:
            report["skipped"].append("Repaired by / Used by (control not found)")

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

        if fields.get("Stamping office/site", "").lower() == "site":
            dormant = self._field_for(["Dormant / Other", "Dormant / other", "Dormant"])
            if dormant is not None and dormant.count():
                try:
                    actions.append((float(dormant.first.evaluate("el => el.getBoundingClientRect().top")), "Site Dormant / Other choice", dormant.first, fields.get("Dormant / Other", "Other"), "field"))
                except Exception as exc:
                    report["skipped"].append(f"Site Dormant / Other choice: {exc}")
            else:
                report["skipped"].append("Site Dormant / Other choice (control not found)")

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
        pending_actions = sorted(actions, key=lambda action: action[0])
        while pending_actions:
            _top, field, locator, value, action_type = pending_actions.pop(0)
            try:
                # Form entry uses fill/select/check APIs; Enter is never sent to the portal.
                if field == "New goods / machine type choice":
                    if self._select_best(locator, value):
                        page.wait_for_timeout(350)
                        report["filled"].append(field)
                        if new_goods_choice == "Electronic":
                            capacity = page.locator("#tonnes")
                            if capacity.count() and capacity.first.is_visible():
                                top = float(capacity.first.evaluate("el => el.getBoundingClientRect().top"))
                                pending_actions.append((top, "Weighing machine capacity range", capacity.first, capacity_choice, "field"))
                                pending_actions.sort(key=lambda action: action[0])
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
                if action_type == "license-establishment":
                    license_establishment = page.locator("#establishmentname")
                    license_name = license_establishment.input_value().strip() if license_establishment.count() else ""
                    value = license_name or fields.get("Used by / trader contact", "")
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
                if locator.evaluate("el => el.tagName.toLowerCase()") == "select":
                    selected = self._select_best(locator, value)
                    if not selected and field in {"District", "Taluk", "Town / Village", "Street", "Weighing machine capacity range"}:
                        deadline = time.monotonic() + 25
                        while time.monotonic() < deadline and not selected:
                            page.wait_for_timeout(300)
                            if locator.is_enabled() and locator.evaluate("el => !el.options || el.options.length > 1"):
                                selected = self._select_best(locator, value)
                    if not selected:
                        report["skipped"].append(f"{field} (no matching enabled option for {value})")
                        continue
                elif not self._fill_control(locator, value):
                    report["skipped"].append(f"{field} (could not select {value})")
                    continue
                if field == "Repairer licence number":
                    page.wait_for_timeout(1400)
                elif field in {"State", "District", "Taluk", "Town / Village", "Street"}:
                    page.wait_for_timeout(1200 if field in {"District", "Taluk"} else 700)
                if field in {"Repairer licence number", "Previous CV number", "Previous CV date"} and not self._field_value_matches(locator, value):
                    report["skipped"].append(f"{field} (portal value did not persist after filling)")
                    continue
                report["filled"].append(field)
            except Exception as exc:
                report["skipped"].append(f"{field}: {exc}")

        if "Site Dormant / Other choice (control not found)" in report["skipped"]:
            pass
        elif fields.get("Stamping office/site", "").lower() == "site" and "Site Dormant / Other choice" not in report["filled"]:
            report["skipped"].append("Site Dormant / Other choice")

        critical_fields = (
            "Applicant / establishment name", "Stamping office/site", "Repairer licence number", "Repairer name",
            "Previous CV number", "Previous CV date", "State", "District", "Taluk", "Town / Village",
            "Street", "Door number", "Pincode", "PAN name", "PAN number", "PAN date",
        )
        filled_names = set(report["filled"])
        for field in ("New goods / machine type choice", "Stamping purpose: Re-verification", "Applicant licence type: Repairer"):
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
            # Fall back to checkbox labels whose text includes the requested phrase.
            for label in self.page.locator("label").all():
                try:
                    if re.search(r"Same Details for Manufacturer\s*/\s*Trader\s*/\s*Establishment", label.inner_text(), re.I):
                        control = label.locator("input[type=checkbox]").first
                        if control.count(): return control
                except Exception:
                    continue
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
        next_button.click(timeout=10000)
        try:
            page.wait_for_load_state("domcontentloaded", timeout=12000)
        except Exception:
            pass
        page.wait_for_timeout(1000)
        if page.url == previous_url and not re.search(r"submit|review|application", " ".join(visible_labels), re.I):
            page.wait_for_timeout(900)

    def _collect_visible_required(self, report):
        try:
            blank = self.page.locator("input[required]:visible,select[required]:visible,textarea[required]:visible").evaluate_all(
                "els => els.filter(e => !e.disabled && !e.readOnly && ((e.type === 'checkbox' || e.type === 'radio') ? !e.checked : !e.value)).map(e => e.id || e.name || e.type)"
            )
            report["required_blank"] = list(dict.fromkeys(report["required_blank"] + blank))
            report["skipped"].extend(f"Required field left blank: {name}" for name in blank if f"Required field left blank: {name}" not in report["skipped"])
        except Exception:
            pass

    def _section_locator(self, heading_text):
        page = self.page
        heading = page.get_by_text(re.compile(heading_text, re.I)).first
        try:
            if heading.count():
                for depth in range(1, 8):
                    scope = heading.locator("xpath=" + "/".join([".."] * depth))
                    if scope.locator("input,select,textarea,button,a,[role='button']").count():
                        return scope
        except Exception:
            pass
        return page.locator("body")

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
                add.click()
                deadline = time.monotonic() + 8
                updated = current
                while time.monotonic() < deadline and updated <= current:
                    self.page.wait_for_timeout(200)
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
            for control in scope.locator("input,select,textarea").all():
                if not control.is_visible():
                    continue
                metadata = control.evaluate("el => [...(el.labels || [])].map(label => label.innerText).join(' ')")
                metadata = " ".join(filter(None, [metadata, control.get_attribute("id"), control.get_attribute("name"), control.get_attribute("placeholder"), control.get_attribute("aria-label"), control.get_attribute("title")]))
                if re.search(pattern, metadata, re.I):
                    matches.append(control)
        except Exception:
            pass
        return matches

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
        return True

    def _fill_items_and_previous_information(self, groups, machines, skipped, filled):
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
                    page.wait_for_timeout(400)
                    if _is_weights_item(group["description"]):
                        weight = next((machine.get("Weights", "") or machine.get("Denomination", "") for machine in group.get("machines", []) if machine.get("Weights") or machine.get("Denomination")), "")
                        if weight:
                            page.wait_for_timeout(350)
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
                    page.wait_for_timeout(150)
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
        app_pattern = r"application\s*(?:number|no\b)"
        cv_pattern = r"(?:certificate|previous\s*cv|cv)\s*(?:number|no\b)"
        model_pattern = r"\bmodel\s*(?:name)?\b"
        def online_controls():
            controls = []
            for control in previous_scope.locator("select:visible").all():
                try:
                    options = [self._norm(option.inner_text()) for option in control.locator("option").all()]
                    if any(label == "online" or "online other state" in label for label in options):
                        controls.append(control)
                except Exception:
                    continue
            return controls

        def wait_for_count(getter, required, timeout=12):
            deadline = time.monotonic() + timeout
            current = getter()
            while len(current) < required and time.monotonic() < deadline:
                page.wait_for_timeout(250)
                current = getter()
            return current

        states = wait_for_count(online_controls, 1)
        if not states:
            skipped.append("Previous Information: Online/Other State control not found")
            return

        for index, machine in enumerate(machines):
            states = online_controls()
            if index == 0:
                state_control = states[0] if states else None
            else:
                model_index = index - 1
                models = self._controls_matching(previous_scope, model_pattern)
                if len(models) <= model_index and len(states) <= index:
                    add = self._add_button(previous_scope)
                    if add is not None:
                        try:
                            add.click()
                            page.wait_for_timeout(350)
                        except Exception as exc:
                            skipped.append(f"Previous Information: could not add machine section {index + 1}: {exc}")
                    else:
                        skipped.append(f"Previous Information: Add More control not found for machine {index + 1}")
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        models = self._controls_matching(previous_scope, model_pattern)
                        states = online_controls()
                        if len(models) > model_index or len(states) > index:
                            break
                        page.wait_for_timeout(250)

                models = self._controls_matching(previous_scope, model_pattern)
                if len(models) > model_index:
                    model_control = models[model_index]
                    model_value = machine.get("Instrument description", "")
                    selected_model = self._select_best(model_control, model_value)
                    if not selected_model:
                        selected_model = self._select_first_available(model_control)
                    if selected_model:
                        filled.append(f"Previous Information Model {index + 1}")
                    else:
                        skipped.append(f"Previous Information Model for machine {index + 1}")
                    states = wait_for_count(online_controls, index + 1)
                state_control = states[index] if len(states) > index else None

            if state_control is None or not self._select_best(state_control, "Online"):
                skipped.append(f"Previous Information Online option for machine {index + 1}")
                continue
            filled.append(f"Previous Information Online {index + 1}")
            page.wait_for_timeout(350)

            apps = wait_for_count(lambda: self._controls_matching(previous_scope, app_pattern), index + 1)
            cvs = wait_for_count(lambda: self._controls_matching(previous_scope, cv_pattern), index + 1)
            app_no = machine.get("Application number", "")
            cv_no = machine.get("Previous CV number", "")
            for label, controls, value in (("Application number", apps, app_no), ("Certificate number", cvs, cv_no)):
                if index >= len(controls) or not value:
                    skipped.append(f"Previous Information {label} for machine {index + 1}")
                    continue
                try:
                    control = controls[index]
                    if self._fill_control(control, value) and self._field_value_matches(control, value):
                        filled.append(f"Previous Information {label} {index + 1}")
                    else:
                        skipped.append(f"Previous Information {label} for machine {index + 1} (value did not persist)")
                except Exception as exc:
                    skipped.append(f"Previous Information {label} for machine {index + 1}: {exc}")

            # Certificate date is computed by the portal after both identifiers.
            dates = self._controls_matching(previous_scope, r"certificate\s*date|previous\s*cv\s*date")
            if index < len(dates):
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        if dates[index].input_value().strip():
                            break
                    except Exception:
                        break
                    page.wait_for_timeout(300)

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
        try:
            for table in page.locator("table").all():
                rows = table.locator("tr").all()
                header_row = None
                headers = []
                for row in rows[:3]:
                    cells = row.locator("th,td").all_inner_texts()
                    joined = self._norm(" ".join(cells))
                    has_weight_column = bool(re.search(r"denomination|weight", joined, re.I))
                    if sum(bool(re.search(pattern, joined, re.I)) for pattern in (r"denomination|weight", r"class", r"max", r"min", r"e\s*d|division", r"make|manufacturer", r"model", r"machine|serial")) >= 3 or (weights_only and has_weight_column):
                        header_row, headers = row, cells
                        break
                if header_row is None:
                    continue
                data_rows = [row for row in rows if row.locator("input,select,textarea").count()]
                data_rows = [row for row in data_rows if row != header_row]
                if not data_rows:
                    continue
                tables.append((table, headers, data_rows))
        except Exception:
            tables = []
        if not tables:
            skipped.append("Machine details: could not identify the portal table columns; review and enter machine rows manually")
            return

        grouped_rows = [group.get("machines", []) for group in groups]
        flat_rows = [row for group in grouped_rows for row in group]
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
                        add.click(); page.wait_for_timeout(450)
                    except Exception:
                        break
                    updated = data_rows_for(table)
                    if len(updated) <= len(current_rows):
                        break
                    current_rows = updated
            else:
                current_rows = data_rows_for(table)
            if len(current_rows) < expected:
                skipped.append(f"Machine details: portal table has {len(current_rows)} row(s), needs {expected}")
            expanded.append((table, headers, current_rows))
        tables = expanded
        pattern_map = {
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
                if not field:
                    continue
                value = machine.get("Weights", "") or machine.get("Denomination", "") if field == "Denomination" else machine.get(field, "")
                if field == "Previous CV number":
                    value = machine.get("Previous CV number", "")
                if _is_weights_item(machine.get("Instrument description", "")) and field not in {"Denomination", "Previous CV number"}:
                    continue
                controls = cell.locator("input,select,textarea")
                if not value or not controls.count():
                    continue
                try:
                    if self._fill_control(controls.first, value):
                        found.add(field)
                        filled.append(f"Machine {machine_index + 1} {field}")
                except Exception:
                    pass
            return found

        cursor = 0
        if len(tables) == 1:
            table, headers, data_rows = tables[0]
            for row_idx, row_locator in enumerate(data_rows[:len(flat_rows)]):
                found = fill_row(row_locator, headers, flat_rows[row_idx], row_idx)
                for key in pattern_map:
                    if flat_rows[row_idx].get(key) and key not in found:
                        skipped.append(f"Machine {row_idx + 1} {key}")
            if len(data_rows) < len(flat_rows):
                skipped.append(f"Machine detail table has {len(data_rows)} row(s); needs {len(flat_rows)}")
            return

        for table, headers, data_rows in tables:
            group_rows = grouped_rows[cursor] if cursor < len(grouped_rows) else []
            for row_idx, row_locator in enumerate(data_rows[:len(group_rows)]):
                machine = group_rows[row_idx]
                global_index = flat_rows.index(machine)
                found = fill_row(row_locator, headers, machine, global_index)
                for key in pattern_map:
                    if machine.get(key) and key not in found:
                        skipped.append(f"Machine {global_index + 1} {key}")
            cursor += 1

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
                value = option.get_attribute("value")
                if label and value is not None and label.lower() != "select":
                    options.append((label, value))
            except Exception:
                pass
        if not options:
            return False
        norm = self._norm(target)
        exact = [o for o in options if self._norm(o[0]) == norm]
        if len(exact) == 1:
            locator.select_option(value=exact[0][1]); return True
        partial = [o for o in options if norm in self._norm(o[0]) or self._norm(o[0]) in norm]
        if len(partial) == 1:
            locator.select_option(value=partial[0][1]); return True
        scored = sorted(((SequenceMatcher(None, norm, self._norm(label)).ratio(), label, value) for label, value in options), reverse=True)
        if scored and scored[0][0] >= 0.62 and (len(scored) == 1 or scored[0][0] - scored[1][0] >= 0.08):
            locator.select_option(value=scored[0][2]); return True
        return False

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

    def _submit(self):
        page = self.page
        payment_text = re.compile(r"make payment|proceed to payment|pay now|payment gateway|payment successful", re.I)
        if re.search(r"payment|receipt|checkout", page.url, re.I) or page.get_by_text(payment_text).count():
            self.messages.put(("payment", "The portal is already at a payment step. The assistant will not interact with payment."))
            return
        if not self.ready_for_submit:
            raise RuntimeError("The application has not reached a verified final review page. Use Fill now / retry to complete the visible page first.")
        submit = self._find_visible_submit()
        if submit is None:
            raise RuntimeError("No visible Submit control is present on the current portal page. The application was not submitted; continue filling the current page.")
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


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1030x820")
        self.minsize(900, 690)
        self.theme_is_dark = None
        self._theme_widgets_applied = False
        self.msgq: queue.Queue = queue.Queue()
        self.worker: PortalWorker | None = None
        self.profile = {}
        try:
            self.profile = load_vault()
        except Exception as e:
            messagebox.showerror("Profile could not be opened", f"Encrypted profile could not be read. It may belong to another Windows user.\n\n{e}")
        self.files = {"certificate": "", "authorization": ""}
        self.vars = {}
        self.machine_rows = []
        self.machine_metadata = []
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
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 8))

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
        style.configure("TLabel", background=p["bg"], foreground=p["fg"], font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=p["bg"], foreground=p["title"], font=("Segoe UI Semibold", 20))
        style.configure("Sub.TLabel", background=p["bg"], foreground=p["muted"], font=("Segoe UI", 10))
        style.configure("Section.TLabel", background=p["card"], foreground=p["title"], font=("Segoe UI Semibold", 12))
        style.configure("Card.TLabel", background=p["card"], foreground=p["fg"])
        style.configure("Muted.Card.TLabel", background=p["card"], foreground=p["muted"])
        style.configure("TEntry", fieldbackground=p["input"], foreground=p["fg"], bordercolor=p["border"])
        style.configure("TCombobox", fieldbackground=p["input"], background=p["card"], foreground=p["fg"], arrowcolor=p["fg"])
        style.map("TCombobox", fieldbackground=[("readonly", p["input"])], foreground=[("readonly", p["fg"])], selectbackground=[("readonly", p["selection"])], selectforeground=[("readonly", p["fg"])])
        style.configure("Primary.TButton", background=p["accent"], foreground="white")
        style.map("Primary.TButton", background=[("active", p["accent_active"])])
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
                widget.configure(bg=p["card"] if current_bg.lower() in ("white", "#ffffff") else p["bg"], fg=p["muted"] if str(widget.cget("fg")).lower() in ("#62738a", "#6c7b8d") else p["fg"])
        except tk.TclError:
            pass
        for child in widget.winfo_children():
            self._retheme_widgets(child, previous)
        self._theme_widgets_applied = True

    def _refresh_system_theme(self):
        self._apply_theme(self._system_dark_mode())
        self.after(1600, self._refresh_system_theme)

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

    def _build(self):
        outer = ttk.Frame(self, padding=22)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="TN Stamping Assistant", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Read a previous certificate, prepare the stamping form, and review before submission.", style="Sub.TLabel").pack(anchor="w", pady=(2, 16))
        canvas = tk.Canvas(outer, bg=self.palette["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas)
        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw", width=960)
        canvas.configure(yscrollcommand=scrollbar.set)
        self.scroll_canvas = canvas
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
        self.account_combo = ttk.Combobox(row, textvariable=self.account_var, state="readonly", width=48)
        self.account_combo.pack(side="left", fill="x", expand=True)
        self.account_combo.bind("<<ComboboxSelected>>", self._on_account_selected)
        ttk.Button(row, text="Add account", command=self.add_account, style="Primary.TButton").pack(side="left", padx=(10, 0))
        ttk.Button(row, text="Edit credentials", command=self.edit_account).pack(side="left", padx=(8, 0))

        docs = self._card(body, "Documents")
        self._file_row(docs, "Purchase invoice / Previous CV (PDF)", "certificate", ("PDF files", "*.pdf"))
        self._file_row(docs, "Authorisation letter from user / owner", "authorization", ("PDF or image", "*.pdf *.jpg *.jpeg *.png"))
        ttk.Label(docs, text="PAN card image is uploaded from the selected account. Portal file uploads must be under 1 MB.", style="Muted.Card.TLabel").pack(anchor="w", pady=(8, 0))

        first_page = self._card(body, "Application review — applicant and first page")
        ttk.Button(first_page, text="Read PDF and fill draft", command=self.read_pdf, style="Primary.TButton").pack(anchor="w", pady=(8, 6))
        self.first_page_field_frame = ttk.Frame(first_page, style="Card.TFrame")
        self.first_page_field_frame.pack(fill="x")

        machine = self._card(body, "Machine details — certificate table")
        ttk.Label(machine, text="Review or correct each machine row read from the certificate pages.", style="Muted.Card.TLabel").pack(anchor="w", pady=(4, 8))
        self.machine_field_frame = ttk.Frame(machine, style="Card.TFrame")
        self.machine_field_frame.pack(fill="x")
        self.pan_name = tk.StringVar(); self.pan_number = tk.StringVar(); self.pan_date = tk.StringVar(); self.license_number = tk.StringVar()
        self.repairer_establishment_var = tk.StringVar()
        self._set_fields({})

        action = ttk.Frame(body, style="Card.TFrame", padding=14); action.pack(fill="x", pady=(12, 5))
        ttk.Button(action, text="Start application", command=self.open_portal, style="Primary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(action, text="Fill now / retry", command=self.fill_application).pack(side="left", padx=8)
        ttk.Button(action, text="Submit application", command=self.submit_application).pack(side="left", padx=8)
        self.status = tk.StringVar(value="Ready. Choose documents, review the PDF draft, then open the portal.")
        ttk.Label(body, textvariable=self.status, style="Sub.TLabel", wraplength=930).pack(anchor="w", pady=(10, 0))

    def _card(self, parent, title):
        card = ttk.Frame(parent, style="Card.TFrame", padding=16)
        card.pack(fill="x", pady=(0, 12))
        ttk.Label(card, text=title, style="Section.TLabel").pack(anchor="w")
        return card

    def _file_row(self, parent, label, key, file_filter):
        frame = ttk.Frame(parent, style="Card.TFrame"); frame.pack(fill="x", pady=(8, 0))
        ttk.Label(frame, text=label, width=40, style="Card.TLabel").pack(side="left")
        display = tk.StringVar(value="No file selected")
        self.files[key + "_display"] = display
        ttk.Label(frame, textvariable=display, style="Muted.Card.TLabel").pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(frame, text="Choose file", command=lambda: self.choose_file(key, file_filter)).pack(side="right")

    def choose_file(self, key, file_filter):
        path = filedialog.askopenfilename(filetypes=[file_filter, ("All files", "*.*")])
        if path:
            self.files[key] = path
            self.files[key + "_display"].set(Path(path).name)

    def _set_fields(self, values, machine_data=None):
        for frame in (self.first_page_field_frame, self.machine_field_frame):
            for widget in frame.winfo_children(): widget.destroy()
        self.vars.clear()
        self.machine_rows = []
        self.machine_metadata = []
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
        for col, name in enumerate(machine_keys):
            ttk.Label(self.machine_field_frame, text=machine_headers.get(name, name), style="Card.TLabel", wraplength=105, anchor="center").grid(row=0, column=col, sticky="nsew", padx=2, pady=(0, 4))
            self.machine_field_frame.columnconfigure(col, weight=1, uniform="machine")
        records = machine_data or [{name: values.get(name, "") for name in machine_keys}]
        for machine_index, record in enumerate(records):
            label_row = 1 + machine_index * 2
            field_row = label_row + 1
            machine_type = record.get("Instrument description", "")
            certificate_no = record.get("Previous CV number", "")
            title = f"Machine {machine_index + 1}" + (f" — {machine_type}" if machine_type else "")
            if certificate_no:
                title += f" (CV {certificate_no})"
            ttk.Label(self.machine_field_frame, text=title, style="Muted.Card.TLabel", wraplength=920, justify="left").grid(row=label_row, column=0, columnspan=len(machine_keys), sticky="w", padx=2, pady=(6, 0))
            row_vars = {}
            for col, name in enumerate(machine_keys):
                var = tk.StringVar(value=record.get(name, ""))
                row_vars[name] = var
                ttk.Entry(self.machine_field_frame, textvariable=var, width=11).grid(row=field_row, column=col, sticky="ew", padx=2, pady=2)
                if machine_index == 0:
                    self.vars[name] = var
            self.machine_rows.append(row_vars)
            self.machine_metadata.append({key: value for key, value in record.items() if key not in machine_keys})
        for name in FIELD_LABELS:
            if name in MACHINE_REVIEW_FIELDS:
                continue
            frame = self.first_page_field_frame
            idx = first_idx
            var = tk.StringVar(value=values.get(name, ""))
            self.vars[name] = var
            ttk.Label(frame, text=name, style="Card.TLabel").grid(row=idx, column=0, sticky="w", pady=3, padx=(0, 10))
            ttk.Entry(frame, textvariable=var, width=75).grid(row=idx, column=1, sticky="ew", pady=3)
            first_idx += 1
        self.first_page_field_frame.columnconfigure(1, weight=1)
        if self.pan_name.get(): self.vars["PAN name"].set(self.pan_name.get())
        if self.pan_number.get(): self.vars["PAN number"].set(self.pan_number.get())
        if self.pan_date.get(): self.vars["PAN date"].set(self.pan_date.get())
        if self.license_number.get(): self.vars["Repairer licence number"].set(self.license_number.get())

    def read_pdf(self):
        path = self.files.get("certificate")
        if not path:
            messagebox.showinfo("Choose the previous certificate", "Select the previous CV or purchase invoice PDF first.")
            return
        try:
            page_count, meaningful_page_count, values, machines = extract_certificate_document(path)
            if not machines:
                messagebox.showwarning("No selectable text found", "This PDF appears to be a scan. Use a text-searchable PDF; OCR is not included in this local build.")
                return
            values.update({"Applicant business name": values.get("Applicant / establishment name", ""), "Applicant contact name": self.contact_var.get(), "Registered name": self.contact_var.get(), "Registered email": self.user_var.get(), "Registered mobile": self.mobile_var.get(), "Used by / trader contact": self.business_var.get() or values.get("Repairer business name", ""), "PAN name": self.pan_name.get(), "PAN number": self.pan_number.get(), "PAN date": self.pan_date.get(), "Repairer name": self.pan_name.get(), "Repairer licence number": self.license_number.get()})
            self.repairer_establishment_var.set(self.business_var.get() or values.get("Repairer business name", ""))
            self._set_fields(values, machines)
            ignored = page_count - meaningful_page_count
            self.status.set(f"Draft read from {Path(path).name}: {page_count} pages, {len(machines)} machine(s), {ignored} blank/footer page(s) ignored. Review every value before filling the portal.")
        except Exception as e:
            messagebox.showerror("Could not read PDF", str(e))

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
                messagebox.showerror("Could not migrate saved account", str(exc))

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
            if self.vars:
                self.vars["PAN name"].set(self.pan_name.get())
                self.vars["PAN number"].set(self.pan_number.get())
                self.vars["PAN date"].set(self.pan_date.get())
                self.vars["Repairer licence number"].set(self.license_number.get())

    def edit_account(self):
        index = self.account_combo.current()
        if index < 0 or index >= len(self.accounts):
            messagebox.showinfo("Choose an account", "Select an email from the dropdown before editing its credentials.")
            return
        self.add_account(edit_index=index)

    def add_account(self, edit_index=None):
        window = tk.Toplevel(self)
        window.title("Edit portal account" if edit_index is not None else "Add portal account")
        window.transient(self)
        window.grab_set()
        window.geometry("540x690")
        pad = ttk.Frame(window, padding=18); pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Portal sign-in and matching PAN profile", style="Section.TLabel").pack(anchor="w")
        ttk.Label(pad, text="All details and the PAN image are encrypted together for this email account.", style="Sub.TLabel", wraplength=480).pack(anchor="w", pady=(4, 12))

        email_var = tk.StringVar(); password_var = tk.StringVar()
        pan_name_var = tk.StringVar(); pan_number_var = tk.StringVar(); pan_date_var = tk.StringVar()
        license_var = tk.StringVar(); image_label = tk.StringVar(value="No PAN image selected")
        image_data = {"b64": "", "name": ""}
        loaded_email = {"value": ""}
        fields = ttk.Frame(pad); fields.pack(fill="x")
        entries = (
            ("Registered email address", email_var, ""), ("Portal password", password_var, "•"),
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
                    messagebox.showwarning("Image too large", "The portal accepts uploaded files up to 1 MB. Choose a smaller PAN image.", parent=window)
                    return
                image_data["b64"] = base64.b64encode(content).decode("ascii")
                image_data["name"] = Path(path).name
                image_label.set(Path(path).name)
            except OSError as exc:
                messagebox.showerror("Could not read PAN image", str(exc), parent=window)

        ttk.Label(pad, text="PAN card image").pack(anchor="w", pady=(8, 2))
        image_row = ttk.Frame(pad); image_row.pack(fill="x")
        ttk.Label(image_row, textvariable=image_label, style="Sub.TLabel").pack(side="left", fill="x", expand=True)
        ttk.Button(image_row, text="Choose JPG / PNG", command=choose_pan_image).pack(side="right")

        def load_existing(_event=None):
            email = email_var.get().strip().casefold()
            existing = next((item for item in self.accounts if item.get("username", "").casefold() == email), None)
            if not existing:
                if edit_index is None and loaded_email["value"] and loaded_email["value"] != email:
                    password_var.set(""); pan_name_var.set(""); pan_number_var.set("")
                    pan_date_var.set(""); license_var.set("")
                    image_data["b64"] = ""; image_data["name"] = ""
                    image_label.set("No PAN image selected")
                    loaded_email["value"] = ""
                return
            loaded_email["value"] = email
            password_var.set(existing.get("password", ""))
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
                messagebox.showwarning("Missing sign-in", "Enter the registered email and portal password.", parent=window)
                return
            if not pan_name_var.get().strip() or not pan_number_var.get().strip() or not pan_date_var.get().strip() or not image_data["b64"]:
                messagebox.showwarning("PAN profile incomplete", "Enter the PAN name, number, and date, and choose a PAN card image.", parent=window)
                return
            old_accounts = self.accounts
            match_index = next((i for i, item in enumerate(self.accounts) if item.get("username", "").casefold() == email.casefold()), None)
            if edit_index is not None:
                duplicate = match_index is not None and match_index != edit_index
                if duplicate:
                    messagebox.showwarning("Email already saved", "That email belongs to another saved account. Use a unique email address.", parent=window)
                    return
                match_index = edit_index
            record = dict(self.accounts[match_index]) if match_index is not None else {}
            record.update({
                "username": email, "password": password,
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
                messagebox.showerror("Could not save account", str(exc), parent=window)
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
            messagebox.showwarning("Sign-in needed", "Choose an email from the dropdown or add an account.")
            return
        self._ensure_worker()
        has_draft = bool(self.machine_rows and self.files.get("certificate"))
        try:
            self.worker.send("open", {"credentials": {"username": self.user_var.get(), "password": self.pass_var.get()}, "application": self._application_payload() if has_draft else None})
            self.status.set("Opening bundled Chromium and filling saved sign-in. Enter the CAPTCHA in that window; a reviewed PDF draft will continue automatically after login." if has_draft else "Opening bundled Chromium and filling saved sign-in. Enter the CAPTCHA there. Read the PDF draft, then choose Fill now / retry after login.")
        except Exception as exc:
            self.status.set(f"Could not start Chromium: {exc}")
            messagebox.showerror("Could not start Chromium", str(exc))

    def _ensure_worker(self):
        if not self.worker or not self.worker.is_alive(): self.worker = PortalWorker(self.msgq)

    def fill_application(self):
        self._on_account_selected()
        if not self.user_var.get() or not self.pass_var.get():
            messagebox.showwarning("Sign-in needed", "Choose an email from the dropdown or add an account.")
            return
        if not self.files.get("certificate") or not self.machine_rows:
            messagebox.showwarning("PDF draft required", "Choose the previous CV PDF and select Read PDF and fill draft first.")
            return
        self._ensure_worker()
        payload = self._application_payload()
        payload["credentials"] = {"username": self.user_var.get(), "password": self.pass_var.get()}
        try:
            self.worker.send("fill", payload)
            self.status.set("Filling the application in bundled Chromium. If you are not signed in, the browser will open for CAPTCHA first.")
        except Exception as exc:
            self.status.set(f"Could not start Chromium: {exc}")
            messagebox.showerror("Could not start Chromium", str(exc))

    def _application_payload(self):
        fields = {k: v.get().strip() for k, v in self.vars.items()}
        # The portal's establishment name is the company name parsed/reviewed
        # from the certificate. PAN identity and repairer identity are separate.
        company_name = fields.get("Applicant business name", "").strip() or fields.get("Applicant / establishment name", "").strip()
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
        fields["Used by / trader contact"] = self.repairer_establishment_var.get().strip() or fields.get("Used by / trader contact", "") or self.business_var.get().strip()
        image_payload = None
        account_index = self.account_combo.current()
        account = self.accounts[account_index] if 0 <= account_index < len(self.accounts) else {}
        encoded = account.get("pan_image_b64")
        if encoded:
            image_bytes = base64.b64decode(encoded)
            image_name = account.get("pan_image_name", "pan-card.jpg")
            image_payload = {"name": image_name, "mimeType": mimetypes.guess_type(image_name)[0] or "image/jpeg", "buffer": image_bytes}
        machine_rows = []
        for index, row in enumerate(self.machine_rows):
            item = {key: value.get().strip() for key, value in row.items()}
            if index < len(self.machine_metadata):
                item.update(self.machine_metadata[index])
            machine_rows.append(item)
        grouped = {}
        for row in machine_rows:
            description = row.get("Instrument description", "")
            key = normalize_text(description)
            if not key:
                continue
            group = grouped.setdefault(key, {"description": description, "quantity": 0, "machines": []})
            group["quantity"] += _item_count(row.get("Quantity", ""))
            group["machines"].append(row)
        return {"fields": fields, "machine_rows": machine_rows, "item_groups": list(grouped.values()), "certificate": self.files.get("certificate"), "authorization": self.files.get("authorization"), "pan_image_data": image_payload}

    def submit_application(self):
        if not self.worker or not self.worker.is_alive():
            messagebox.showinfo("Sign in first", "Log in through the app browser and prepare the application first.")
            return
        if not self.worker.ready_for_submit:
            messagebox.showinfo("Finish the review pages first", "Use Start application or Fill now / retry and complete the portal pages through the final review page before submitting.")
            return
        if not messagebox.askyesno("Submit application", "Submit this completed application to the Tamil Nadu Labour Department?\n\nReview the portal pages first. This is the final application submission; the app will not make a payment."):
            return
        self.worker.send("submit")
        self.status.set("Submitting the reviewed application. No payment will be made.")

    def _poll(self):
        try:
            while True:
                kind, value = self.msgq.get_nowait()
                if kind == "error":
                    self.status.set(value); messagebox.showerror("Automation stopped", value)
                elif kind == "details":
                    self.status.set(f"Filled: {', '.join(value['filled']) or 'none'}. Uploaded: {', '.join(value['uploaded']) or 'none'}. Needs manual review: {', '.join(value['skipped']) or 'no unmatched fields reported'}.")
                    if not value.get("automatic"):
                        messagebox.showinfo("Review the portal", self.status.get())
                elif kind == "payment":
                    self.status.set(value); messagebox.showinfo("Payment page reached", value)
                elif kind == "submitted":
                    self.status.set(value); messagebox.showinfo("Application submitted", value)
                elif kind == "login_ok":
                    self.status.set(value); messagebox.showinfo("Sign-in confirmed", value)
                elif kind == "login_failed":
                    self.status.set(value); messagebox.showwarning("Sign-in not confirmed", value)
                elif kind == "ready_to_submit":
                    self.status.set(value); messagebox.showinfo("Review before submission", value)
                else:
                    self.status.set(value)
        except queue.Empty: pass
        self.after(250, self._poll)


if __name__ == "__main__":
    App().mainloop()

