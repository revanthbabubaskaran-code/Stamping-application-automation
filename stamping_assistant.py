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
    "Applicant business name": "#establishmentname",
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
    "Business address", "Instrument make", "Instrument model", "Machine number",
    "Maximum capacity", "Minimum capacity", "Verification interval (e/d)", "Class",
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


def first(pattern: str, text: str, flags=re.I | re.S) -> str:
    match = re.search(pattern, text, flags)
    return re.sub(r"\s+", " ", match.group(1)).strip(" .,:;\n") if match else ""


def extract_certificate(text: str) -> dict[str, str]:
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
    values["Door number"] = parts[0] if parts and re.match(r"\d", parts[0]) else ""
    taluk_at = next((i for i, part in enumerate(parts) if re.search(r"\btaluk\b", part, re.I)), -1)
    values["Taluk"] = re.sub(r"\s*taluk\s*", "", parts[taluk_at], flags=re.I).strip() if taluk_at >= 0 else ""
    values["District"] = parts[taluk_at + 1] if taluk_at >= 0 and len(parts) > taluk_at + 1 else ""
    values["Town / Village"] = parts[taluk_at - 1] if taluk_at > 0 else ""
    values["Pincode"] = first(r"\b(\d{6})\b", raw_address)
    street_candidates = [p for p in parts[1:taluk_at - 1] if re.search(r"road|street|salai|main", p, re.I)] if taluk_at > 1 else []
    values["Street"] = street_candidates[-1] if street_candidates else ""
    values["Repairer licence date"] = first(r"Licence Number\s*:\s*[^\n]*?(\d{2}[-/]\d{2}[-/]\d{4})", text)
    values["Trader / establishment number"] = first(r"Trader\s+No\.?\s*:\s*\n\s*([^\n]+)", text)
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
        self.last_captcha_value = ""

    def run(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.messages.put(("error", "Playwright is not installed. Follow README setup/build steps."))
            return
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=False)
            except Exception as e:
                self.messages.put(("error", f"Could not start the app's Chromium browser. Rebuild the app with the bundled browser.\n{e}"))
                return
            context = browser.new_context()
            self.page = context.new_page()
            self.page.set_default_timeout(3500)
            self.ready.set()
            while True:
                try:
                    cmd, payload = self.commands.get(timeout=0.5)
                except queue.Empty:
                    if self.pending_application is not None:
                        if not self._logged_in():
                            self._submit_login_after_captcha()
                            continue
                        application = self.pending_application
                        self.pending_application = None
                        try:
                            self._navigate_to_stamping_form()
                            report = self._fill_form(application)
                            report["automatic"] = True
                            self.messages.put(("details", report))
                            if report["required_blank"]:
                                self.messages.put(("error", "The form is filled, but required fields remain blank. Complete those fields in the app browser; the application was not submitted."))
                            else:
                                self._submit()
                        except Exception as e:
                            self.messages.put(("error", f"Login was detected, but the automatic form steps stopped safely: {e}"))
                    continue
                if cmd == "stop":
                    break
                try:
                    if cmd == "open":
                        self.pending_application = payload["application"]
                        self._open_login_page()
                        self._fill_login(payload["credentials"])
                        self.messages.put(("opened", "Saved email and password filled. Enter the CAPTCHA in the app browser; the app will click Login and finish the application flow."))
                    elif cmd == "fill":
                        report = self._fill_form(payload)
                        if report["required_blank"]:
                            self.messages.put(("error", "The form is filled, but required fields remain blank. Complete those fields in the app browser; the application was not submitted."))
                        else:
                            self._submit()
                    elif cmd == "submit":
                        self._submit()
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
                            return value
                for token in frame.locator('textarea[name="g-recaptcha-response"],textarea[name="h-captcha-response"]').all():
                    value = token.input_value().strip()
                    if value:
                        return value
            except Exception:
                continue
        return ""

    def _submit_login_after_captcha(self):
        """Submit only after the user has entered/completed the CAPTCHA."""
        value = self._captcha_value()
        if not value:
            self.last_captcha_value = ""
            return
        if value == self.last_captcha_value:
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
                self.messages.put(("status", "CAPTCHA detected. Signing in and continuing automatically."))
                return
            except Exception:
                continue

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
        return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()

    def _field_for(self, names):
        page = self.page
        for name in names:
            # Prefer native accessible label matching.
            loc = page.get_by_label(re.compile(re.escape(name), re.I)).first
            try:
                if loc.count():
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
                        return page.locator(f"#{target_id}")
                    nested = label.locator("input,select,textarea").first
                    if nested.count():
                        return nested
            except Exception:
                continue
        return None

    def _fill_form(self, payload):
        page = self.page
        self._navigate_to_stamping_form()
        filled, skipped = [], []
        for field, value in payload["fields"].items():
            if not value:
                continue
            if field == "Instrument description":
                continue
            if field in LOCAL_ONLY_FIELDS:
                continue
            selector = PORTAL_IDS.get(field)
            locator = page.locator(selector) if selector else self._field_for(FIELD_LABELS.get(field, [field]))
            if locator is None:
                skipped.append(field)
                continue
            try:
                tag = locator.evaluate("el => el.tagName.toLowerCase()")
                if tag == "select":
                    if not self._select_best(locator, value):
                        skipped.append(field)
                        continue
                    page.wait_for_timeout(350)
                else:
                    locator.fill(value)
                filled.append(field)
            except Exception:
                skipped.append(field)

        # The portal's required choice fields are not represented in the PDF draft.
        description = payload["fields"].get("Instrument description", "")
        low = description.lower()
        machine_kind = "Electronic" if "electronic" in low else "Mechanical" if "mechanical" in low else "Weighing"
        if not self._select_best(page.locator("#newgood"), machine_kind): skipped.append("Instrument technology (portal choice)")
        capacity = payload["fields"].get("Maximum capacity", "")
        cap_number = self._number(capacity)
        capacity_choice = "Below 3 tonnes" if cap_number and cap_number < 3000 else "Above 3 tonnes" if cap_number else ""
        if capacity_choice and not self._select_best(page.locator("#tonnes"), capacity_choice): skipped.append("Capacity range (portal choice)")
        route = "Re-verification" if payload["fields"].get("Previous CV number") else "New verification"
        if not self._select_best(page.locator("#stamping-intend"), route): skipped.append("Stamping purpose (portal choice)")
        if payload["fields"].get("Repairer licence number"):
            if not self._select_best(page.locator("#applicant-licence-id"), "Repairer"):
                skipped.append("Licensed applicant type (portal choice)")
        item = payload["fields"].get("Instrument description", "")
        if item and not self._select_best(page.locator("#stampinglabourmeasures-0-stamping-type-id"), item):
            skipped.append("Instrument item category")

        attachments = [
            ("Upload the purchase Invoice/Previous CV", "#pur-invo-file", payload.get("certificate")),
            ("Upload Repairer License", None, payload.get("repairer_license")),
            ("Upload the Authorisation Letter from the user/owner", "#repairerletter", payload.get("authorization")),
            ("Upload copy of PAN card", "#pancard-file", payload.get("pan_image_data")),
        ]
        uploaded = []
        for label, selector, file_path in attachments:
            if not file_path:
                continue
            locator = page.locator(selector) if selector else self._file_input_for(label)
            if locator:
                if isinstance(file_path, dict):
                    if len(file_path.get("buffer", b"")) > 1024 * 1024:
                        skipped.append(f"{label} exceeds the portal's 1 MB file limit")
                        continue
                    locator.set_input_files(file_path)
                else:
                    if Path(file_path).stat().st_size > 1024 * 1024:
                        skipped.append(f"{label} exceeds the portal's 1 MB file limit")
                        continue
                    locator.set_input_files(file_path)
                uploaded.append(label)
            else:
                skipped.append(f"Upload: {label}")
        required_blank = []
        # Required controls that remain empty are reported and block auto-submit.
        try:
            blank_required = page.locator("input[required],select[required],textarea[required]").evaluate_all(
                "els => els.filter(e => (e.type === 'checkbox' || e.type === 'radio') ? !e.checked : !e.value).map(e => e.id || e.name || e.type)"
            )
            required_blank = blank_required
            skipped.extend(f"Required field left blank: {name}" for name in blank_required)
        except Exception:
            pass
        report = {"filled": filled, "skipped": skipped, "uploaded": uploaded, "required_blank": required_blank}
        self.messages.put(("details", report))
        return report

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

    def _submit(self):
        page = self.page
        payment_text = re.compile(r"make payment|proceed to payment|pay now|payment gateway|payment successful", re.I)
        if re.search(r"payment|receipt|checkout", page.url, re.I) or page.get_by_text(payment_text).count():
            self.messages.put(("payment", "The portal is already at a payment step. The assistant will not interact with payment."))
            return
        self._navigate_to_stamping_form()
        submit = page.get_by_role("button", name=re.compile(r"submit", re.I)).last
        if not submit.count():
            submit = page.locator('input[type="submit"]').last
        submit.click()
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


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1030x820")
        self.minsize(900, 690)
        self.configure(bg="#f3f6fa")
        self.msgq: queue.Queue = queue.Queue()
        self.worker: PortalWorker | None = None
        self.profile = {}
        try:
            self.profile = load_vault()
        except Exception as e:
            messagebox.showerror("Profile could not be opened", f"Encrypted profile could not be read. It may belong to another Windows user.\n\n{e}")
        self.files = {"certificate": "", "repairer_license": "", "authorization": "", "pan_image": ""}
        self.vars = {}
        self._styles()
        self._build()
        self._load_profile()
        self.after(250, self._poll)

    def _styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f6fa")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f3f6fa", foreground="#243247", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#f3f6fa", foreground="#172b4d", font=("Segoe UI Semibold", 20))
        style.configure("Sub.TLabel", background="#f3f6fa", foreground="#62738a", font=("Segoe UI", 10))
        style.configure("Section.TLabel", background="#ffffff", foreground="#172b4d", font=("Segoe UI Semibold", 12))
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 8))
        style.configure("Primary.TButton", background="#1261a0", foreground="white")
        style.map("Primary.TButton", background=[("active", "#0c4b7d")])

    def _build(self):
        outer = ttk.Frame(self, padding=22)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="TN Stamping Assistant", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Read a previous certificate, prepare the stamping form, and stop at payment.", style="Sub.TLabel").pack(anchor="w", pady=(2, 16))
        canvas = tk.Canvas(outer, bg="#f3f6fa", highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas)
        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw", width=960)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        login = self._card(body, "Portal sign-in")
        row = ttk.Frame(login, style="Card.TFrame"); row.pack(fill="x", pady=(10, 8))
        self.user_var = tk.StringVar(); self.pass_var = tk.StringVar()
        self.account_var = tk.StringVar()
        self.business_var = tk.StringVar(); self.contact_var = tk.StringVar(); self.mobile_var = tk.StringVar(); self.trader_contact_var = tk.StringVar()
        ttk.Label(row, text="Saved sign-in", background="white").pack(side="left", padx=(0, 10))
        self.account_combo = ttk.Combobox(row, textvariable=self.account_var, state="readonly", width=48)
        self.account_combo.pack(side="left", fill="x", expand=True)
        self.account_combo.bind("<<ComboboxSelected>>", self._on_account_selected)
        ttk.Button(row, text="Manage saved sign-ins", command=self.manage_credentials).pack(side="left", padx=(10, 0))
        contacts = ttk.Frame(login, style="Card.TFrame"); contacts.pack(fill="x", pady=(0, 8))
        for col, (label, var, width) in enumerate((("Applicant business name", self.business_var, 24), ("Authorised contact name", self.contact_var, 24), ("Applicant mobile", self.mobile_var, 16), ("Trader / user contact", self.trader_contact_var, 22))):
            ttk.Label(contacts, text=label, background="white").grid(row=0, column=col, sticky="w", padx=(0, 12))
            ttk.Entry(contacts, textvariable=var, width=width).grid(row=1, column=col, sticky="ew", padx=(0, 12))
            contacts.columnconfigure(col, weight=1)
        ttk.Button(login, text="Save applicant and PAN details", command=self.save_profile).pack(anchor="e")
        ttk.Label(login, text="Saved sign-ins and PAN data are encrypted for this Windows account. Complete CAPTCHA in the app browser.", background="white", foreground="#6c7b8d").pack(anchor="w", pady=(6, 0))

        docs = self._card(body, "Documents and PAN profile")
        self._file_row(docs, "Previous CV / purchase invoice (PDF)", "certificate", ("PDF files", "*.pdf"))
        self._file_row(docs, "Repairer licence copy (if requested by portal)", "repairer_license", ("PDF or image", "*.pdf *.jpg *.jpeg *.png *.bmp"))
        self._file_row(docs, "Owner authorization letter (PDF or image)", "authorization", ("PDF or image", "*.pdf *.jpg *.jpeg *.png"))
        self._file_row(docs, "PAN card image (JPG or PNG)", "pan_image", ("Image files", "*.jpg *.jpeg *.png"))
        pan = ttk.Frame(docs, style="Card.TFrame"); pan.pack(fill="x", pady=(12, 4))
        self.pan_name = tk.StringVar(); self.pan_number = tk.StringVar(); self.pan_date = tk.StringVar()
        for col, (label, var, width) in enumerate((("PAN name", self.pan_name, 30), ("PAN number", self.pan_number, 20), ("Date on PAN", self.pan_date, 18))):
            ttk.Label(pan, text=label, background="white").grid(row=0, column=col, sticky="w", padx=(0, 12))
            ttk.Entry(pan, textvariable=var, width=width).grid(row=1, column=col, sticky="ew", padx=(0, 12))
            pan.columnconfigure(col, weight=1)
        ttk.Label(docs, text="PAN number, name, date, and selected image are kept in the encrypted profile for reuse. Portal uploads must be under 1 MB.", background="white", foreground="#6c7b8d").pack(anchor="w", pady=(5, 0))

        draft = self._card(body, "Application details to review")
        ttk.Button(draft, text="Read PDF and fill draft", command=self.read_pdf, style="Primary.TButton").pack(anchor="w", pady=(8, 6))
        self.field_frame = ttk.Frame(draft, style="Card.TFrame"); self.field_frame.pack(fill="x")
        self._set_fields({})

        action = ttk.Frame(body, style="Card.TFrame", padding=14); action.pack(fill="x", pady=(12, 5))
        ttk.Button(action, text="Start application", command=self.open_portal, style="Primary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(action, text="Fill now / retry", command=self.fill_application).pack(side="left", padx=8)
        ttk.Button(action, text="Submit to payment page (retry)", command=self.submit_application).pack(side="left", padx=8)
        self.status = tk.StringVar(value="Ready. Choose documents, review the PDF draft, then open the portal.")
        ttk.Label(body, textvariable=self.status, style="Sub.TLabel", wraplength=930).pack(anchor="w", pady=(10, 0))

    def _card(self, parent, title):
        card = ttk.Frame(parent, style="Card.TFrame", padding=16)
        card.pack(fill="x", pady=(0, 12))
        ttk.Label(card, text=title, style="Section.TLabel").pack(anchor="w")
        return card

    def _file_row(self, parent, label, key, file_filter):
        frame = ttk.Frame(parent, style="Card.TFrame"); frame.pack(fill="x", pady=(8, 0))
        ttk.Label(frame, text=label, width=40, background="white").pack(side="left")
        display = tk.StringVar(value="No file selected")
        self.files[key + "_display"] = display
        ttk.Label(frame, textvariable=display, background="white", foreground="#62738a").pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(frame, text="Choose file", command=lambda: self.choose_file(key, file_filter)).pack(side="right")

    def choose_file(self, key, file_filter):
        if key == "certificate":
            path = filedialog.askopenfilename(filetypes=[file_filter, ("All files", "*.*")])
        elif key == "authorization":
            path = filedialog.askopenfilename(filetypes=[file_filter, ("All files", "*.*")])
        else:
            path = filedialog.askopenfilename(filetypes=[file_filter, ("All files", "*.*")])
        if path:
            self.files[key] = path
            self.files[key + "_display"].set(Path(path).name)
            if key == "pan_image":
                try:
                    self.profile["pan_image_b64"] = base64.b64encode(Path(path).read_bytes()).decode("ascii")
                    self.profile["pan_image_name"] = Path(path).name
                except OSError as e: messagebox.showerror("Could not read PAN image", str(e))

    def _set_fields(self, values):
        for widget in self.field_frame.winfo_children(): widget.destroy()
        self.vars.clear()
        for idx, name in enumerate(FIELD_LABELS):
            ttk.Label(self.field_frame, text=name, background="white").grid(row=idx, column=0, sticky="w", pady=3, padx=(0, 10))
            var = tk.StringVar(value=values.get(name, ""))
            self.vars[name] = var
            ttk.Entry(self.field_frame, textvariable=var, width=75).grid(row=idx, column=1, sticky="ew", pady=3)
        self.field_frame.columnconfigure(1, weight=1)
        if self.pan_number.get(): self.vars["PAN number"].set(self.pan_number.get())

    def read_pdf(self):
        path = self.files.get("certificate")
        if not path:
            messagebox.showinfo("Choose the previous certificate", "Select the previous CV or purchase invoice PDF first.")
            return
        try:
            text = pdf_text(path)
            if not text.strip():
                messagebox.showwarning("No selectable text found", "This PDF appears to be a scan. Use a text-searchable PDF; OCR is not included in this local build.")
                return
            values = extract_certificate(text)
            values.update({"Applicant business name": self.business_var.get(), "Applicant contact name": self.contact_var.get(), "Registered name": self.contact_var.get(), "Registered email": self.user_var.get(), "Registered mobile": self.mobile_var.get(), "Used by / trader contact": self.trader_contact_var.get(), "PAN number": self.pan_number.get(), "PAN date": self.pan_date.get()})
            self._set_fields(values)
            self.status.set(f"Draft prepared from {Path(path).name}. Review and correct every value before filling the portal.")
        except Exception as e:
            messagebox.showerror("Could not read PDF", str(e))

    def _load_profile(self):
        self.accounts = list(self.profile.get("portal_accounts", []))
        if not self.accounts and self.profile.get("username") and self.profile.get("password"):
            self.accounts = [{"label": self.profile.get("account_label") or self.profile.get("username"), "username": self.profile["username"], "password": self.profile["password"]}]
        self._refresh_accounts(0 if self.accounts else None)
        self.business_var.set(self.profile.get("applicant_business_name", "")); self.contact_var.set(self.profile.get("applicant_contact_name", "")); self.mobile_var.set(self.profile.get("applicant_mobile", "")); self.trader_contact_var.set(self.profile.get("trader_contact_name", ""))
        self.pan_name.set(self.profile.get("pan_name", "")); self.pan_number.set(self.profile.get("pan_number", "")); self.pan_date.set(self.profile.get("pan_date", ""))
        img = self.profile.get("pan_image_b64")
        if img:
            self.files["pan_image"] = "__encrypted_profile_image__"
            self.files["pan_image_display"].set("Saved in encrypted profile")

    def _account_label(self, account):
        label = account.get("label") or account.get("username", "Saved account")
        email = account.get("username", "")
        return f"{label} ({email})" if email and email not in label else label

    def _refresh_accounts(self, select_index=None):
        values = [self._account_label(account) for account in getattr(self, "accounts", [])]
        self.account_combo["values"] = values
        if values:
            index = select_index if select_index is not None and 0 <= select_index < len(values) else 0
            self.account_combo.current(index)
            self._on_account_selected()
        else:
            self.account_var.set("")
            self.user_var.set(""); self.pass_var.set("")

    def _on_account_selected(self, _event=None):
        index = self.account_combo.current()
        if 0 <= index < len(getattr(self, "accounts", [])):
            account = self.accounts[index]
            self.user_var.set(account.get("username", ""))
            self.pass_var.set(account.get("password", ""))

    def manage_credentials(self):
        window = tk.Toplevel(self)
        window.title("Manage saved sign-ins")
        window.transient(self)
        window.grab_set()
        window.geometry("560x430")
        pad = ttk.Frame(window, padding=18); pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Saved portal accounts", style="Section.TLabel").pack(anchor="w")
        account_list = tk.Listbox(pad, height=6, exportselection=False)
        account_list.pack(fill="x", pady=(8, 12))
        for account in self.accounts:
            account_list.insert("end", self._account_label(account))
        label_var = tk.StringVar(); email_var = tk.StringVar(); password_var = tk.StringVar()
        fields = ttk.Frame(pad); fields.pack(fill="x")
        for row, (label, var, secret) in enumerate((("Profile name", label_var, False), ("Registered email", email_var, False), ("Password", password_var, True))):
            ttk.Label(fields, text=label).grid(row=row * 2, column=0, sticky="w", pady=(2, 1))
            ttk.Entry(fields, textvariable=var, show="•" if secret else "").grid(row=row * 2 + 1, column=0, sticky="ew", pady=(0, 6))
        fields.columnconfigure(0, weight=1)
        editing = {"index": None}

        def load_selected(_event=None):
            selection = account_list.curselection()
            if not selection: return
            editing["index"] = selection[0]
            account = self.accounts[editing["index"]]
            label_var.set(account.get("label", "")); email_var.set(account.get("username", "")); password_var.set(account.get("password", ""))

        def new_account():
            editing["index"] = None
            account_list.selection_clear(0, "end")
            label_var.set(""); email_var.set(""); password_var.set("")

        def save_account():
            label, email, password = label_var.get().strip(), email_var.get().strip(), password_var.get()
            if not label or not email or not password:
                messagebox.showwarning("Missing sign-in details", "Enter a profile name, registered email, and password.", parent=window)
                return
            record = {"label": label, "username": email, "password": password}
            index = editing["index"]
            if index is None:
                self.accounts.append(record); index = len(self.accounts) - 1
            else:
                self.accounts[index] = record
            self.profile["portal_accounts"] = self.accounts
            self.profile.pop("username", None); self.profile.pop("password", None)
            try:
                save_vault(self.profile)
            except Exception as exc:
                messagebox.showerror("Could not save sign-in", str(exc), parent=window)
                return
            self._refresh_accounts(index)
            account_list.delete(0, "end")
            for item in self.accounts: account_list.insert("end", self._account_label(item))
            account_list.selection_set(index)
            editing["index"] = index
            self.status.set("Saved sign-in encrypted for this Windows account.")

        def delete_account():
            index = editing["index"]
            if index is None or not messagebox.askyesno("Remove saved sign-in", "Remove this sign-in from the encrypted profile?", parent=window): return
            self.accounts.pop(index)
            self.profile["portal_accounts"] = self.accounts
            self.profile.pop("username", None); self.profile.pop("password", None)
            try: save_vault(self.profile)
            except Exception as exc:
                messagebox.showerror("Could not update profile", str(exc), parent=window); return
            account_list.delete(index)
            _new = min(index, len(self.accounts) - 1) if self.accounts else None
            self._refresh_accounts(_new)
            new_account()

        account_list.bind("<<ListboxSelect>>", load_selected)
        buttons = ttk.Frame(pad); buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="New", command=new_account).pack(side="left")
        ttk.Button(buttons, text="Save", command=save_account, style="Primary.TButton").pack(side="left", padx=8)
        ttk.Button(buttons, text="Remove", command=delete_account).pack(side="left")
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right")
        if self.accounts:
            account_list.selection_set(0); load_selected()

    def save_profile(self):
        self.profile.update({"portal_accounts": getattr(self, "accounts", []), "applicant_business_name": self.business_var.get(), "applicant_contact_name": self.contact_var.get(), "applicant_mobile": self.mobile_var.get(), "trader_contact_name": self.trader_contact_var.get(), "pan_name": self.pan_name.get(), "pan_number": self.pan_number.get(), "pan_date": self.pan_date.get()})
        self.profile.pop("username", None); self.profile.pop("password", None)
        if not self.profile.get("pan_image_b64") and self.files.get("pan_image"):
            self.profile["pan_image_b64"] = base64.b64encode(Path(self.files["pan_image"]).read_bytes()).decode("ascii")
            self.profile["pan_image_name"] = Path(self.files["pan_image"]).name
        try:
            save_vault(self.profile)
            self.status.set("Profile saved encrypted for this Windows account.")
            messagebox.showinfo("Saved securely", "Credentials and PAN profile were saved in the local encrypted vault.")
        except Exception as e: messagebox.showerror("Could not save profile", str(e))

    def open_portal(self):
        self._on_account_selected()
        if not self.user_var.get() or not self.pass_var.get():
            messagebox.showwarning("Sign-in needed", "Choose a saved sign-in or add one with Manage saved sign-ins.")
            return
        if not self.files.get("certificate"):
            messagebox.showwarning("Previous CV required", "Choose the previous CV PDF and read/review the draft before starting the application.")
            return
        self._ensure_worker()
        self.worker.send("open", {"credentials": {"username": self.user_var.get(), "password": self.pass_var.get()}, "application": self._application_payload()})
        self.status.set("Opening the app browser and filling saved sign-in. Enter the CAPTCHA there; login and application steps continue automatically.")

    def _ensure_worker(self):
        if not self.worker or not self.worker.is_alive(): self.worker = PortalWorker(self.msgq)

    def fill_application(self):
        if not self.worker or not self.worker.is_alive():
            messagebox.showinfo("Sign in first", "Open the app browser, complete CAPTCHA, and log in first.")
            return
        if not self.files.get("certificate"):
            messagebox.showwarning("Previous CV required", "Choose the PDF to upload as the previous CV.")
            return
        self.worker.send("fill", self._application_payload())
        self.status.set("Filling matching fields and uploads in the app browser.")

    def _application_payload(self):
        fields = {k: v.get().strip() for k, v in self.vars.items()}
        fields["PAN number"] = self.pan_number.get().strip() or fields.get("PAN number", "")
        fields["PAN date"] = self.pan_date.get().strip() or fields.get("PAN date", "")
        fields["Applicant business name"] = self.business_var.get().strip() or fields.get("Applicant business name", "")
        fields["Applicant contact name"] = self.contact_var.get().strip() or fields.get("Applicant contact name", "")
        fields["Registered name"] = self.contact_var.get().strip() or fields.get("Registered name", "")
        fields["Registered email"] = self.user_var.get().strip() or fields.get("Registered email", "")
        fields["Registered mobile"] = self.mobile_var.get().strip() or fields.get("Registered mobile", "")
        fields["Used by / trader contact"] = self.trader_contact_var.get().strip() or fields.get("Used by / trader contact", "")
        image_payload = None
        if self.files.get("pan_image") == "__encrypted_profile_image__" or not self.files.get("pan_image"):
            encoded = self.profile.get("pan_image_b64")
            if encoded:
                image_bytes = base64.b64decode(encoded)
                image_name = self.profile.get("pan_image_name", "pan-card.jpg")
                image_payload = {"name": image_name, "mimeType": mimetypes.guess_type(image_name)[0] or "image/jpeg", "buffer": image_bytes}
        elif self.files.get("pan_image"):
            image_payload = self.files["pan_image"]
        return {"fields": fields, "certificate": self.files.get("certificate"), "repairer_license": self.files.get("repairer_license"), "authorization": self.files.get("authorization"), "pan_image_data": image_payload}

    def submit_application(self):
        if not self.worker or not self.worker.is_alive():
            messagebox.showinfo("Sign in first", "Log in through the app browser and prepare the application first.")
            return
        if not messagebox.askyesno("Submit application", "Submit the information and files currently shown in the portal to Tamil Nadu Labour Department?\n\nReview the form in Chrome before continuing. This will stop at the payment page; no payment will be made."):
            return
        self.worker.send("submit")
        self.status.set("Submitting the reviewed application; payment is not part of this action.")

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
                else:
                    self.status.set(value)
        except queue.Empty: pass
        self.after(250, self._poll)


if __name__ == "__main__":
    App().mainloop()
