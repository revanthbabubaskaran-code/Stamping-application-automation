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

MACHINE_REVIEW_FIELDS = {
    "Instrument description", "Instrument make", "Instrument model", "Machine number",
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
        self.captcha_candidate_value = ""
        self.captcha_candidate_since = 0.0

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
                self.messages.put(("status", "CAPTCHA entry is complete. Signing in and continuing automatically."))
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
        self.files = {"certificate": "", "authorization": ""}
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
        ttk.Label(outer, text="Read a previous certificate, prepare the stamping form, and stop at payment.", style="Sub.TLabel").pack(anchor="w", pady=(2, 16))
        canvas = tk.Canvas(outer, bg="#f3f6fa", highlightthickness=0)
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

        first_page = self._card(body, "Application review — applicant and first page")
        ttk.Button(first_page, text="Read PDF and fill draft", command=self.read_pdf, style="Primary.TButton").pack(anchor="w", pady=(8, 6))
        self.first_page_field_frame = ttk.Frame(first_page, style="Card.TFrame")
        self.first_page_field_frame.pack(fill="x")

        docs = ttk.Frame(first_page, style="Card.TFrame"); docs.pack(fill="x", pady=(14, 0))
        ttk.Label(docs, text="Documents for the first page", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self._file_row(docs, "Purchase invoice / Previous CV (PDF)", "certificate", ("PDF files", "*.pdf"))
        self._file_row(docs, "Authorisation letter from user / owner", "authorization", ("PDF or image", "*.pdf *.jpg *.jpeg *.png"))

        machine = self._card(body, "Machine details — certificate table")
        ttk.Label(machine, text="Review or correct the machine row read from the certificate table.", background="white", foreground="#62738a").pack(anchor="w", pady=(4, 8))
        self.machine_field_frame = ttk.Frame(machine, style="Card.TFrame")
        self.machine_field_frame.pack(fill="x")
        self.pan_name = tk.StringVar(); self.pan_number = tk.StringVar(); self.pan_date = tk.StringVar(); self.license_number = tk.StringVar()
        ttk.Label(first_page, text="PAN card image is uploaded from the selected account. Portal file uploads must be under 1 MB.", background="white", foreground="#6c7b8d").pack(anchor="w", pady=(8, 0))
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
        path = filedialog.askopenfilename(filetypes=[file_filter, ("All files", "*.*")])
        if path:
            self.files[key] = path
            self.files[key + "_display"].set(Path(path).name)

    def _set_fields(self, values):
        for frame in (self.first_page_field_frame, self.machine_field_frame):
            for widget in frame.winfo_children(): widget.destroy()
        self.vars.clear()
        first_idx = 0
        machine_keys = [
            "Instrument description", "Instrument make", "Maximum capacity", "Minimum capacity",
            "Verification interval (e/d)", "Instrument model", "Machine number", "Class", "Quantity",
        ]
        machine_headers = {
            "Instrument description": "Weight / type", "Instrument make": "Make",
            "Maximum capacity": "Max", "Minimum capacity": "Min",
            "Verification interval (e/d)": "e/d", "Instrument model": "Model",
            "Machine number": "Machine number", "Class": "Class", "Quantity": "Qty",
        }
        for col, name in enumerate(machine_keys):
            ttk.Label(self.machine_field_frame, text=machine_headers.get(name, name), background="white", wraplength=105, anchor="center").grid(row=0, column=col, sticky="nsew", padx=2, pady=(0, 4))
            var = tk.StringVar(value=values.get(name, ""))
            self.vars[name] = var
            ttk.Entry(self.machine_field_frame, textvariable=var, width=13).grid(row=1, column=col, sticky="ew", padx=2, pady=2)
            self.machine_field_frame.columnconfigure(col, weight=1, uniform="machine")
        for name in FIELD_LABELS:
            if name in MACHINE_REVIEW_FIELDS:
                continue
            frame = self.first_page_field_frame
            idx = first_idx
            var = tk.StringVar(value=values.get(name, ""))
            self.vars[name] = var
            ttk.Label(frame, text=name, background="white").grid(row=idx, column=0, sticky="w", pady=3, padx=(0, 10))
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
            text = pdf_text(path)
            if not text.strip():
                messagebox.showwarning("No selectable text found", "This PDF appears to be a scan. Use a text-searchable PDF; OCR is not included in this local build.")
                return
            values = extract_certificate(text)
            values.update({"Applicant business name": self.business_var.get(), "Applicant contact name": self.contact_var.get(), "Registered name": self.contact_var.get(), "Registered email": self.user_var.get(), "Registered mobile": self.mobile_var.get(), "Used by / trader contact": self.trader_contact_var.get(), "PAN name": self.pan_name.get(), "PAN number": self.pan_number.get(), "PAN date": self.pan_date.get(), "Repairer licence number": self.license_number.get()})
            self._set_fields(values)
            self.status.set(f"Draft prepared from {Path(path).name}. Review and correct every value before filling the portal.")
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
        ttk.Label(pad, text="All details and the PAN image are encrypted together for this email account.", background="#f3f6fa", foreground="#62738a", wraplength=480).pack(anchor="w", pady=(4, 12))

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

        ttk.Label(pad, text="PAN card image", background="#f3f6fa").pack(anchor="w", pady=(8, 2))
        image_row = ttk.Frame(pad); image_row.pack(fill="x")
        ttk.Label(image_row, textvariable=image_label, foreground="#62738a").pack(side="left", fill="x", expand=True)
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
        fields["PAN name"] = fields.get("PAN name", "") or self.pan_name.get().strip()
        fields["PAN number"] = fields.get("PAN number", "") or self.pan_number.get().strip()
        fields["PAN date"] = fields.get("PAN date", "") or self.pan_date.get().strip()
        fields["Repairer licence number"] = self.license_number.get().strip() or fields.get("Repairer licence number", "")
        fields["Applicant business name"] = fields.get("Applicant business name", "") or self.business_var.get().strip()
        fields["Applicant contact name"] = fields.get("Applicant contact name", "") or self.contact_var.get().strip()
        fields["Registered name"] = fields.get("Registered name", "") or self.contact_var.get().strip()
        fields["Registered email"] = self.user_var.get().strip() or fields.get("Registered email", "")
        fields["Registered mobile"] = fields.get("Registered mobile", "") or self.mobile_var.get().strip()
        fields["Used by / trader contact"] = fields.get("Used by / trader contact", "") or self.trader_contact_var.get().strip()
        image_payload = None
        account_index = self.account_combo.current()
        account = self.accounts[account_index] if 0 <= account_index < len(self.accounts) else {}
        encoded = account.get("pan_image_b64")
        if encoded:
            image_bytes = base64.b64decode(encoded)
            image_name = account.get("pan_image_name", "pan-card.jpg")
            image_payload = {"name": image_name, "mimeType": mimetypes.guess_type(image_name)[0] or "image/jpeg", "buffer": image_bytes}
        return {"fields": fields, "certificate": self.files.get("certificate"), "authorization": self.files.get("authorization"), "pan_image_data": image_payload}

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
