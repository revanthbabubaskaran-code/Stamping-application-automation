# Tamil Nadu Stamping Assistant

A local Windows desktop helper for preparing the Tamil Nadu Labour Department weighing instrument stamping application from a previous verification certificate.

## What it does

- Reads text from a selectable-text PDF and prepares an editable application draft.
- Saves each portal email/password with that account's PAN name, number, date, license number, and PAN image in the Windows DPAPI encrypted profile for the current Windows account.
- Opens a dedicated Chromium browser bundled with the app, waits for the portal login form, and fills the selected saved email and password. You enter/solve the CAPTCHA; the app detects completion, clicks Login, opens Legal Metrology → Verification and Stamping → Stamping → + New Stamping, fills the draft and uploads, then submits to the payment page when all browser-required fields are complete.
- Fills visible portal fields using the labels and field IDs on the current stamping form.
- Uploads the selected Previous CV/purchase invoice and owner authorisation letter, plus the PAN image belonging to the selected account.
- Stops for any remaining required fields that could not be filled from your saved details or source PDF. It does not solve CAPTCHA, make legal declarations, or click anything on the payment page.

## Build the EXE

Requirements: Windows, Python 3.10 or newer, and internet access for the first dependency and Chromium browser install.

From PowerShell in this folder, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

The executable will be created at `dist\TN_Stamping_Assistant_v8.exe`. The build script downloads Python packages into `.build-deps`, downloads Chromium into `.pw-browsers`, and bundles both with PyInstaller. The app opens its own Chromium window and does not use installed Chrome. CAPTCHA completion is the only login step requiring your input.

To run from source instead:

```powershell
python -m pip install -r requirements.txt
python stamping_assistant.py
```

## Use

1. Choose an email from the sign-in dropdown or click **Add account** to save the email, password, PAN details and image, and License Number together. Each account uses its own PAN profile.
2. Choose the Previous CV/purchase invoice PDF and the owner authorisation letter. The selected account's PAN image is uploaded automatically.
3. Choose **Read PDF and fill draft**. Review and correct every value in the editable fields. Only values found in the PDF are suggested.
4. Choose **Start application**. The selected saved email and password are filled automatically. Complete the CAPTCHA in the bundled Chromium window; the app clicks Login and proceeds automatically.
5. Review applicant/address/PAN fields in **Application review — applicant and first page**, then review weight/type, make, max, min, e/d, model, machine number, class, and quantity in the machine details row. Use **Fill now / retry** if needed. Fields missing from the certificate need your entry.
6. When the required portal fields are complete, the app submits the application and stops at the payment page. Review the submitted details and complete payment yourself. Use **Submit to payment page (retry)** only if the automatic submit needs another attempt.

## Limits

- Scanned/image-only PDFs need OCR and are not parsed by this build. Use a PDF with selectable text.
- Portal labels and layout can change. The field mapping is based on the current stamping form, and the app reports unmatched fields and uploads. Verify every field and each uploaded document in the app browser.
- This helper does not solve CAPTCHA, sign legal declarations automatically, or make payments.
- The encrypted profile is bound to the current Windows account on this PC. If Windows user profile access is lost, the saved values cannot be decrypted. Delete the profile through Windows Explorer at `%LOCALAPPDATA%\TNStampingAssistant\profile.vault` if you need to remove it.

