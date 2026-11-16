# Tamil Nadu Stamping Assistant

A local Windows desktop helper for preparing Tamil Nadu Legal Metrology weighing instrument stamping applications from previous verification certificates.

## What it does

- Reads selectable PDF text and tables, counts pages, ignores footer-only pages, and creates one editable machine row for every certificate page with a machine record.
- Extracts the first-page CV number/date, each page's CV number and application number, machine details, address, stamping mode, and additional fee indicator.
- Groups identical instrument types for the portal item list while keeping per-machine denomination, capacities, class, make, model, machine number, and CV reference for the later machine-detail page.
- Saves portal credentials and each account's PAN details/image in the Windows DPAPI-encrypted profile for the current Windows account.
- Opens bundled Chromium, fills the selected saved login, and waits for you to complete CAPTCHA. It then advances through the establishment, item/previous-information, and machine-detail pages.
- Uploads the selected Previous CV, repairer license copy, owner authorisation letter, and PAN image from the selected account.
- Stops at the final review page. **Submit application** asks for confirmation before making the official submission. It does not make a payment.

## Build the EXE

Requirements: Windows, Python 3.10 or newer, and internet access for the first dependency and Chromium browser install.

From PowerShell in this folder, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

The executable will be created at `dist\TN_Stamping_Assistant_v36.exe`. The build script downloads Python packages into `.build-deps`, downloads Chromium into `.pw-browsers`, and bundles both with PyInstaller.

To run from source instead:

```powershell
python -m pip install -r requirements.txt
python stamping_assistant.py
```

## Use

1. Choose an email from the sign-in dropdown. Use **Add account** or **Edit credentials** to manage the saved login, PAN profile, and license number.
2. Add the Previous CV PDF and owner authorisation letter in the **Documents** section directly below sign-in. The selected account's PAN image is uploaded automatically.
3. Choose **Read PDF and fill draft**. Review applicant and address values, then check each machine row. The app lists page count and footer-only pages ignored. It uses the first page's CV number/date for the first-page fields and preserves each page's CV number for a separate Previous Information row. Each row is set to Online, the portal's requested model selection is made before selecting Online for that row, and the shared application number is reused if a page omits it.
4. Choose **Start application** to open bundled Chromium and fill the saved login. Complete the CAPTCHA manually. If no PDF draft is ready yet, choose **Fill now / retry** after signing in.
5. With a reviewed PDF draft ready, choose **Start application** to continue automatically after login, or **Fill now / retry** to resume the current page. On the first portal page, fields are filled in their visible top-to-bottom order, waiting for dependent location lists and license details before continuing. The app then fills item types and quantities, Previous Information, and machine-detail rows in page order. It advances only when the visible required fields are filled and verifies a Submit control is present on the final review page.
6. Check the portal pages. The app selects **Other** for mixed instrument types, **Re-verification** as the stamping purpose, **Repairer** as the licensed applicant type, and sets site Dormant/Other from the additional-fee value on the certificate. It selects the 3-tonne capacity option only for an Electronic choice.
7. Press **Submit application** and confirm after reviewing the final portal page. The app only clicks a visible, enabled portal Submit control; it reports a clear message if the portal has not reached that page. Payment remains manual. **Fill now / retry** resumes the current portal step if a page needs attention.

Use the mouse wheel or the vertical scrollbar to navigate the application UI. The colors follow the Windows app theme and update when Windows switches between light and dark mode.

## Limits

- Scanned/image-only PDFs need OCR and are not parsed by this build. Use a PDF with selectable text.
- Portal field labels and layout can change. The app reports unmatched fields and required values; verify the portal pages and uploaded documents before submitting.
- CAPTCHA completion, final submission confirmation, any legal declaration that the portal requires, and payment remain user-controlled.
- The encrypted profile is bound to the current Windows account on this PC. If Windows profile access is lost, saved values cannot be decrypted. To remove it, delete `%LOCALAPPDATA%\TNStampingAssistant\profile.vault` in Windows Explorer.
