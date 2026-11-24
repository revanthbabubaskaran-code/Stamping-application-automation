# Tamil Nadu Stamping Assistant

A local Windows desktop helper for preparing Tamil Nadu Legal Metrology weighing instrument stamping applications from previous verification certificates.

## What it does

- Reads selectable PDF text and tables, counts pages, ignores footer-only pages, and creates one editable machine row for every certificate page with a machine record. Model text split across table lines is rejoined within partial tokens (for example, `ELT3` + `0` becomes `ELT30`, and `PS20` + `0` becomes `PS200`) while normal spaces between model words are preserved.
- Extracts the first-page CV number/date, each page's CV number and application number, machine details, address, stamping mode, and additional fee indicator.
- Groups identical instrument types for the portal item list while keeping per-machine denomination, capacities, class, make, model, machine number, and CV reference for the later machine-detail page.
- Saves portal credentials and each account's PAN details/image in the Windows DPAPI-encrypted profile for the current Windows account.
- Opens bundled Chromium maximized and uses the live window size as the viewport, so the portal reflows when you maximize or restore the browser. It fills the selected saved login and waits for you to complete CAPTCHA before continuing through the application.
- Keeps `dist\address_comparison\location_options.json` as a local comparison cache. Each address dropdown snapshot includes its parent selections and the portal's option labels/IDs; repeated Town/Village labels remain separate. The file fills as the app visits live dropdown branches, while active portal choices remain authoritative.
- Uploads the selected Previous CV and owner authorisation letter, plus the PAN image from the selected account.
- Verifies the final review rows and total quantity, uses the portal Edit control once to refill machine details if a row is inconsistent, then submits a verified application to reach the payment step. Payment remains manual.
- Lets you start another application from the **New application (keep signed-in session)** button. It returns the existing Chromium tab to the stamping services page, opens a fresh New Stamping form, and fills the newly selected/reviewed PDF without starting another browser or login session.
- Splits PDFs containing more than 40 machine records into selectable application parts. Parts are balanced up to 35 machines where possible; if the greedy final remainder would be under 10, the number of parts is reduced and all machines are redistributed evenly. For example, 65 becomes 33 + 32, 100 becomes 33 + 33 + 34, and 73 becomes 37 + 36. **Start all parts (same login)** can fill them sequentially in new tabs inside one signed-in Chromium context; each final Submit still requires confirmation, and payment remains manual.

## Build the EXE

Double-click **Run Stamping Assistant.bat** to start the built program. The launcher works from the project folder or beside the executable in `dist`. Build the executable first when using a fresh source checkout. Personal certificates, authorization letters, PAN images, credentials and test-session diagnostics must remain local.

Requirements: Windows, Python 3.10 or newer, and internet access for the first dependency and Chromium browser install.

From PowerShell in this folder, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

Automation and setup errors appear in a selectable text window with **Copy error**, **Select all**, and **Save error…** actions. Copy retries through native Windows, Tk, and PowerShell clipboard paths. Chromium starts in a background worker so slow first launch does not freeze the UI. The New goods/Re-verification choice is **Electronic weighing machine** only when every Previous CV machine is electronic; mixed or other machine types select **Others**. For electronic machines, **Weighing machine with** uses denomination/Weights across the Previous CV pages: any value of at least 3,000 kg selects **Above 3 tonnes**, otherwise **Below 3 tonnes**. The Office/Site choice selected in the app controls the new application; an old Office/Site label on the Previous CV is only a fallback when no selection was supplied. Previous Information rows are prepared in a first pass, then the Online choices and certificate/application numbers are filled in a second pass. A model selection is made early only when the portal requires it before it will add another row. Certificate dates are polled as a batch and the wait scales with the number of machines, with progress shown during long lookups. Machine-detail rows are also added before their values are entered, and row progress is reported during large files. Address parsing anchors Taluk/District from the right; when Street spans several comma-separated components, the assistant checks exact suffix matches against the portal's Street options and leaves all preceding components in Door Number. When Town/Village repeats, it tries the options in order and uses the one whose Street options contain the matching address suffix. Before opening the final review page, the app verifies each machine row has its own exact Previous CV selection. On the review page it confirms each machine number and its CV number appear together in the same row. For both establishment address blocks, it selects each dependent dropdown in top-to-bottom order and waits for the next dropdown options to populate and settle before continuing. Dependent dropdowns are handled in place in row order with short readiness checks instead of fixed pauses. After address and repeater updates, the app restores and verifies the Manufacturer / Trader / Establishment Name from the PDF M/S line. The executable is created at `dist\TN_Stamping_Assistant_v69.exe`. Credentials, repairer company/mobile, and PAN details are encrypted with Windows DPAPI. The app uses Local AppData when writable and falls back to an ignored `.TNStampingAssistant` folder beside the app when it is not.

Routine sign-in and fill success confirmations are shown in the status line only; modal notifications are reserved for errors. Automation errors also appear in the **Previous Information** panel and remain copyable from the error window.

To run from source instead:

```powershell
python -m pip install -r requirements.txt
python stamping_assistant.py
```

## Use

1. Choose an email from the sign-in dropdown. Use **Add account** or **Edit credentials** to manage the saved login, repairer company name/mobile, PAN profile, and license number. If those repairer fields are blank, reading a certificate fills them from its “Repaired by” line and saves the missing values to that account without replacing existing ones.
2. Add the Previous CV PDF and owner authorisation letter in the **Documents** section directly below sign-in. The selected account's PAN image is uploaded automatically.
3. If the application address differs from the Previous CV, check **Use different address** in Documents and choose an address PDF. Then choose **Read PDF and fill draft**. The app reads applicant/address fields from the optional address PDF and reads machine rows, CV numbers, and application numbers only from the Previous CV PDF. Without the checkbox, all draft values come from the Previous CV. Review address values and every machine row before filling. The app lists page count and footer-only pages ignored. It uses the first page's CV number/date for first-page fields and preserves each machine page's CV number for a separate Previous Information row. Each row is set to Online, the portal's requested model selection is made before selecting Online for that row, and the shared application number is reused if a page omits it.
   For a single-machine application, the machine-detail Previous CV dropdown is not required because there is only one possible certificate. PAN name is retained as profile information and is not treated as a separate required portal field.
4. Choose **Start application** to open bundled Chromium and fill the saved login. Complete the CAPTCHA manually. If no PDF draft is ready yet, choose **Fill now / retry** after signing in.
5. With a reviewed PDF draft ready, choose **Start application** to continue automatically after login, or **Fill now / retry** to resume the current page. On the first portal page, fields are filled in their visible top-to-bottom order, waiting for dependent location lists and license details before continuing. The certificate business name and address are entered in both Establishment Details and Manufacturer / Trader / Establishment after selecting **Same Details**. The app then fills item types and quantities, Previous Information, and machine-detail rows in page order. It advances only when the visible required fields are filled and verifies a Submit control is present on the final review page.
6. Check the portal pages. The app selects **Other** for mixed instrument types, **Re-verification** as the stamping purpose, **Repairer** as the licensed applicant type, and sets site Dormant/Other from the additional-fee value on the certificate. It selects the 3-tonne capacity option only for an Electronic choice.
7. Press **Submit application** and confirm after reviewing the final portal page. The app only clicks a visible, enabled portal Submit control; it reports a clear message if the portal has not reached that page. Payment remains manual. **Fill now / retry** resumes the current portal step if a page needs attention.
8. To prepare another application while still signed in, select its PDFs and review/confirm its draft, then choose **New application (keep signed-in session)**. The current application page is left without submitting; the same signed-in Chromium tab is returned to the services page and opened on a fresh stamping form.
9. For a certificate with multiple application parts, select **Part 1** and confirm the reviewed draft. Choose **Start all parts (same login)** to complete one CAPTCHA/login and then open each part in a new tab in the same Chromium session. After you confirm **Submit application** for one part, the next part starts automatically in another tab; each part still stops for its own Submit confirmation. All payment pages remain open for your manual payment. You can alternatively select parts individually and choose **New application (keep signed-in session)**. Each part uses the CV number/date and machine rows from its own first included certificate page.

Use the mouse wheel or the vertical scrollbar to navigate the application UI. Text, fields, and buttons use larger fonts for readability. Use the **Theme** dropdown to choose **Auto** (follow Windows), **Light**, or **Dark**; the selected color scheme updates text, backgrounds, inputs, and dropdown lists together.

Choose **Clear previous application** to remove the current local draft, selected document paths, parsed address, and machine rows before preparing another application. It preserves saved accounts and the signed-in Chromium session. It does not cancel or erase a portal application already in progress or one already submitted.

The main window opens at a screen-aware size. Its content expands to the available width, wraps long status messages, and reflows machine details from a wide table into 5-, 3-, or 2-column layouts as the window narrows. The vertical scrollbar remains available at every size.

## Limits

- Scanned/image-only PDFs need OCR and are not parsed by this build. Use a PDF with selectable text.
- Portal field labels and layout can change. The app reports unmatched fields and required values; verify the portal pages and uploaded documents before submitting.
- CAPTCHA completion, final submission confirmation, any legal declaration that the portal requires, and payment remain user-controlled.
- The encrypted profile is bound to the current Windows account on this PC. If Windows profile access is lost, saved values cannot be decrypted. To remove it, delete `%LOCALAPPDATA%\TNStampingAssistant\profile.vault`, or the app's `.TNStampingAssistant\profile.vault` fallback folder.

