@echo off
rem Keep this launcher alongside each source and executable update.
rem The app's Clear previous application action preserves the signed-in browser.
rem It clears the selected CV, authorization/address files, and machine draft.
rem With Use different address selected, the address PDF supplies the applicant name too.
rem Machine data may come from a stamping transcription; portal upload can use another PDF.
setlocal
cd /d "%~dp0"
if exist "%~dp0dist\TN_Stamping_Assistant_v69.exe" (
    start "" "%~dp0dist\TN_Stamping_Assistant_v69.exe"
    exit /b 0
)
if exist "%~dp0TN_Stamping_Assistant_v69.exe" (
    start "" "%~dp0TN_Stamping_Assistant_v69.exe"
    exit /b 0
)
echo The stamping executable was not found.
echo Run build.ps1 first, or place this launcher beside TN_Stamping_Assistant_v69.exe.
pause
exit /b 1

