$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $project

if (-not (Test-Path ".build-deps")) {
    New-Item -ItemType Directory -Path ".build-deps" | Out-Null
}

if (-not (Test-Path ".build-deps\playwright\__init__.py")) {
    python -m pip install --target .build-deps -r requirements.txt
}
$env:PYTHONPATH = (Join-Path $project ".build-deps")
$env:PLAYWRIGHT_BROWSERS_PATH = (Join-Path $project ".pw-browsers")
if (-not (Get-ChildItem -LiteralPath $env:PLAYWRIGHT_BROWSERS_PATH -Directory -Filter "chromium-*" -ErrorAction SilentlyContinue)) {
    python -m playwright install chromium --no-shell
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright Chromium download failed with exit code $LASTEXITCODE"
    }
}
Get-ChildItem -LiteralPath $env:PLAYWRIGHT_BROWSERS_PATH -Directory -Filter "chromium_headless_shell-*" -ErrorAction SilentlyContinue | ForEach-Object {
    $resolved = (Resolve-Path -LiteralPath $_.FullName).Path
    $root = (Resolve-Path -LiteralPath $env:PLAYWRIGHT_BROWSERS_PATH).Path + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw "Refusing to remove an unexpected browser path: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
python -m PyInstaller --noconfirm --clean --onefile --windowed --noupx `
    --name TN_Stamping_Assistant_v20 `
    --add-data "$env:PLAYWRIGHT_BROWSERS_PATH;.pw-browsers" `
    --collect-all playwright `
    --collect-all pdfplumber `
    --collect-all pdfminer `
    --collect-all pypdfium2 `
    stamping_assistant.py
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

Write-Host "Built: $project\dist\TN_Stamping_Assistant_v20.exe"
