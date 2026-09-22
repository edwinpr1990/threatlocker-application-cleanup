$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment creation failed.' }
}
& '.venv\Scripts\python.exe' -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& '.venv\Scripts\python.exe' -m streamlit run portal_app.py --server.address 127.0.0.1 --server.port 8513 --browser.gatherUsageStats false --theme.base light --theme.primaryColor '#007f9d' --theme.backgroundColor '#ffffff' --theme.secondaryBackgroundColor '#f8f9fa' --theme.textColor '#233c49' --theme.font sans-serif
