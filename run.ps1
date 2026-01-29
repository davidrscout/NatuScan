$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$venvPath = Join-Path $root ".venv"
$requirements = Join-Path $root "requirements.txt"
$pythonExe = Join-Path $venvPath "Scripts\\python.exe"

$hasUv = Get-Command uv -ErrorAction SilentlyContinue
if (-not (Test-Path $venvPath)) {
    if ($hasUv) {
        uv venv $venvPath
    } else {
        $py = Get-Command python -ErrorAction SilentlyContinue
        if (-not $py) {
            Write-Host "No se encontro ni uv ni python en PATH."
            Write-Host "Instala uno de los dos y reabre la terminal."
            exit 1
        }
        python -m venv $venvPath
    }
}

if (Test-Path $requirements) {
    if ($hasUv) {
        uv pip install -r $requirements
    } else {
        & $pythonExe -m pip install -r $requirements
    }
}

& $pythonExe (Join-Path $root "tool.py")
