# Store the GitHub token as the Worker's GITHUB_TOKEN secret and deploy.
# Run from any directory:  pwsh -File scheduler\set-token.ps1
# The token is read without echo, checked against GitHub, written to a temp file
# only for the duration of `cf deploy`, then deleted. It never lands in the repo.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$repo = 'BrettmVincent/cyberdigest'
$secure = Read-Host -AsSecureString 'Paste the GitHub fine-grained token (input hidden)'
$token = [System.Net.NetworkCredential]::new('', $secure).Password.Trim()
if (-not $token) { throw 'No token entered.' }

# Sanity check: the token must be able to read this repo's workflows (Actions permission).
try {
    $wf = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/workflows/update.yml" `
        -Headers @{ Authorization = "Bearer $token"; Accept = 'application/vnd.github+json'; 'User-Agent' = 'cyberdigest-scheduler-setup' }
    Write-Host "Token OK: can see workflow '$($wf.name)' ($($wf.state))."
} catch {
    throw "GitHub rejected the token for $repo ($($_.Exception.Message)). Check: repository access = only $repo, permission Actions = Read and write."
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cf-secrets-" + [guid]::NewGuid().ToString('N') + '.env')
try {
    [System.IO.File]::WriteAllText($tmp, "GITHUB_TOKEN=$token")
    cf deploy --secrets-file $tmp
    if ($LASTEXITCODE -ne 0) { throw "cf deploy failed (exit $LASTEXITCODE)." }
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    $token = $null
}
Write-Host 'Deployed. The Worker will trigger the update workflow every 10 minutes.'
