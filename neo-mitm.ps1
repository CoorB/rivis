# Backward-compatible NEO profile entry point.
$Product = Get-Content -Raw (Join-Path $PSScriptRoot "product.json") | ConvertFrom-Json
$Main = Join-Path $PSScriptRoot ($Product.cli + ".ps1")
$forward = @()
$hasProject = $false
for ($i = 0; $i -lt $args.Count; $i++) {
  if ($args[$i] -eq "--project") {
    $hasProject = $true
    $forward += "-Project"
  } elseif ($args[$i] -like "--project=*") {
    $hasProject = $true
    $forward += "-Project"
    $forward += $args[$i].Substring(10)
  } else {
    if ($args[$i] -eq "-Project") { $hasProject = $true }
    $forward += $args[$i]
  }
}
if ($hasProject) { & $Main @forward }
else { & $Main -Project neo @forward }
exit $LASTEXITCODE
