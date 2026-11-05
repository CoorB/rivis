# Backward-compatible NEO profile entry point.
$Product = Get-Content -Raw (Join-Path $PSScriptRoot "product.json") | ConvertFrom-Json
$Main = Join-Path $PSScriptRoot ($Product.cli + ".ps1")
$forward = @()
$project = "neo"
for ($i = 0; $i -lt $args.Count; $i++) {
  if ($args[$i] -eq "--project" -or $args[$i] -eq "-Project") {
    if ($i + 1 -ge $args.Count) {
      Write-Host "neo-mitm: -Project needs a value" -ForegroundColor Red
      exit 1
    }
    $project = $args[$i + 1]
    $i++
  } elseif ($args[$i] -like "--project=*") {
    $project = $args[$i].Substring(10)
  } elseif ($args[$i] -like "-Project=*") {
    $project = $args[$i].Substring(9)
  } else {
    $forward += $args[$i]
  }
}
# -Project must be a real named argument in the call. Putting the string "-Project" into a
# splatted array binds it as the positional $Name instead, so `--project default` used to
# land as Rest and die with "unexpected argument(s): default".
& $Main -Project $project @forward
exit $LASTEXITCODE
