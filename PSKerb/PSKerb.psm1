#region Globals

$private = Join-Path $PSScriptRoot "Shared"
$kerberos = Join-Path $PSScriptRoot "Kerberos"

Get-ChildItem $private -Filter *.ps1 -File -ErrorAction Ignore | ForEach-Object { . $_.FullName }
Get-ChildItem $kerberos -Filter *.ps1 -File -ErrorAction Ignore | ForEach-Object {
    . $_.FullName
    Export-ModuleMember -Function $_.BaseName
}

#end region