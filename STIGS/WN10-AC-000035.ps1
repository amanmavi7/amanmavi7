<#
.SYNOPSIS
    This PowerShell script ensures that passwords must, at a minimum, be 14 characters.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000035.ps1 
#>

# Define expected value
$expectedMinLength = 14
$tempInfPath = "$env:TEMP\secpol.inf"

Write-Output "`nChecking 'Minimum password length' policy..."

# Export current security policy
secedit /export /cfg $tempInfPath /quiet

# Read current minimum password length
$currentLine = Select-String -Path $tempInfPath -Pattern "^MinimumPasswordLength\s*=\s*\d+" | ForEach-Object { $_.ToString() }

if (-not $currentLine) {
    Write-Error "Unable to read current 'MinimumPasswordLength' from local security policy."
    exit 1
}

$currentMinLength = [int]($currentLine -split "=")[1].Trim()

# Check compliance
if ($currentMinLength -lt $expectedMinLength) {
    Write-Output "Finding: Minimum password length is set to $currentMinLength (less than required $expectedMinLength)."

    Write-Output "`nRemediating: Setting minimum password length to $expectedMinLength..."
    try {
        net accounts /minpwlen:$expectedMinLength | Out-Null
        Write-Output "Remediated: Minimum password length set to $expectedMinLength."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: Minimum password length is $currentMinLength."
}

# Cleanup
Remove-Item -Path $tempInfPath -Force -ErrorAction SilentlyContinue
