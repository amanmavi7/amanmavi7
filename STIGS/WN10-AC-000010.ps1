<#
.SYNOPSIS
    This PowerShell script ensures that the number of allowed bad logon attempts must be configured to 3 or less.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-17
    Last Modified   : 2025-04-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000010.ps1 
#>

# Define expected policy value
$expectedThreshold = 3
$tempInfPath = "$env:TEMP\secpol.inf"

Write-Output "`nChecking 'Account lockout threshold' setting..."

# Export current security policy
secedit /export /cfg $tempInfPath /quiet

# Read current lockout threshold from exported file
$currentThresholdLine = Select-String -Path $tempInfPath -Pattern "^LockoutBadCount\s*=\s*\d+" | ForEach-Object { $_.ToString() }

if (-not $currentThresholdLine) {
    Write-Error "Unable to read current 'LockoutBadCount' from local security policy."
    exit 1
}

$currentThreshold = [int]($currentThresholdLine -split "=")[1].Trim()

# Check compliance
if ($currentThreshold -eq 0 -or $currentThreshold -gt $expectedThreshold) {
    Write-Output "Finding: 'Account lockout threshold' is set to $currentThreshold (must be between 1 and $expectedThreshold)."

    Write-Output "`nRemediating: Setting 'Account lockout threshold' to $expectedThreshold..."

    try {
        # Set the new value
        net accounts /lockoutthreshold:$expectedThreshold | Out-Null
        Write-Output "Remediated: 'Account lockout threshold' set to $expectedThreshold."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: 'Account lockout threshold' is set to $currentThreshold."
}

# Cleanup
Remove-Item -Path $tempInfPath -Force -ErrorAction SilentlyContinue
