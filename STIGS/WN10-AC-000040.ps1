<#
.SYNOPSIS
    This PowerShell script ensures that the built-in Microsoft password complexity filter must be enabled.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000040

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000040.ps1 
#>

# Define expected value
$expectedValue = 1  # 1 = Enabled, 0 = Disabled
$tempInfPath = "$env:TEMP\secpol.inf"

Write-Output "`nChecking 'Password must meet complexity requirements' setting..."

# Export current security policy
secedit /export /cfg $tempInfPath /quiet

# Read current complexity setting
$currentLine = Select-String -Path $tempInfPath -Pattern "^PasswordComplexity\s*=\s*\d+" | ForEach-Object { $_.ToString() }

if (-not $currentLine) {
    Write-Error "Unable to read 'PasswordComplexity' from local security policy."
    exit 1
}

$currentValue = [int]($currentLine -split "=")[1].Trim()

# Check compliance
if ($currentValue -ne $expectedValue) {
    Write-Output "Finding: Password complexity requirement is not enabled (current value: $currentValue)."

    Write-Output "`nRemediating: Enabling password complexity requirements..."
    try {
        net accounts /minpwlen:14 | Out-Null  # ensure min length is also enforced
        secedit /configure /db secedit.sdb /cfg $tempInfPath /quiet

        # Update the inf file with the correct value
        (Get-Content $tempInfPath) -replace "PasswordComplexity\s*=\s*\d+", "PasswordComplexity = 1" | Set-Content $tempInfPath

        secedit /configure /db secedit.sdb /cfg $tempInfPath /quiet
        gpupdate /force | Out-Null

        Write-Output "Remediated: Password complexity requirements are now enabled."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: Password complexity requirement is already enabled."
}

# Cleanup
Remove-Item -Path $tempInfPath -Force -ErrorAction SilentlyContinue
