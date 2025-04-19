<#
.SYNOPSIS
    This PowerShell script ensures that the WDigest Authentication must be disabled.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-19
    Last Modified   : 2025-04-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000038

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000038.ps1 
#>

# Registry configuration for WDigest
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest"
$valueName = "UseLogonCredential"
$expectedValue = 0

Write-Output "`nChecking WDigest authentication setting..."

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    try {
        New-Item -Path $regPath -Force | Out-Null
        Write-Output "Created missing registry path: $regPath"
    } catch {
        Write-Error "Failed to create registry path: $regPath"
        exit 1
    }
}

# Retrieve the current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Evaluate and remediate if needed
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    $reportedValue = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: 'UseLogonCredential' is $reportedValue. Expected: $expectedValue (WDigest disabled)."

    Write-Output "`nRemediating: Disabling WDigest authentication..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: 'UseLogonCredential' set to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: WDigest authentication is disabled ('UseLogonCredential' = $expectedValue)."
}
