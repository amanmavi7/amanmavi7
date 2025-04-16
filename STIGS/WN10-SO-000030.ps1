<#
.SYNOPSIS
    This PowerShell script enables subcategories in the Audit policy by checking if the registry value SCENoApplyLegacyAuditPolicy exists and is set to 1, and if it’s missing or misconfigured, it will remediate it by setting the correct value.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-15
    Last Modified   : 2025-04-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000030

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-SO-000030.ps1 
#>

# Define the registry path, value name, and expected value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "SCENoApplyLegacyAuditPolicy"
$expectedValue = 1

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    try {
        New-Item -Path $regPath -Force | Out-Null
        Write-Output "Created missing registry path: $regPath"
    } catch {
        Write-Error "Failed to create registry path: $regPath. Error: $_"
        exit 1
    }
}

# Get current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Check if the value exists and is correct
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: Set '$valueName' to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Failed to set registry value: $valueName. Error: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: '$valueName' is already set to $expectedValue."
}
