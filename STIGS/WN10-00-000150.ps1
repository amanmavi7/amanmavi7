<#
.SYNOPSIS
    This PowerShell script checks if the Windows 10 version is prior to v1709 (i.e., ReleaseId < 1709). If applicable, verifies the DisableExceptionChainValidation registry value is set to 0. If the value does not exist or is not set correctly, it will remediate it by setting it to 0.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-16
    Last Modified   : 2024-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000150

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-00-000150.ps1 
#>

# Enable SEHOP via registry equivalent of Group Policy setting

# Registry path and value for SEHOP
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
$valueName = "DisableExceptionChainValidation"
$expectedValue = 0

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

# Check the current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Remediate if the value is missing or incorrect
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: Enabled SEHOP by setting '$valueName' to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Failed to set registry value: $valueName. Error: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: SEHOP is already enabled ('$valueName' is set to $expectedValue)."
}
