<#
.SYNOPSIS
    This PowerShell script will check for the presence and correct configuration of the DisableWindowsConsumerFeatures registry value under HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent. If it's missing or misconfigured, the script will remediate it by setting the value to 1.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-16
    Last Modified   : 2025-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000197

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000197.ps1 
#>

# Define registry info
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableWindowsConsumerFeatures"
$expectedValue = 1

# Check Windows version (skip for Windows 10 v1507 LTSB)
$winVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
if ($winVersion -eq "1507") {
    Write-Output "Not Applicable: Windows 10 v1507 LTSB does not include this setting."
    return
}

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

# Check and remediate
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: Set '$valueName' to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Failed to set registry value: $valueName. Error: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: '$valueName' is correctly set to $expectedValue."
}
