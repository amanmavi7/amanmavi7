<#
.SYNOPSIS
    This PowerShell script ensures that the camera access from the lock screen must be disabled.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000005.ps1 
#>

# Define registry settings
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenCamera"
$expectedValue = 1

Write-Output "`nChecking if device has a camera..."

# Check for connected cameras (Device Class = Image, PNPClass = Camera)
$cameras = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_PnPEntity | Where-Object {
    $_.PNPClass -eq 'Image' -or $_.Name -match 'Camera'
}

if (-not $cameras) {
    Write-Output "Not Applicable: No camera detected on this device."
    return
}

Write-Output "Camera detected. Checking lock screen camera policy setting..."

# Ensure registry path exists
if (-not (Test-Path $regPath)) {
    try {
        New-Item -Path $regPath -Force | Out-Null
        Write-Output "Created missing registry path: $regPath"
    } catch {
        Write-Error "Failed to create registry path: $regPath"
        exit 1
    }
}

# Get current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Evaluate and remediate
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    $reportedValue = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: 'NoLockScreenCamera' is $reportedValue (expected: $expectedValue)."

    Write-Output "`nRemediating: Setting '$valueName' to $expectedValue..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: '$valueName' set to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: Lock screen camera access is disabled ('$valueName' is set to $expectedValue)."
}
