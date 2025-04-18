<#
.SYNOPSIS
    This PowerShell script ensures that Windows 10 must cover or disable the built-in or attached camera when not in use.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000007

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000007.ps1 
#>

# Registry details
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
$valueName = "Value"
$expectedValue = "Deny"

# Optional: Flag device type if known (manually mark N/A if mobile or VTC)
$deviceIsMobile = $false
$deviceIsDedicatedVTC = $false

# Check for camera presence
Write-Output "`nChecking for attached or built-in cameras..."

$cameras = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_PnPEntity | Where-Object {
    $_.PNPClass -eq 'Image' -or $_.Name -match 'Camera'
}

if (-not $cameras) {
    Write-Output "Not Applicable: No camera detected on this system."
    return
}

if ($deviceIsMobile) {
    Write-Output "Not Applicable: This is a mobile device (smartphone/tablet), local AO decision applies."
    return
}

if ($deviceIsDedicatedVTC) {
    Write-Output "Not Applicable: This is a dedicated VTC suite, centrally managed."
    return
}

Write-Output "Camera detected. Checking if access is blocked by registry..."

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

# Get the current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Evaluate and remediate if needed
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    $reportedValue = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: Registry value is '$reportedValue'. Expected: '$expectedValue'."

    Write-Output "`nRemediating: Setting '$valueName' to '$expectedValue'..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type String
        Write-Output "Remediated: '$valueName' set to '$expectedValue' at '$regPath'."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: Camera access is blocked via registry ('$valueName' is set to '$expectedValue')."
}
