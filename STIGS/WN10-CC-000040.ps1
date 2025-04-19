<#
.SYNOPSIS
    This PowerShell script ensures that the insecure logons to an SMB server must be disabled.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-19
    Last Modified   : 2025-04-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000040

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000040.ps1 
#>

# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$valueName = "AllowInsecureGuestAuth"
$expectedValue = 0

Write-Output "`nChecking Windows version..."

# Get Windows ReleaseId to determine if it's Windows 10 v1507 (LTSB)
try {
    $releaseId = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
} catch {
    Write-Error "Unable to retrieve Windows version. Exiting."
    exit 1
}

if ($releaseId -eq "1507") {
    Write-Output "Not Applicable: Windows 10 v1507 LTSB does not support this setting."
    return
}

Write-Output "Windows version is $releaseId. Proceeding with SMB guest logon check..."

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

# Evaluate compliance
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    $reported = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: '$valueName' is $reported. Expected: $expectedValue (insecure guest logons disabled)."

    Write-Output "`nRemediating: Setting '$valueName' to $expectedValue..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: '$valueName' set to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: Insecure guest logons are disabled ('$valueName' = $expectedValue)."
}
