<#
.SYNOPSIS
    This PowerShell script ensures that the display of slide shows on the lock screen must be disabled.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000010.ps1 
#>

# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenSlideshow"
$expectedValue = 1

Write-Output "`nChecking if lock screen slideshow is disabled..."

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

# Retrieve current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Evaluate compliance
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    $reportedValue = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: 'NoLockScreenSlideshow' is $reportedValue. Expected: $expectedValue."

    Write-Output "`nRemediating: Disabling lock screen slideshow..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: 'NoLockScreenSlideshow' set to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Failed to remediate registry setting. Error: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: Lock screen slideshow is already disabled ('NoLockScreenSlideshow' = $expectedValue)."
}
