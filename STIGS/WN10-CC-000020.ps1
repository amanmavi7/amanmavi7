<#
.SYNOPSIS
    This PowerShell script ensures that the IPv6 source routing must be configured to highest protection.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000020

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000020.ps1 
#>

# Registry configuration
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$valueName = "DisableIpSourceRouting"
$expectedValue = 2

Write-Output "`nChecking IPv6 source routing protection level..."

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

# Evaluate compliance
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    $reportedValue = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: 'DisableIpSourceRouting' is $reportedValue. Expected: $expectedValue (highest protection)."

    Write-Output "`nRemediating: Setting 'DisableIpSourceRouting' to $expectedValue..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: 'DisableIpSourceRouting' set to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Failed to remediate registry setting. Error: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: IPv6 source routing is fully disabled ('DisableIpSourceRouting' = $expectedValue)."
}
