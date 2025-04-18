<#
.SYNOPSIS
    This PowerShell script ensures that the system must be configured to ignore NetBIOS name release requests except from WINS servers.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000035.ps1 
#>

# Registry configuration
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
$valueName = "NoNameReleaseOnDemand"
$expectedValue = 1

Write-Output "`nChecking NetBIOS name release protection setting..."

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

# Get current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Evaluate and remediate
if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
    $reportedValue = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: 'NoNameReleaseOnDemand' is $reportedValue. Expected: $expectedValue (Enabled)."

    Write-Output "`nRemediating: Enabling NetBIOS name release protection..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
        Write-Output "Remediated: 'NoNameReleaseOnDemand' set to $expectedValue at '$regPath'."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: NetBIOS name release protection is enabled ('NoNameReleaseOnDemand' = $expectedValue)."
}
