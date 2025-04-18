<#
.SYNOPSIS
    This PowerShell script ensures that the Security event log size must be configured to 1024000 KB or greater.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000505

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AU-000505.ps1 
#>

# Define required registry settings
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$valueName = "MaxSize"
$requiredMinSize = 1024000

# Optional override: Set this to $true if audit forwarding is used and documented with ISSO
$usingAuditServer = $false

# Check NA condition
if ($usingAuditServer) {
    Write-Output "Not Applicable: Audit records are forwarded to a centralized audit server (must be documented with ISSO)."
    return
}

Write-Output "`nChecking Security Event Log MaxSize setting..."

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

# Get current MaxSize value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

# Check compliance
if ($null -eq $currentValue -or $currentValue.$valueName -lt $requiredMinSize) {
    $currentReported = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
    Write-Output "Finding: MaxSize is $currentReported KB (must be at least $requiredMinSize KB)."

    Write-Output "`nRemediating: Setting MaxSize to $requiredMinSize KB..."
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $requiredMinSize -Type DWord
        Write-Output "Remediated: MaxSize set to $requiredMinSize KB at $regPath."
    } catch {
        Write-Error "Remediation failed: $_"
        exit 1
    }
} else {
    Write-Output "Compliant: MaxSize is $($currentValue.$valueName) KB (meets or exceeds $requiredMinSize KB)."
}
