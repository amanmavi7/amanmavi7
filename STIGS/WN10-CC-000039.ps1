<#
.SYNOPSIS
    This PowerShell script ensures that the run as different user must be removed from context menus.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-19
    Last Modified   : 2025-04-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000039

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000039.ps1 
#>

# Registry base path and value settings
$basePath = "HKLM:\SOFTWARE\Classes"
$suffixPaths = @(
    "batfile\shell\runasuser",
    "cmdfile\shell\runasuser",
    "exefile\shell\runasuser",
    "mscfile\shell\runasuser"
)
$valueName = "SuppressionPolicy"
$expectedValue = 4096

Write-Output "`nChecking 'Run as Different User' context menu suppression..."

foreach ($suffix in $suffixPaths) {
    $regPath = Join-Path $basePath $suffix

    # Ensure the registry path exists
    if (-not (Test-Path $regPath)) {
        try {
            New-Item -Path $regPath -Force | Out-Null
            Write-Output "Created missing registry path: $regPath"
        } catch {
            Write-Error "Failed to create registry path: $regPath"
            continue
        }
    }

    # Get current value
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

    # Evaluate and remediate
    if ($null -eq $currentValue -or $currentValue.$valueName -ne $expectedValue) {
        $reported = if ($null -eq $currentValue) { "Not Set" } else { $currentValue.$valueName }
        Write-Output "Finding: '$valueName' at '$regPath' is $reported. Expected: $expectedValue."

        Write-Output "Remediating: Setting '$valueName' to $expectedValue..."
        try {
            Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
            Write-Output "Remediated: '$valueName' set to $expectedValue at '$regPath'."
        } catch {
            Write-Error "Failed to set value at $regPath. Error: $_"
        }
    } else {
        Write-Output "Compliant: '$valueName' at '$regPath' is set to $expectedValue."
    }
}
