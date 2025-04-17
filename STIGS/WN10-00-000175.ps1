<#
.SYNOPSIS
    This PowerShell script ensures to configure the "Secondary Logon" service "Startup Type" to "Disabled" on Windows 10.

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-17
    Last Modified   : 2025-04-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000175

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-00-000175.ps1 
#>

# Define the service name
$serviceName = "seclogon"

Write-Output "`nChecking status of 'Secondary Logon' service..."

try {
    # Get service info
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"

    $startupType = $wmiService.StartMode
    $status = $service.Status

    # Check compliance
    if ($startupType -ne "Disabled" -or $status -eq "Running") {
        Write-Output "Finding: 'Secondary Logon' is not compliant:"
        Write-Output "  - Startup Type: $startupType"
        Write-Output "  - Status: $status"

        Write-Output "`nRemediating..."

        # Stop the service if running
        if ($status -eq "Running") {
            Stop-Service -Name $serviceName -Force
            Write-Output "  - Stopped 'Secondary Logon' service."
        }

        # Disable the service
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Output "  - Set startup type to Disabled."

        Write-Output "`nRemediation complete. 'Secondary Logon' is now disabled."
    } else {
        Write-Output "Compliant: 'Secondary Logon' is Disabled and not running."
    }

} catch {
    Write-Error "Error occurred: $_"
}
