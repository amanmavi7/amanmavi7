<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Amanjot Mavi
    LinkedIn        : linkedin.com/in/amanjot-mavi-it-support/
    GitHub          : github.com/amanmavi7
    Date Created    : 2025-04-15
    Last Modified   : 2025-04-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# YOUR CODE GOES HERE

# Define the registry path and values
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$propertyName = "MaxSize"
$propertyValue = 0x8000  # Hexadecimal 0x8000 = 32768 decimal

# Create the registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the registry value
New-ItemProperty -Path $regPath -Name $propertyName -PropertyType DWord -Value $propertyValue -Force | Out-Null

Write-Host "Registry value 'MaxSize' set to 0x8000 under $regPath"
