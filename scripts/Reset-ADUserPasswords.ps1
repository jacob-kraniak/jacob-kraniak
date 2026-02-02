# Reset-ADUserPasswords.ps1
# Purpose: Bulk reset AD user passwords from a CSV file.
# Author: Jacob Kraniak
# Requirements: ActiveDirectory module (Import-Module ActiveDirectory), Run as AD admin.
# Run in PowerShell (elevated): .\Reset-ADUserPasswords.ps1 -CsvPath ""C:\PowerShell Scripts\password resets.csv""

$CsvPath = "C:\PowerShell Scripts\password resets.csv"

# Import required module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Active Directory module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import Active Directory module. Ensure RSAT is installed."
    exit 1
}

# Validate CSV file exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    exit 1
}

# Read CSV
try {
    $users = Import-Csv -Path $CsvPath
    Write-Host "Loaded $($users.Count) users from CSV." -ForegroundColor Green
} catch {
    Write-Error "Failed to read CSV: $($_.Exception.Message)"
    exit 1
}

# Initialize log (output to console and file)
$LogPath = "C:\ADPasswordResetLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$successCount = 0
$errorCount = 0

Write-Host "Starting password reset process..." -ForegroundColor Yellow
Add-Content -Path $LogPath -Value "$(Get-Date): Script started. Log for $($users.Count) users."

foreach ($user in $users) {
   $upn = $user.UserPrincipalName
    $newPassword = $user.NewPassword

    # Validate required fields
    if (-not $upn -or -not $newPassword) {
        Write-Warning "Skipping invalid entry: Missing UserPrincipalName or NewPassword for row."
        Add-Content -Path $LogPath -Value "$(Get-Date): WARNING - Skipped invalid entry for UPN: $upn"
        $errorCount++
        continue
    }

    try {
        # Search for user by UPN
        $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -ErrorAction Stop
        Write-Host "Processing user: $upn" -ForegroundColor Cyan

        # Convert password to secure string
        $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force

        # Reset password
        if ($WhatIf) {
            Set-ADAccountPassword -Identity $adUser.SamAccountName -NewPassword $securePassword -WhatIf
            Write-Host "  [SIMULATED] Password reset for $upn" -ForegroundColor Yellow
            Add-Content -Path $LogPath -Value "$(Get-Date): SIMULATED - Password reset for $upn"
        } else {
            Set-ADAccountPassword -Identity $adUser.SamAccountName -NewPassword $securePassword -Reset
            # Optional: Force password change at next logon
            # Set-ADUser -Identity $adUser.SamAccountName -ChangePasswordAtLogon $true

            Write-Host "  Password reset successfully for $upn" -ForegroundColor Green
            Add-Content -Path $LogPath -Value "$(Get-Date): SUCCESS - Password reset for $upn"
            $successCount++
        }
    } catch {
        Write-Error "Failed to reset password for $upn : $($_.Exception.Message)"
        Add-Content -Path $LogPath -Value "$(Get-Date): ERROR - Failed for $upn : $($_.Exception.Message)"
        $errorCount++
    }
}

# Summary
Write-Host "`nSummary:" -ForegroundColor Yellow
Write-Host "  Successful resets: $successCount" -ForegroundColor Green
Write-Host "  Errors/Failures: $errorCount" -ForegroundColor Red
Write-Host "  Log saved to: $LogPath" -ForegroundColor Cyan
Add-Content -Path $LogPath -Value "$(Get-Date): Script completed. Success: $successCount, Errors: $errorCount"
