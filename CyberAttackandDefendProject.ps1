# Function to validate user input as 'Y' or 'N'
function Validate-YesNoInput {
    param (
        [string]$prompt
    )
    $response = ''
    while ($response -ne 'Y' -and $response -ne 'N') {
        $response = Read-Host $prompt
        $response = $response.ToUpper()
        if ($response -ne 'Y' -and $response -ne 'N') {
            Write-Host "Please enter 'Y' for Yes or 'N' for No."
        }
    }
    return $response
}

# Ask if the user wants to secure the system
$secureSystem = Validate-YesNoInput "Do you want to secure the system? (Y/N)"

if ($secureSystem -ne "Y") {
    Write-Host "Script canceled."
    exit
}

# Verify Windows Firewall is turned on
$firewallStatus = Get-Service -Name "MpsSvc" | Select-Object -ExpandProperty Status

if ($firewallStatus -ne "Running") {
    $enableFirewall = Validate-YesNoInput "Windows Firewall is not turned on. Enable it now? (Y/N)"
    if ($enableFirewall -eq "Y") {
        Write-Host "Enabling Windows Firewall..."
        Set-Service -Name "MpsSvc" -StartupType Automatic
        Start-Service -Name "MpsSvc"
        Write-Host "Windows Firewall is now enabled."
    } else {
        Write-Host "Windows Firewall remains disabled."
    }
}

# Verify and enable Windows Updates and auto-updates
$windowsUpdateStatus = Get-Service -Name "wuauserv" | Select-Object -ExpandProperty Status

if ($windowsUpdateStatus -ne "Running") {
    $enableWindowsUpdates = Validate-YesNoInput "Windows Updates are not enabled. Enable them now? (Y/N)"
    if ($enableWindowsUpdates -eq "Y") {
        Write-Host "Enabling Windows Updates and auto-updates..."
        Set-Service -Name "wuauserv" -StartupType Automatic
        Start-Service -Name "wuauserv"
        Write-Host "Windows Updates and auto-updates are now enabled."
    } else {
        Write-Host "Windows Updates and auto-updates remain disabled."
    }
}

# Check OS Version (Just a simple info check)
$osVersion = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version
Write-Host "Your current OS version is $osVersion. Please ensure it's up to date with the latest LTS version."

# Make sure Windows Defender is activated
$defenderStatus = Get-Service -Name "WinDefend" | Select-Object -ExpandProperty Status

if ($defenderStatus -ne "Running") {
    $activateDefender = Validate-YesNoInput "Windows Defender is not activated. Activate it now? (Y/N)"
    if ($activateDefender -eq "Y") {
        Write-Host "Activating Windows Defender..."
        Set-MpPreference -DisableRealtimeMonitoring 0
        Write-Host "Windows Defender is now activated."
    } else {
        Write-Host "Windows Defender remains deactivated."
    }
}

# Enable BitLocker on a specific drive without a TPM
$driveLetter = "C:"
$recoveryKeyPath = "C:\BitLockerRecovery"

# Check if the recovery key path exists, and create it if not
if (-not (Test-Path -Path $recoveryKeyPath -PathType Container)) {
    New-Item -Path $recoveryKeyPath -ItemType Directory -Force
}

# Check if BitLocker is already enabled on the drive
$bitlockerStatus = Get-BitLockerVolume -MountPoint $driveLetter | Select-Object -ExpandProperty VolumeStatus

if ($bitlockerStatus -eq "FullyEncrypted") {
    Write-Host "BitLocker is already enabled on drive $driveLetter."
} else {
    Write-Host "Enabling BitLocker on drive $driveLetter without TPM..."
    
    # Prompt the user to set a BitLocker password
    $secureBitlockerKey = Read-Host "Enter a BitLocker password for drive $driveLetter" -AsSecureString
    
    # Enable BitLocker with a password protector
    $enableBitLockerResult = Enable-BitLocker -MountPoint $driveLetter -PasswordProtector -Password $secureBitlockerKey -SkipHardwareTest
    
    # Check if BitLocker was successfully enabled
    if ($enableBitLockerResult -and $enableBitLockerResult.ProtectionStatus -eq "On") {
        Write-Host "BitLocker has been enabled on drive $driveLetter."
        # Save the BitLocker encryption key to a file (securely)
        $secureBitlockerKey | ConvertFrom-SecureString | Out-File -FilePath "$recoveryKeyPath\BitLockerKey.txt"
        Write-Host "The BitLocker encryption key has been saved to $recoveryKeyPath\BitLockerKey.txt. Keep this safe!"
    } else {
        Write-Host "Failed to enable BitLocker on drive $driveLetter."
    }
}

# Check if automatic login is enabled
$autoLogin = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "AutoAdminLogon" -ErrorAction SilentlyContinue

if ($autoLogin.AutoAdminLogon -eq "1") {
    $disableAutoLogin = Validate-YesNoInput "Automatic login is enabled. Disable it now? (Y/N)"
    if ($disableAutoLogin -eq "Y") {
        Write-Host "Disabling automatic login..."
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "AutoAdminLogon" -Value "0"
        Write-Host "Automatic login is now disabled."
    } else {
        Write-Host "Automatic login remains enabled."
    }
} else {
    Write-Host "Automatic login is already disabled."
}

# Disable remote access (e.g., RDP)
$remoteAccessEnabled = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" | Select-Object -ExpandProperty fDenyTSConnections

if ($remoteAccessEnabled -eq 0) {
    $disableRemoteAccess = Validate-YesNoInput "Remote access is enabled. Disable it now? (Y/N)"
    if ($disableRemoteAccess -eq "Y") {
        Write-Host "Disabling remote access..."
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
        Write-Host "Remote access is now disabled."
    } else {
        Write-Host "Remote access remains enabled."
    }
}

# Install MalwareBytes
$installAntivirus = Validate-YesNoInput "Do you want to install MalwareBytes? (Y/N)"

if ($installAntivirus -eq "Y") {
    Write-Host "Downloading and installing MalwareBytes..."

    # Define the download URL
    $downloadUrl = "https://www.malwarebytes.com/api/downloads/mb-windows?filename=MBSetup.exe"

    # Define the installer file path
    $installerPath = Join-Path $env:TEMP "MalwareBytesInstaller.exe"

    # Download the installer
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath

    # Run the installer
    Start-Process -FilePath $installerPath -Wait

    # Check if installation was successful
    $installed = Test-Path "C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe"

    if ($installed) {
        Write-Host "MalwareBytes has been successfully installed."
    } else {
        Write-Host "Failed to install MalwareBytes."
    }
} else {
    Write-Host "MalwareBytes installation skipped."
}

# Check if Adobe Flash Player is installed
$flashInstalled = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player ActiveX' -Name "UninstallString" -ErrorAction SilentlyContinue

if ($flashInstalled -ne $null) {
    $uninstallFlash = Validate-YesNoInput "Adobe Flash Player is installed. Uninstall it now? (Y/N)"
    if ($uninstallFlash -eq "Y") {
        Write-Host "Uninstalling Adobe Flash Player..."
        $uninstallString = $flashInstalled.UninstallString
        Start-Process -FilePath $uninstallString -Wait
        Write-Host "Adobe Flash Player has been uninstalled."
    } else {
        Write-Host "Adobe Flash Player remains installed."
    }
} else {
    Write-Host "Adobe Flash Player is not installed."
}

# Verify and modify Users
$modifyUsers = Validate-YesNoInput "Do you want to modify Users? (Y/N)"

if ($modifyUsers -eq "Y") {
    $users = Get-LocalUser | Select-Object -Property Name, Description
    Write-Host "List of Users:"
    $users | Format-Table -AutoSize

    $removeUser = Read-Host "Do you want to remove a user? (Enter the username or N to skip)"

    if ($removeUser -ne "N") {
        Remove-LocalUser -Name $removeUser -ErrorAction SilentlyContinue
        Write-Host "User '$removeUser' has been removed."
    } else {
        Write-Host "User modification skipped."
    }
}

# Verify and modify Groups
$modifyGroups = Validate-YesNoInput "Do you want to modify Groups? (Y/N)"

if ($modifyGroups -eq "Y") {
    $groups = Get-LocalGroup | Select-Object -Property Name, Description
    Write-Host "List of Groups:"
    $groups | Format-Table -AutoSize

    $removeGroup = Read-Host "Do you want to remove a group? (Enter the group name or N to skip)"

    if ($removeGroup -ne "N") {
        Remove-LocalGroup -Name $removeGroup -ErrorAction SilentlyContinue
        Write-Host "Group '$removeGroup' has been removed."
    } else {
        Write-Host "Group modification skipped."
    }
}

# Summarize changes
Write-Host "Changes Made."
Write-Host "-------------------------"
# You can extend this section to include any other summary items you feel are necessary.

Write-Host "Script completed. This script was planned and architected by Joshua Gutierrez, and checked with ChatGPT."

