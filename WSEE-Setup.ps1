<# ============================== WSEE-Setup ================================ #>

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" `"$args`"" -Verb RunAs; exit}

$host.UI.RawUI.WindowTitle = "Windows Server Essentials Role - Setup"

if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") {
	$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
} else { 
	$ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0])
}

function New-Shortcut {

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=0)] 
    [Alias("File","Shortcut")] 
    [string]$Path,

    [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=1)] 
    [Alias("Target")] 
    [string]$TargetPath,

    [Parameter(ValueFromPipelineByPropertyName=$True,Position=2)] 
    [Alias("Args","Argument")] 
    [string]$Arguments,

    [Parameter(ValueFromPipelineByPropertyName=$True,Position=3)]  
    [Alias("Desc")]
    [string]$Description,

    [Parameter(ValueFromPipelineByPropertyName=$True,Position=4)]  
    [string]$HotKey,

    [Parameter(ValueFromPipelineByPropertyName=$True,Position=5)]  
    [Alias("WorkingDirectory","WorkingDir")]
    [string]$WorkDir,

    [Parameter(ValueFromPipelineByPropertyName=$True,Position=6)]  
    [int]$WindowStyle,

    [Parameter(ValueFromPipelineByPropertyName=$True,Position=7)]  
    [string]$Icon,

    [Parameter(ValueFromPipelineByPropertyName=$True)]  
    [switch]$admin
)

Process {

  If (!($Path -match "^.*(\.lnk)$")) {
    $Path = "$Path`.lnk"
  }
  [System.IO.FileInfo]$Path = $Path
  Try {
    If (!(Test-Path $Path.DirectoryName)) {
      md $Path.DirectoryName -ErrorAction Stop | Out-Null
    }
  } Catch {
    Write-Verbose "Unable to create $($Path.DirectoryName), shortcut cannot be created"
    Return $false
    Break
  }

  # Define Shortcut Properties
  $WshShell = New-Object -ComObject WScript.Shell
  $Shortcut = $WshShell.CreateShortcut($Path.FullName)
  $Shortcut.TargetPath = $TargetPath
  $Shortcut.Arguments = $Arguments
  $Shortcut.Description = $Description
  $Shortcut.HotKey = $HotKey
  $Shortcut.WorkingDirectory = $WorkDir
  $Shortcut.WindowStyle = $WindowStyle
  If ($Icon){
    $Shortcut.IconLocation = $Icon
  }

  Try {
    # Create Shortcut
    $Shortcut.Save()
    # Set Shortcut to Run Elevated
    If ($admin) {     
      $TempFileName = [IO.Path]::GetRandomFileName()
      $TempFile = [IO.FileInfo][IO.Path]::Combine($Path.Directory, $TempFileName)
      $Writer = New-Object System.IO.FileStream $TempFile, ([System.IO.FileMode]::Create)
      $Reader = $Path.OpenRead()
      While ($Reader.Position -lt $Reader.Length) {
        $Byte = $Reader.ReadByte()
        If ($Reader.Position -eq 22) {$Byte = 34}
        $Writer.WriteByte($Byte)
      }
      $Reader.Close()
      $Writer.Close()
      $Path.Delete()
      Rename-Item -Path $TempFile -NewName $Path.Name | Out-Null
    }
    Return $True
  } Catch {
    Write-Verbose "Unable to create $($Path.FullName)"
    Write-Verbose $Error[0].Exception.Message
    Return $False
  }

}
}

# Windows Server Essentials Install
if (!(Test-Path -Path "$env:SystemRoot\system32\Essentials")) {

	Write-Host "Installing  Windows Server Essentials Role.."

	# Install the following (5) required prerequisite server roles
	Install-WindowsFeature -Name RSAT-RemoteAccess-PowerShell
	Install-WindowsFeature -Name Windows-Server-Backup
	Install-WindowsFeature -Name FS-DFS-Namespace
	Install-WindowsFeature -Name FS-BranchCache
	Install-WindowsFeature -Name BranchCache

	# Copy the following (7) required folders
	Dism /Apply-Image /ImageFile:"$ScriptPath\Essentials.wim" /Index:"1" /ApplyDir:"$env:SystemDrive\"
	Get-Item "$env:SystemDrive\ProgramData" -Force | foreach {$_.attributes = "Hidden"} | Out-Null

	# Copy the following (10) required registry key branches
	$Reg = Get-ChildItem -Path (Join-Path -Path "$env:SystemDrive" -ChildPath Registry) -Filter "*.reg"
	ForEach ($Regs In $Reg) {Reg import $Regs.FullName | Out-Null}

	# Remove Folder
	Remove-Item "$env:SystemDrive\Registry" -Recurse | Out-Null

	# Create the following (8) required services
	SC.exe CREATE "WseStorageSvc" start= disabled binpath= "$env:SystemRoot\System32\Essentials\storageservice.exe" depend= rpcss/samss/vds/winmgmt DisplayName= "Windows Server Essentials Storage Service" | Out-Null
	SC.exe CREATE "ServiceProviderRegistry" start= disabled binpath= "$env:SystemRoot\System32\Essentials\ProviderRegistryService.exe" depend= KeyIso/NetTcpPortSharing DisplayName= "Windows Server Essentials Provider Registry Service" | Out-Null
	SC.exe CREATE "WseComputerBackupSvc" start= disabled binpath= "$env:SystemRoot\System32\Essentials\WSSBackup.exe" depend= rpcss/samss/tcpip DisplayName= "Windows Server Essentials Computer Backup Service" | Out-Null
	SC.exe CREATE "WseNtfSvc" type= share start= disabled binpath= ""$env:SystemRoot\System32\Essentials\SharedServiceHost.exe" "$env:SystemRoot\System32\Essentials\NotificationServiceConfig"" depend= ServiceProviderRegistry DisplayName= "Windows Server Essentials Notification Service" | Out-Null
	SC.exe CREATE "WseMgmtSvc" type= share start= disabled binpath= ""$env:SystemRoot\System32\Essentials\SharedServiceHost.exe" "$env:SystemRoot\System32\Essentials\ManagementServiceConfig"" depend= ServiceProviderRegistry DisplayName= "Windows Server Essentials Management Service" | Out-Null
	SC.exe CREATE "WseHealthSvc" type= share start= disabled binpath= ""$env:SystemRoot\System32\Essentials\SharedServiceHost.exe" "$env:SystemRoot\System32\Essentials\HealthServiceConfig"" depend= ServiceProviderRegistry/eventlog DisplayName= "Windows Server Essentials Health Service" | Out-Null
	SC.exe CREATE "WseEmailSvc" type= share start= disabled binpath= ""$env:SystemRoot\System32\Essentials\SharedServiceHost.exe" "$env:SystemRoot\System32\Essentials\EmailProviderServiceConfig"" depend= ServiceProviderRegistry DisplayName= "Windows Server Essentials Email Service" | Out-Null
	SC.exe CREATE "WseMediaSvc" start= disabled binpath= "$env:SystemRoot\System32\Essentials\MediaStreamingProvider.exe" depend= ServiceProviderRegistry DisplayName= "Windows Server Essentials Media Streaming Service" | Out-Null

	# Add a rule to allow the "Windows Server Essentials Client Backup Service" through the Windows Defender Firewall 
	netsh advfirewall firewall add rule name="Windows Server Essentials Client Backup Service" dir=in action=allow program="$env:SystemRoot\System32\Essentials\WSSBackup.exe" enable=yes profile=any | Out-Null

	# Shortcuts
	New-Shortcut -Path "$env:programdata\Microsoft\Windows\Start Menu\Programs\Windows Server Essentials\Dashboard.lnk" -TargetPath "$env:SystemRoot\system32\Essentials\Dashboard.exe" -Description "Windows Server Essentials Dashboard" | Out-Null
	New-Shortcut -Path "$env:Public\Desktop\Dashboard.lnk" -TargetPath "$env:SystemRoot\system32\Essentials\Dashboard.exe" -Description "Windows Server Essentials Dashboard" | Out-Null

	# RunOnce after Restart
	Set-Itemproperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" "WSEERunOnce" "$env:SystemRoot\System32\EssentialsRoleConfigWizard.exe"
	Restart-Computer

} else {
	
	# Show Status
	Get-WssConfigurationStatus -ShowProgress

}

#pause