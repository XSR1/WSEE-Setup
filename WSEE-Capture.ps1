<# ============================== WSEE-Capture ================================ #>

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" `"$args`"" -Verb RunAs; exit}

# ScriptPath
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") {
	$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
} else { 
	$ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0])
}

function Copy-Files {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [alias("c")]
        [hashtable[]]$Config
    )

    # Retrieve the respective arrays from the config hashtable
    $sources = $Config.Sources
    $destinations = $Config.Destinations
    $robocopy_options = $Config.Robocopy_options

    # Signal Start
    Write-Output "-------------  Copy-Files Started: $(Get-Date)  -------------"

    # Return if sources or destinations are null
    if ($sources.count -eq 0) {
        Write-Output "No sources were specified. Exiting."
        return
    }
    if ($destinations.count -eq 0) {
        Write-Output "No destinations were specified. Exiting."
        return
    }

    # Trim config arrays
    $sources = $sources.Trim()
    $destinations = $destinations.Trim()
    if ($robocopy_options.count -gt 0) {
        $robocopy_options = $robocopy_options.Trim()
    }

    # Initialize source variables
    $sources_valid = @()
    $sources_invalid = @()
    $sources_empty_cnt = 0

    # Store valid and invalid sources into separate arrays, and count the number of empty strings
    foreach ($source in $sources) {
        try {
            $source_valid = Get-Item $source -Force -ErrorAction Stop
            $sources_valid += $source_valid
        }
        catch {
            $e = $_.Exception.Gettype().Name
            if ($e -eq 'ItemNotFoundException') {
                $sources_invalid += $source
            }
            if ($e -eq 'ParameterBindingValidationException') {
                $sources_empty_cnt++
            }
        }
    }

    # Return if all sources are invalid
    if ($sources_valid.count -eq 0) {
        Write-Output "All the sources specified either cannot be found or are empty strings. Exiting."
        return
    }

    # Initialize destination variables
    $destinations_valid = @()
    $destinations_empty_cnt = 0

    # Store valid destinations into separate array, and count the number of empty strings
    foreach ($destination in $destinations) {
        if ($destination -ne '') {
            $destinations_valid += $destination
        }
        if ($destination -eq '') {
            $destinations_empty_cnt++
        }
    }

    # Return if all destinations are empty strings
    if ($destinations_valid.count -eq 0) {
        Write-Output "All destinations specified are empty strings. Exiting."
        return
    }

    # Define command variable
    $cmd = 'robocopy'

    # Signal Summary
    Write-Host "`n- - - - -`n SUMMARY`n- - - - -" -ForegroundColor Cyan

    # Print Summary
    Write-Output "`nSources:" $sources_valid.FullName
    if ($sources_invalid.count -gt 0) {
        Write-Output "`nSources (Not Found):" $sources_invalid
    }
    if ($sources_empty_cnt -gt 0) {
        Write-Output "`nSources (Empty Strings): $sources_empty_cnt"
    }
    Write-Output "`nDestinations:" $destinations_valid
    if ($destinations_empty_cnt -gt 0) {
        Write-Output "`nDestinations (Empty Strings): $destinations_empty_cnt"
    }
    if ($robocopy_options.count -gt 0) {
        Write-Output "`nRobocopy Options: `n$robocopy_options"
    }

    # Signal start copy
    Write-Host "`n`n- - - -`n START`n- - - -" -ForegroundColor Green

    # Make a copy of valid sources to each valid destination
    foreach ($destination_valid in $destinations_valid) {
        Write-Host "`nDestination: $destination_valid" -ForegroundColor Green -BackgroundColor Black

        foreach ($source_valid in $sources_valid) {
            Write-Host "`nSource: $($source_valid.FullName)" -ForegroundColor Yellow -BackgroundColor Black
            Write-Host "Type: $($source_valid.Attributes)" -ForegroundColor Yellow

            # Define parameters depending on whether source is a file or directory
            if (!$source_valid.PSIsContainer) {
                $prm = $source_valid.DirectoryName, $destination_valid, $source_valid.Name + ($robocopy_options | Where-Object { ($_ -ne '/MIR') -and ($_ -ne '/E') -and ($_ -ne '/S') } )      # /MIR, /E, /S will be ignored for file sources
            }
            elseif ($source_valid.PSIsContainer) {
                $prm = $source_valid.FullName, "$($destination_valid)\$($source_valid.Name)" + $robocopy_options
            }

            # Execute Robocopy with set parameters
            Write-Host "Command: $($cmd) $($prm)" -ForegroundColor Yellow
            & $cmd $prm
        }

    }

    # Signal end copy
    Write-Host "`n- - -`n END`n- - -" -ForegroundColor Magenta

    # Signal End
    Write-Output "-------------   Copy-Files Ended: $(Get-Date)   -------------"

}

##############################   Destination directories   ###############################

$CopyPath ="$PSScriptRoot\Essentials"

New-Item -Path "$CopyPath\Registry" -ItemType Directory
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Server" "$CopyPath\Registry\01.reg"
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WSSG" "$CopyPath\Registry\02.reg"
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.wssx" "$CopyPath\Registry\03.reg"
reg export "HKEY_CLASSES_ROOT\.wssx" "$CopyPath\Registry\04.reg"
reg export "HKEY_CLASSES_ROOT\Microsoft.WindowsServerSolutions.InstallAddin.1" "$CopyPath\Registry\05.reg"
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Microsoft.WindowsServerSolutions.InstallAddin.1" "$CopyPath\Registry\06.reg"
reg export "HKEY_CLASSES_ROOT\CLSID\{54F82DAB-FC57-425b-AA4E-2CB9B2DA6034}" "$CopyPath\Registry\07.reg"
reg export "HKEY_CLASSES_ROOT\CLSID\{581D0142-CFE7-4E18-9AC3-979C96BE66CB}" "$CopyPath\Registry\08.reg"
reg export "HKEY_CLASSES_ROOT\TypeLib\{C2DDC667-7DCC-4382-A7B6-B5CEE1989E0B}" "$CopyPath\Registry\09.reg"
reg export "HKEY_CLASSES_ROOT\TypeLib\{D6FE6D43-7DC8-4f74-A730-F33B8EDC8D46}" "$CopyPath\Registry\10.reg"
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\ServerEssentialsRole" "$CopyPath\Registry\11.reg"

###########################   Destination directories   ###########################

$share = "C:\Windows\Microsoft.NET\assembly\GAC_MSIL"

$Config1 = @{

Sources = @(
"$share\AddinInfrastructure"
"$share\AdminCommon"
"$share\AdminCommon.Resources"
"$share\AlertFramework"
"$share\AlertFramework.Resources"
"$share\AuthLib"
"$share\AuthLib.resources"
"$share\certEnroll.interop"
"$share\CertManaged"
"$share\ClientNotificationObjectModel"
"$share\CNetManagement"
"$share\Common"
"$share\Common.Resources"
"$share\CoreProviders"
"$share\DevicesOM"
"$share\HomeAddinContract"
"$share\IdentityManaged"
"$share\MachineIdentityObjectModel"
"$share\MailServiceCommon"
"$share\MailServiceCommon.Resources"
"$share\MediaStreamingObjectModel"
"$share\Microsoft.Deployment.Compression"
"$share\Microsoft.Deployment.WindowsInstaller"
"$share\Microsoft.Windows.ServerEssentials.DirectoryServicesUtility"
"$share\Microsoft.Windows.ServerManager.ServerEssentials.Plugin"
"$share\Microsoft.Windows.ServerManager.ServerEssentials.Plugin.resources"
"$share\Microsoft.WindowsServer.Essentials.Interop"
"$share\Microsoft.WindowsServerSolutions.Administration.ObjectModel"
"$share\Microsoft.WindowsServerSolutions.RemoteConnectionManagementObjectModel"
"$share\MiscUtil"
"$share\NetFwTypeLib"
"$share\NetworkHealthEngine"
"$share\PluginManager"
"$share\Policy.6.1.AddinInfrastructure"
"$share\Policy.6.1.AdminCommon"
"$share\Policy.6.1.AlertFramework"
"$share\Policy.6.1.AuthLib"
"$share\Policy.6.1.CertManaged"
"$share\Policy.6.1.Common"
"$share\Policy.6.1.CoreProviders"
"$share\Policy.6.1.DevicesOM"
"$share\Policy.6.1.MachineIdentityObjectModel"
"$share\Policy.6.1.MediaStreamingObjectModel"
"$share\Policy.6.1.Microsoft.WindowsServerSolutions.Administration.ObjectModel"
"$share\Policy.6.1.NetworkHealthEngine"
"$share\Policy.6.1.ProviderFramework"
"$share\Policy.6.1.SettingsObjectModel"
"$share\Policy.6.1.SKU"
"$share\Policy.6.1.SqmProvider"
"$share\Policy.6.1.SqmProviderUtilities"
"$share\Policy.6.1.StorageOM"
"$share\Policy.6.1.StorageResources"
"$share\Policy.6.1.UserObjectModel"
"$share\Policy.6.1.Wssg.Web"
"$share\Policy.6.1.WssgCommon"
"$share\Policy.6.1.WssHomeGroupObjectModel"
"$share\Policy.6.2.AddinInfrastructure"
"$share\Policy.6.2.AdminCommon"
"$share\Policy.6.2.AlertFramework"
"$share\Policy.6.2.AuthLib"
"$share\Policy.6.2.CertManaged"
"$share\Policy.6.2.Common"
"$share\Policy.6.2.CoreProviders"
"$share\Policy.6.2.DevicesOM"
"$share\Policy.6.2.HomeAddinContract"
"$share\Policy.6.2.MachineIdentityObjectModel"
"$share\Policy.6.2.MailServiceCommon"
"$share\Policy.6.2.MediaStreamingObjectModel"
"$share\Policy.6.2.Microsoft.WindowsServerSolutions.Administration.ObjectModel"
"$share\Policy.6.2.MiscUtil"
"$share\Policy.6.2.NetworkHealthEngine"
"$share\Policy.6.2.ProviderFramework"
"$share\Policy.6.2.ProviderFrameworkExtended"
"$share\Policy.6.2.SettingsObjectModel"
"$share\Policy.6.2.SKU"
"$share\Policy.6.2.SqmProvider"
"$share\Policy.6.2.SqmProviderUtilities"
"$share\Policy.6.2.StorageOM"
"$share\Policy.6.2.StorageResources"
"$share\Policy.6.2.UserObjectModel"
"$share\Policy.6.2.Wssg.HostedEmailBase"
"$share\Policy.6.2.Wssg.HostedEmailObjectModel"
"$share\Policy.6.2.Wssg.PasswordSyncObjectModel"
"$share\Policy.6.2.Wssg.Web"
"$share\Policy.6.2.Wssg.WebApi.Framework"
"$share\Policy.6.2.WssgCommon"
"$share\Policy.6.2.WssHomeGroupObjectModel"
"$share\Policy.6.3.AddinInfrastructure"
"$share\Policy.6.3.AdminCommon"
"$share\Policy.6.3.AlertFramework"
"$share\Policy.6.3.AuthLib"
"$share\Policy.6.3.CertManaged"
"$share\Policy.6.3.Common"
"$share\Policy.6.3.CoreProviders"
"$share\Policy.6.3.DevicesOM"
"$share\Policy.6.3.HomeAddinContract"
"$share\Policy.6.3.MachineIdentityObjectModel"
"$share\Policy.6.3.MailServiceCommon"
"$share\Policy.6.3.MediaStreamingObjectModel"
"$share\Policy.6.3.Microsoft.WindowsServerSolutions.Administration.ObjectModel"
"$share\Policy.6.3.MiscUtil"
"$share\Policy.6.3.NetworkHealthEngine"
"$share\Policy.6.3.ProviderFramework"
"$share\Policy.6.3.ProviderFrameworkExtended"
"$share\Policy.6.3.SettingsObjectModel"
"$share\Policy.6.3.SKU"
"$share\Policy.6.3.SqmProvider"
"$share\Policy.6.3.SqmProviderUtilities"
"$share\Policy.6.3.StorageOM"
"$share\Policy.6.3.StorageResources"
"$share\Policy.6.3.UserObjectModel"
"$share\Policy.6.3.Wssg.HostedEmailBase"
"$share\Policy.6.3.Wssg.HostedEmailObjectModel"
"$share\Policy.6.3.Wssg.PasswordSyncObjectModel"
"$share\Policy.6.3.Wssg.Web"
"$share\Policy.6.3.Wssg.WebApi.Framework"
"$share\Policy.6.3.WssgCommon"
"$share\Policy.6.3.WssHomeGroupObjectModel"
"$share\ProviderFramework"
"$share\ProviderFrameworkExtended"
"$share\SettingsObjectModel"
"$share\SetupCommon"
"$share\Sku"
"$share\SkuResources"
"$share\SkuResources.resources"
"$share\SqmProvider"
"$share\SqmProviderUtilities"
"$share\storageif"
"$share\StorageOM"
"$share\StorageResources"
"$share\StorageResources.resources"
"$share\UPnPLib"
"$share\UserObjectModel"
"$share\Wssg.AzureAD.Objects"
"$share\Wssg.AzureAD.ServiceManagement"
"$share\Wssg.FileAccess"
"$share\Wssg.FileAccess.Resources"
"$share\Wssg.HostedEmailBase"
"$share\Wssg.HostedEmailObjectModel"
"$share\Wssg.PasswordSyncObjectModel"
"$share\WSSG.PowerShell"
"$share\WSSG.PowerShell.resources"
"$share\Wssg.Setup.ICCommon"
"$share\Wssg.Setup.ICCommon.Resources"
"$share\Wssg.Web.Common"
"$share\Wssg.Web"
"$share\Wssg.WebApi.Framework"
"$share\WssgCertMgmt"
"$share\WssgCertMgmt.resources"
"$share\WssgCommon"
"$share\WssgCommon.resources"
)

Destinations = @(
    "$CopyPath\Windows\Microsoft.NET\assembly\GAC_MSIL"
)

Robocopy_options = @(
    '/MIR'                     # Mirrored copy. Equivalent to /E plus /PURGE
    '/SEC'                     # Include security info
    "/LOG+:$exepath\log.txt"  # Append output to log file. Directory of log file must already exist
)

}

###########################   Destination directories   ###########################

$Config2 = @{

Sources = @(
	"C:\Program Files\Windows Server"
)

Destinations = @(
    "$CopyPath\Program Files"
)

Robocopy_options = @(
    '/MIR'                     # Mirrored copy. Equivalent to /E plus /PURGE
    '/SEC'                     # Include security info
    "/LOG+:$exepath\log.txt"  # Append output to log file. Directory of log file must already exist
)

}

###########################   Destination directories   ###########################

$Config3 = @{

Sources = @(
	"C:\Program Files (x86)\Windows Server"
)

Destinations = @(
    "$CopyPath\Program Files (x86)"
)

Robocopy_options = @(
    '/MIR'                     # Mirrored copy. Equivalent to /E plus /PURGE
    '/SEC'                     # Include security info
    "/LOG+:$exepath\log.txt"  # Append output to log file. Directory of log file must already exist
)

}

###########################   Destination directories   ###########################

$Config4 = @{

Sources = @(
	"C:\ProgramData\Microsoft\Windows Server"
)

Destinations = @(
    "$CopyPath\ProgramData\Microsoft"
)

Robocopy_options = @(
    '/MIR'                     # Mirrored copy. Equivalent to /E plus /PURGE
    '/SEC'                     # Include security info
    "/LOG+:$exepath\log.txt"  # Append output to log file. Directory of log file must already exist
)

}

###########################   Destination directories   ###########################

$Config5 = @{

Sources = @(
	"C:\Windows\System32\Essentials"
)

Destinations = @(
    "$CopyPath\Windows\System32"
)

Robocopy_options = @(
    '/MIR'                     # Mirrored copy. Equivalent to /E plus /PURGE
    '/SEC'                     # Include security info
    "/LOG+:$exepath\log.txt"  # Append output to log file. Directory of log file must already exist
)

}


###########################   Destination directories   ###########################

$Config6 = @{

Sources = @(
	"C:\Windows\System32\WindowsPowerShell\v1.0\Modules\WssCmdlets"
	"C:\Windows\System32\WindowsPowerShell\v1.0\Modules\WssSetupCmdlets"
)

Destinations = @(
    "$CopyPath\Windows\System32\WindowsPowerShell\v1.0\Modules"
)

Robocopy_options = @(
    '/MIR'                     # Mirrored copy. Equivalent to /E plus /PURGE
    '/SEC'                     # Include security info
    "/LOG+:$exepath\log.txt"  # Append output to log file. Directory of log file must already exist
)

}

###########################   Destination directories   ###########################

$Config7 = @{

Sources = @(
	"C:\Windows\System32\EssentialsRoleConfigWizard.exe"
	"C:\Windows\System32\EssentialsConfigPluginNative.dll"
)

Destinations = @(
    "$CopyPath\Windows\System32"
)

Robocopy_options = @(
    '/MIR'                     # Mirrored copy. Equivalent to /E plus /PURGE
    '/SEC'                     # Include security info
    "/LOG+:$exepath\log.txt"  # Append output to log file. Directory of log file must already exist
)

}


###################################################################################

# Run Copy-Files
Copy-Files -Config $Config1
Copy-Files -Config $Config2
Copy-Files -Config $Config3
Copy-Files -Config $Config4
Copy-Files -Config $Config5
Copy-Files -Config $Config6
Copy-Files -Config $Config7

# Pause
pause

