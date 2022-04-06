
<#



|||||| CSIR PROJECT ||||||

Author: https://github.com/Hayaiken/
Version: 1



Objectives:
    
    Collect Several Security Information


Prerequisite:
    
    - Security Programs:
        Append The Values In The Custom Object $Security_Softwares With New Programs As Follows
        $Security_Softwares += [PSCustomObject] @{'Name' = "Test Program" ; 'Service' = "Test Service"}



How To Use:

    - Run The Code From Powershell / Powershell ISE As Administrator
    - Run The Code From CMD As Administrator Using The Command "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Maximized -File CSIR.ps1"



To Update:

    - Convert The Code as a Function-Based
    - Make it Run continuously
    - Create Gui Based
    - Add RDP <<< Need Fix
    - Add Security Settings Check Like : CMD/PS/BAT/VBS/HTA Enabled/Disabled , Proxy , ... etc
    - Browsers Extensions
    - Enhance Run Registry Function
    - Powershell Logging
    - EDR Agents




Resources:
https://adamtheautomator.com/html-report/
https://gist.github.com/scuq/1c9c74a952da3aee06c8
https://gist.github.com/talatham/ad406d5428ccec641f075a7019cd29a8
https://itluke.online/2018/11/27/how-to-display-firewall-rule-ports-with-powershell/
https://stackoverflow.com/questions/3405122/get-uac-settings-using-powershell

#>


$header = @"
<style>
    body{
    
   		Background: #1A1B2D;
        Color: #ffffff;
        font-family: Verdana;
        font-size: 13px;
    
    }
    
    h1 {

        font-family: Verdana;
        color: #FFF;
        font-size: 28px;

    }

    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color:#56C3FE;
        font-size: 16px;

    }
    
    h3 {

        font-family: Arial, Helvetica, sans-serif;
        color: #e68a00;
        font-size: 14px;
        
    }
    
    .SubHeaders {

        font-family: Segoe UI;
        margin: 10px;
        color: #94B5C0;
        font-weight: bold;
        font-size: 11px;
        text-transform: uppercase;
        background: #1A1B2D;
   
   }

    table {
   		
        margin: 5px;
        font-size: 12px;
        border: 0px;
        font-family: Segoe UI;
        width: -webkit-fill-available;
        border-collapse: collapse;
         
	} 
	
    td {
        padding-bottom: 5px;
        padding-top: 5px;
        padding-right: 5px;
        padding-left: 10px;
        margin: 0px;
        border-bottom: 5px solid #1A1B2D;
        
	}
	
    th {
        
        padding-top: 5px;
        padding-right: 5px;
        padding-bottom: 10px;
        padding-left: 5px;
        color: #94B5C0;
        font-size: 11px;
        text-transform: uppercase;
        background: #1A1B2D;
        
	}

    tr {

        background: #222335;
        text-align: justify;
        
    }
    
    .MultiCellsContainer {

        display:flex;
	    flex-flow:wrap;
    
    }

	.MultiCells {

        margin-bottom: 5px;
        margin-right: 5px;
        margin-left: 5px;
        border-left: 3px Solid #26C4D6;
        background: #222335;
        padding: 5px;
        padding-right: 10px;
        padding-left: 10px;
        font-size: 12px;
        font-family: Segoe UI;
        flex-grow: 1;
        
    }

    .MultiCells:hover{

        border-left: 3px Solid #2D46B9;
        background:#1E3163;

   }

    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #F8485E;
        font-size: 12px;

    }
    
    .RunningStatus {

        color: #42D9C8;
    
    }

    .StopStatus {

        color: #F8485E;
    
    }

    .EnabledUsers {
    
        color: #26C4D6;
    
    }

    .DisabledUsers {
        
        color: #F8485E;

    }

    .EnabledStatus {
    
        color: #26C4D6;
    
    }

    .DisabledStatus {
        
        color: #F8485E;

    }

    .AllowSSID {
    
        color: #26C4D6;
    
    }

    .BlockSSID {
        
        color: #F8485E;

    }

    .InterfaceUp {
    
        color: #26C4D6;
    
    }

    .InterfaceDisconnected {
        
        color: #F8485E;

    }

    tbody tr td:first-child {

        border-left: 3px Solid #26C4D6;
    }

	hr {

        border: 1px solid #26263A;

	}
    
    tr:hover,  tr:hover td {
        
        background:#1E3163;
        color:#fff;
    
    }
     
   tr:hover td:first-child{
        
        border-left: 3px Solid #2D46B9;
   
    }
    
</style>
"@



# Checking Powershell

if (($pshome -like "*syswow64*") -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -like "64*")) {
    write-warning "Restarting script under 64 bit powershell"
 
    # relaunch this script under 64 bit shell
    & (join-path ($pshome -replace "syswow64", "sysnative")\powershell.exe) -file $myinvocation.mycommand.Definition @args
 
    # This will exit the original powershell process. This will only be done in case of an x86 process on a x64 OS.
    exit
}




# Checking Admin Privileges

$GetPrivilege = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

if ($GetPrivilege.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {

    Clear-Host

    Write-Host "Admin Privilege is Required to Start. Kindly Run Again As Admin" -BackgroundColor DarkRed

    Start-Sleep -S 2

    Exit

}




# Checking Registry Privileges

if (Test-Path "HKCU:\Software\Policies\Microsoft\Windows\System") {

    Clear-Host

    if ($null -ne (Get-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\System").GetValue("DisableRegistryTools") -and (Get-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\System").GetValue("DisableRegistryTools") -eq "1"){

    Write-Host "Registry Editing Privilege is Required to Start." -BackgroundColor DarkRed

    Start-Sleep -S 2

    Exit

    }

}


# Main Variables

$ReportElements = @()

$ReportElementsHTML = @()

$FinalReport = @()

$FinalReportHTML = @()



# Selection Menu

$toDO = @()

$List = @()

$List += [PSCustomObject] @{'col1' = "`t a - All" ; 'col2' = "`t b - Workstation Info"; 'col3' = "`t c - Workstation GPO" ; 'col4' = "`t d - Security Software Status" }

$List += [PSCustomObject] @{'col1' = "`t e - Windows Update Service Status" ; 'col2' = "`t f - Local Users"; 'col3' = "`t g - Local Administrators" ; 'col4' = "`t h - Users Profile" }

$List += [PSCustomObject] @{'col1' = "`t i - Deleted Local Accounts" ; 'col2' = "`t j - Users GPO"; 'col3' = "`t k - Last Successful Logon (10 Days)" ; 'col4' = "`t l - Last Failed Logon (10 Days)" }

$List += [PSCustomObject] @{'col1' = "`t m - Groupless Firewall Rules" ; 'col2' = "`t n - Intsalled Programs"; 'col3' = "`t o - Run Registry" ; 'col4' = "`t p - SMB" }

$List += [PSCustomObject] @{'col1' = "`t q - Wireless Network" ; 'col2' = "`t r - TaskScheduler List"; 'col3' = "`t s - Workstation Services" ; 'col4' = "`t t - Security Settings"}

$List += [PSCustomObject] @{'col1' = "`t u - TCP Connections" ; 'col2' = "`t v - RDP" ; 'col3' = "`t w - Browsers Extensions"}

$List += [PSCustomObject] @{'col1' = "" }

$List += [PSCustomObject] @{'col2' = "0 - Clear" ; 'col3' = "1 - Start"; 'col4' = "x - Exit" }


:Selection do {

    do {

        Clear-Host

        Write-Host ""

        Write-Host "Select Process:"

        $List | Format-Table  -HideTableHeaders 

        Write-Host "Current Selection(s): "  -NoNewline

        $toDO -join (' | ') 

        $Selection = Read-Host "Select character(s) "
    

        $Valid = $Selection -match '[a-wx01]+$'

        if ( -not $Valid) {

            Write-Host "Invalid selection"

            Start-Sleep -s 1

            Write-Host ""

        }

        if ( $Selection -match '[1]+$' -and "0" -eq $toDO.Length -and $Selection.Length -le '1') {

            Write-Host ""

            Write-Host "You Need To Select at Least One Process" -BackgroundColor DarkRed

            Start-Sleep -s 1

            Write-Host ""

        }

    } until ($Valid)

    Switch -Regex ( $Selection ) {

        "a" {
            if ($toDO -notcontains "All") {
                $toDO = "All"; break Selection 
            }
        }

        "b" {
            if ($toDO -notcontains "Workstation Info") {
                $toDO += "Workstation Info"
            }
        }

        "c" {
            if ($toDO -notcontains "Workstation GPO") {
                $toDO += "Workstation GPO"
            }
        }

        "d" {
            if ($toDO -notcontains "Security Software Status") {
                $toDO += "Security Software Status"
            }
        }

        "e" {
            if ($toDO -notcontains "Windows Update Service Status") {
                $toDO += "Windows Update Service Status"
            }
        }

        "f" {
            if ($toDO -notcontains "Local Users") {
                $toDO += "Local Users"
            }
        }
    
        "g" {
            if ($toDO -notcontains "Local Administrators") {
                $toDO += "Local Administrators"
            }
        }

        "h" {
            if ($toDO -notcontains "Users Profile") {
                $toDO += "Users Profile"
            }
        }

        "i" {
            if ($toDO -notcontains "Deleted Local Accounts") {
                $toDO += "Deleted Local Accounts"
            }
        }

        "j" {
            if ($toDO -notcontains "Users GPO") {
                $toDO += "Users GPO"
            }
        }

        "k" {
            if ($toDO -notcontains "Last Successful Logon") {
                $toDO += "Last Successful Logon"
            }
        }

        "l" {
            if ($toDO -notcontains "Last Failed Logon") {
                $toDO += "Last Failed Logon"
            }
        }

        "m" {
            if ($toDO -notcontains "Groupless Firewall Rules") {
                $toDO += "Groupless Firewall Rules"
            }
        }

        "n" {
            if ($toDO -notcontains "Intsalled Programs") {
                $toDO += "Intsalled Programs"
            }
        }

        "o" {
            if ($toDO -notcontains "Run Registry") {
                $toDO += "Run Registry"
            }
        }

        "p" {
            if ($toDO -notcontains "SMB") {
                $toDO += "SMB"
            }
        }

        "q" {
            if ($toDO -notcontains "Wireless Network") {
                $toDO += "Wireless Network"
            }
        }

        "r" {
            if ($toDO -notcontains "TaskScheduler List") {
                $toDO += "TaskScheduler List"
            }
        }

        "s" {
            if ($toDO -notcontains "Workstation Services") {
                $toDO += "Workstation Services"
            }
        }

        "t" {
            if ($toDO -notcontains "Security Settings") {
                $toDO += "Security Settings"
            }
        }

        "u" {
            if ($toDO -notcontains "TCP Connections") {
                $toDO += "TCP Connections"
            }
        }

        "v" {
            if ($toDO -notcontains "RDP") {
                $toDO += "RDP"
            }
        }

        "w" {
            if ($toDO -notcontains "Browsers Extensions") {
                $toDO += "Browsers Extensions"
            }
        }
       
        "x" { exit }

        "0" { $toDO = @() }

    }

} until ( $Selection -match "1" -and "0" -ne $toDO.length)



Clear-Host

# Workstation Info ---------------------------------------------------

Write-Progress -Activity "Collecting Workstation Info"

$WorkstationInfo = @()

$WorkstationInfoHTML = @()

if ($toDo -contains 'All' -or $toDO -contains "Workstation Info") {

    $WorkstationName = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty Name

    $WorkstationDomain = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain

    $WorkstationOS = Get-WmiObject Win32_OperatingSystem | Select-Object Caption , Version, OSArchitecture 

    $WorkstaionNet = Get-WmiObject win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq 'True' -and $_.DefaultIPGateway -ne $null } | Select-Object DHCPEnabled, DHCPServer, DNSDomain, DNSServerSearchOrder, IPAddress, MACAddress 

    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {

        $WorkstationLocation = ([adsisearcher]"Name=$env:Computername").Findone().Properties.distinguishedname

        $WorkstationOU = (($WorkstationLocation -split (',') | Where-Object { $_ -like 'OU=*' } | Sort-Object -Descending ) -join '/').replace('OU=', '')

        $WorkstationDC = (($WorkstationLocation -split (',') | Where-Object { $_ -like 'DC=*' } ) -join '.').replace('DC=', '')

        $WorkstationLocation = "$WorkstationDC/$WorkstationOU"

        $WorkstationInfo = [PSCustomObject] @{'Name' = $WorkstationName ; 'Domain' = $WorkstationDomain ; 'Location' = $WorkstationLocation ; 'OS' = $WorkstationOS.Caption; 'OSVersion' = $WorkstationOS.Version ; 'OSArchi' = $WorkstationOS.OSArchitecture ; 'IPAddress' = ($WorkstaionNet.IPAddress | Where-Object { $_ -notlike "*:*" }) -join "`n" ; 'MACAddress' = $WorkstaionNet.MACAddress -join "`n" ; 'DHCPEnabled' = $WorkstaionNet.DHCPEnabled -join "`n" ; 'DHCPServer' = $WorkstaionNet.DHCPServer -join "`n" ; 'DNSDomain' = $WorkstaionNet.DNSDomain -join "`n" ; 'DNSServerSearchOrder' = $WorkstaionNet.DNSServerSearchOrder -join "`n" }

        $WorkstationInfoHTML = $WorkstationInfo | ConvertTo-Html -As List -Property 'Name', 'Domain', 'Location', 'OS' , 'OSVersion' , 'OSArchi' , 'IPAddress' , 'MACAddress' , 'DHCPEnabled' , 'DHCPServer' , 'DNSDomain' , 'DNSServerSearchOrder'  -Fragment

    }

    else {

        $WorkstationInfo = [PSCustomObject] @{'Name' = $WorkstationName ; 'Workgroup' = $WorkstationDomain ; 'OS' = $WorkstationOS.Caption; 'OSVersion' = $WorkstationOS.Version ; 'OSArchi' = $WorkstationOS.OSArchitecture ; 'IPAddress' = ($WorkstaionNet.IPAddress | Where-Object { $_ -notlike "*:*" }) -join "`n" ; 'MACAddress' = $WorkstaionNet.MACAddress -join "`n" ; 'DHCPEnabled' = $WorkstaionNet.DHCPEnabled -join "`n" ; 'DHCPServer' = $WorkstaionNet.DHCPServer -join "`n" ; 'DNSDomain' = $WorkstaionNet.DNSDomain -join "`n" ; 'DNSServerSearchOrder' = $WorkstaionNet.DNSServerSearchOrder -join "`n" } 

        $WorkstationInfoHTML = $WorkstationInfo | ConvertTo-Html -As List -Property 'Name', 'Workgroup', 'OS' , 'OSVersion' , 'OSArchi' , 'IPAddress' , 'MACAddress' , 'DHCPEnabled' , 'DHCPServer' , 'DNSDomain' , 'DNSServerSearchOrder'  -Fragment

    }

    $ReportElements += "====== Workstation Info =======" , ($WorkstationInfo | Format-List)

    $ReportElementsHTML += "<h2>Workstation Info</h2>" , "$WorkstationInfoHTML" , "<hr>"

}

#-------------------------------------------- End of Workstation Info



# Workstation GPO ---------------------------------------------------

Write-Progress -Activity "Collecting Workstation GPO"

$AppliedComputerGPO = @()

$AppliedComputerGPOHTML = @()

$FilteredComputerGPO = @()

$FilteredComputerGPOHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Workstation GPO') {

    $ComputerGPOs = cmd.exe /c "chcp 1256 > nul & Gpresult /r /Scope COMPUTER" 

    For ($i = 0; $i -le $ComputerGPOs.Length; $i++) {

        if ($ComputerGPOs[$i] -like '*Applied Group Policy Objects*') {

            $i = $i + 2

            while ($ComputerGPOs[$i] -notlike $null) {

                $AppliedComputerGPO += [PSCustomObject] @{'AppliedGPO' = $ComputerGPOs[$i].Trim() }

                $i++
            }

        }

        if ($ComputerGPOs[$i] -like '*The following GPOs were not applied because they were filtered out*') {
    
            $i = $i + 2

            while ($ComputerGPOs[$i] -notlike '*The computer is a part of the following security groups*') {
            
                $FilteredComputerGPO += [PSCustomObject] @{'FilteredGPO' = $ComputerGPOs[$i].trim(); 'FilterReason' = $ComputerGPOs[$i + 1].Replace('Filtering:', '').Trim() }
 
                $i = $i + 3
            }

            break

        }

    }

    if ("0" -eq $AppliedComputerGPO.Length) {

        $AppliedComputerGPO = [PSCustomObject] @{'AppliedGPO' = "No Applied GPO Found" }
        
        $AppliedComputerGPOHTML = $AppliedComputerGPO | ConvertTo-Html -Property AppliedGPO -Fragment 

    }

    else {

        foreach ($AppliedComputerGPOItem in $AppliedComputerGPO.AppliedGPO) {

            $AppliedComputerGPOHTML += "<div class=MultiCells>$AppliedComputerGPOItem</div>"

        }

        $AppliedComputerGPOHTML = "<div class = MultiCellsContainer>$AppliedComputerGPOHTML</div>"

        $AppliedComputerGPOHTML = "<div class = SubHeaders>Applied GPO</div>$AppliedComputerGPOHTML"
                  
    }

    if ("0" -eq $FilteredComputerGPO.Length) {

        $FilteredComputerGPO = [PSCustomObject] @{'FilteredGPO' = "No Filtered GPO Found" } 


    }

    $FilteredComputerGPOHTML = $FilteredComputerGPO | ConvertTo-Html -Property 'FilteredGPO', 'FilterReason' -Fragment

    $ReportElements += "====== Workstation GPO =======" , ($AppliedComputerGPO | Format-Table) , ($FilteredComputerGPO | Format-Table)

    $ReportElementsHTML += "<h2>Workstation GPO</h2>" , "$AppliedComputerGPOHTML" , "$FilteredComputerGPOHTML", "<hr>"

}

# -------------------------------------------- End Of Workstation GPO



# Security Software Status ------------------------------------------

Write-Progress -Activity "Collecting Security Software Status"

$Security_Softwares = @()

<# Old

$Security_Softwares += [PSCustomObject] @{'Name' = "Test Program1" ; 'Service' = "Test Service1"} 

$Security_Softwares += [PSCustomObject] @{'Name' = "Test Program2" ; 'Service' = "Test Service2"}

$Software_Paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'

$Security_Software_Report = @()

$Security_Software_ReportHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Security Software Status') {


foreach ($Security_Software in $Security_Softwares){
        
        $Security_Software_Service = $Security_Software.Service

        $Security_Software_NameHTML = $Security_Software.Name

        $Security_Software_Installed = $null -ne (Get-ItemProperty -Path $Software_Paths | Where-Object { $_.DisplayName -eq $Security_Software.Name })

        If ($Security_Software_Installed) {

            $Security_Software_Status = [PSCustomObject] @{'INFO' = $Security_Software.Name + " is installed" } 

            $Security_Software_StatusHTML = $Security_Software_Status |  ConvertTo-Html -Property INFO -Fragment 

            $Security_Software_Services = Get-Service | Where-Object {$_.DisplayName -like "*$Security_Software_Service*" } | Select-Object DisplayName, Status 

            $Security_Software_ServicesHTML = $Security_Software_Services |  ConvertTo-Html -Property DisplayName, Status -Fragment 

            $Security_Software_ServicesHTML = $Security_Software_ServicesHTML -replace '<td>Running</td>', '<td class="RunningStatus">Running</td>' 

            $Security_Software_ServicesHTML = $Security_Software_ServicesHTML -replace '<td>Stopped</td>', '<td class="StopStatus">Stopped</td>'

            $Security_Software_Report += $Security_Software.Name , ($Security_Software_Status | Format-Table) , ($Security_Software_Services | Format-Table)

            $Security_Software_ReportHTML += "<h3>$Security_Software_NameHTML</h3>" , "$Security_Software_StatusHTML $Security_Software_ServicesHTML" , "<br>"

        }

        else {

            $Security_Software_Status = [PSCustomObject] @{'INFO' = $Security_Software.Name + " is NOT installed" }
    
            $Security_SoftwareHTML = $Security_Software_Status |  ConvertTo-Html -Property INFO -Fragment
    
            $Security_Software_Report += $Security_Software.Name , ($Security_Software_Status | Format-Table)

            $Security_Software_ReportHTML += "<h3>$Security_Software_NameHTML</h3>" , "$Security_Software_StatusHTML" , "<br>"
     
        }

    }

    $ReportElements += "====== Security Software Status =======`n" , ($Security_Software_Report | Format-Table )

    $ReportElementsHTML += "<h2>Security Software Status</h2>" , "$Security_Software_ReportHTML" , "<hr>"

}

#>




$Security_Softwares = @()

$Security_Softwares_HTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Security Software Status') {

    $Security_Softwares = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName 

    if ('0' -eq $Security_Softwares.length) {
    
        $Security_Softwares = [PSCustomObject] @{'INFO' = "No Anti-Virus Products Found" } 

        $Security_Softwares_HTML = $Security_Softwares | ConvertTo-Html -Property INFO -Fragment
    
    }

    else {
    
        $Security_Softwares_HTML = $Security_Softwares | ConvertTo-Html -Property displayName -Fragment
    
    }


    $ReportElements += "====== Security Software Status =======`n" , ($Security_Softwares | Format-Table )

    $ReportElementsHTML += "<h2>Security Software Status</h2>" , "$Security_Softwares_HTML" , "<hr>"

}


# ------------------------------------ End of Security Software Status 




# Check Security Settings --------------------------------------------

Write-Progress -Activity "Collecting Security Settings"

if ($toDo -contains 'All' -or $toDO -contains 'Security Settings') {

    # Check UAC Status and Levels

        $UACResults = @()

        $UACResultsHTML = @()

        $UACPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        if ((Get-ItemProperty $UACPath).EnableLUA -eq '1') {

        $ConsentPromptBehaviorAdmin_Value = (Get-ItemProperty $UACPath).ConsentPromptBehaviorAdmin

        $PromptOnSecureDesktop_Value = (Get-ItemProperty $UACPath).PromptOnSecureDesktop

        if($ConsentPromptBehaviorAdmin_Value -Eq 0 -And $PromptOnSecureDesktop_Value -Eq 0){
 
            $UACLevel = " Level: (0/3) | Never NotIfy" 

        } 

        elseif($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 0){ 

            $UACLevel = "Level: (1/3) | NotIfy Me Only when Apps Try to Make Changes to My Computer(Do Not Dim My Desktop)" 

        } 

        elseif($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 1){ 

            $UACLevel = "Level: (2/3) | NotIfy Me Only when Apps Try to Make Changes to My Computer(Default)" 

        } 

        elseif($ConsentPromptBehaviorAdmin_Value -Eq 2 -And $PromptOnSecureDesktop_Value -Eq 1){ 

            $UACLevel = "Level: (3/3) | Always NotIfy" 

        } 

        else{ 

            $UACLevel = "Unknown" 

        } 


        $UACResults = [PSCustomObject] @{'Status' = "Enabled" ; "Level" = $UACLevel }

        $UACResultsHTML = $UACResults | ConvertTo-Html -Property Status , Level -Fragment


        }

        else {
        
        $UACResults = [PSCustomObject] @{'Status' = "Disabled"}

        $UACResultsHTML = $UACResults | ConvertTo-Html -Property Status -Fragment

        }

        $UACResultsHTML = $UACResultsHTML -replace '<td>Enabled</td>', '<td class="EnabledStatus">Enabled</td>' 

        $UACResultsHTML = $UACResultsHTML -replace '<td>Disabled</td>', '<td class="DisabledStatus">Disabled</td>'

    

    # Check Authentication Policy

    $AuthLMResults = @()

    $AuthLMResultsHTML = @()

    $AuthPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

        if ($null -ne (Get-ItemProperty $AuthPath).NoLmHash) {

            $AuthLMHash = (Get-ItemProperty $AuthPath).NoLmHash

                if ('1' -eq $AuthLMHash) {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "Disable Stroing LanMan Hash" ; 'Status' = "Enabled"}

                }

                else {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "Disable Stroing LanMan Hash" ; 'Status' = "Disabled"}
                
                }
        
        }

        else {
        
            $AuthLMResults = [PSCustomObject] @{'Policy' = "Disable Stroing LanMan Hash" ; 'Status' = "Not Configured"}

        }

        if ($null -ne (Get-ItemProperty $AuthPath).LMCompatibilityLevel) {

            $AuthLMLevel = (Get-ItemProperty $AuthPath).LMCompatibilityLevel
        
                if ('0' -eq $AuthLMLevel) {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Level: 0/5 | Send LM & NTLM responses"}

                }

                elseif ('1' -eq $AuthLMLevel) {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Level: 1/5 | Send LM & NTLM - Use NTLMv2 Session Security if Negotiated"}
                
                }

                elseif ('2' -eq $AuthLMLevel) {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Level: 2/5 | Send NTLM Response Only"}
                
                }
                
                elseif ('3' -eq $AuthLMLevel) {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Level: 3/5 | Send NTLMv2 Response Only"}
                
                }
                
                elseif ('4' -eq $AuthLMLevel) {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Level: 4/5 | Send NTLMv2 Response Only/Refuse LM"}
                
                }
                
                elseif ('5' -eq $AuthLMLevel) {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Level: 5/5 | Send NTLMv2 Response Only/Refuse LM & NTLM"}
                
                }
                      
                else {
                
                    $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Unknown"}
                
                }

        }

        else {
        
            $AuthLMResults += [PSCustomObject] @{'Policy' = "LM Compatibility Level" ; 'Status' = "Not Configured"}

        }

    $AuthLMResultsHTML = $AuthLMResults | ConvertTo-Html -Property Policy , Status -Fragment

    $AuthLMResultsHTML = $AuthLMResultsHTML -replace '<td>Enabled</td>', '<td class="EnabledStatus">Enabled</td>' 

    $AuthLMResultsHTML = $AuthLMResultsHTML -replace '<td>Disabled</td>', '<td class="DisabledStatus">Disabled</td>'


    <# Check Proxy Settings

    $ProxyResults = @()

    $ProxyResultsHTML = @()

    $ProxySettings = Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

        if ($ProxySettings.ProxyEnable -eq '1') {

        $ProxyResults = [PSCustomObject] @{'Status' = "Enabled" ; 'ProxyServer' = $ProxySettings.ProxyServer ; 'ProxyBypass' = $ProxySettings.ProxyOverride }

        }

        else {

        $ProxyResults = [PSCustomObject] @{'Status' = "Disabled" ; 'ProxyServer' = $ProxySettings.ProxyServer ; 'ProxyBypass' = $ProxySettings.ProxyOverride }

        }

        $ProxyResultsHTML = $ProxyResults | ConvertTo-Html -As List -Property Status, ProxyServer, ProxyBypass -Fragment

        $ProxyResultsHTML = $ProxyResultsHTML -replace '<td>Enabled</td>', '<td class="EnabledStatus">Enabled</td>' 

        $ProxyResultsHTML = $ProxyResultsHTML -replace '<td>Disabled</td>', '<td class="DisabledStatus">Disabled</td>'



        $ReportElements += "======= Security Settings =======`n" , "UAC Status And Level" , ($UACResults | Format-Table ) , "Authentication" , ($AuthLMResults | Format-Table ) ,"Proxy Settings" , ($ProxyResults | Format-Table ) 

        $ReportElementsHTML += "<h2>Security Settings</h2>" , "<h3>UAC Status And Level</h3>" , "$UACResultsHTML" , "<h3>Authentication</h3>" , "$AuthLMResultsHTML" ,"<h3>Proxy Settings</h3>" , "$ProxyResultsHTML" ,"<hr>"

        #>

        $ReportElements += "======= Security Settings =======`n" , "UAC Status And Level" , ($UACResults | Format-Table ) , "Authentication" , ($AuthLMResults | Format-Table ) 

        $ReportElementsHTML += "<h2>Security Settings</h2>" , "<h3>UAC Status And Level</h3>" , "$UACResultsHTML" , "<h3>Authentication</h3>" , "$AuthLMResultsHTML" ,"<hr>"


}

# ------------------------------------------- End of Security Settings



# Windows Update -----------------------------------------------------

Write-Progress -Activity "Collecting Windows Update Status"

$Windows_Update_Report = @()

$Windows_Update_ReportHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Windows Update Service Status') {

    $Windows_Update_Service = Get-Service -Name 'Windows Update' | Select-Object DisplayName, StartType, Status

    $Windows_Update_ServiceHTML = $Windows_Update_Service | ConvertTo-Html -Property DisplayName, StartType, Status -Fragment

    $Windows_Update_ServiceHTML = $Windows_Update_ServiceHTML -replace '<td>Running</td>', '<td class="RunningStatus">Running</td>' 

    $Windows_Update_ServiceHTML = $Windows_Update_ServiceHTML -replace '<td>Stopped</td>', '<td class="StopStatus">Stopped</td>'

    $Windows_Update_History = Get-HotFix | Select-Object Description, HotFixID, InstalledOn | Sort-Object -Property InstalledOn -Descending

    $Windows_Update_HistoryHTML = $Windows_Update_History | Sort-Object -Property InstalledOn -Descending | ConvertTo-Html -Property Description, HotFixID, InstalledOn -Fragmen

    $Windows_Update_Report = ($Windows_Update_Service | Format-Table) , ($Windows_Update_History | Format-Table)

    $Windows_Update_ReportHTML = "$Windows_Update_ServiceHTML $Windows_Update_HistoryHTML"

    $ReportElements += "====== Windows Update Service Status =======" , ($Windows_Update_Report | Format-Table)

    $ReportElementsHTML += "<h2>Windows Update Service Status</h2>" , $Windows_Update_ReportHTML, "<hr>"

}

# ----------------------------------------------- End of Windows Update



# Local Users -----------------------------------------------------

Write-Progress -Activity "Collecting Local Users List"

$LocalUsers = @()

$LocalUsersHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Local Users') {

    $LocalUsers = Get-LocalUser | Select-Object Name , Enabled , LastLogon , PasswordLastSet

    $LocalUsersHTML = $LocalUsers | ConvertTo-Html -Property Name, Enabled, SID, LastLogon, PasswordLastSet -Fragment
 
    $LocalUsersHTML = $LocalUsersHTML -replace '<th>Enabled</th>', '<th >Account Status</th>'

    $LocalUsersHTML = $LocalUsersHTML -replace '<td>True</td>', '<td class="EnabledUsers">Enabled</td>' 

    $LocalUsersHTML = $LocalUsersHTML -replace '<td>False</td>', '<td class="DisabledUsers">Disabled</td>'

    $ReportElements += "====== Local Users =======" , ($LocalUsers | Format-Table)

    $ReportElementsHTML += "<h2>Local Users</h2>" , "$LocalUsersHTML", "<hr>"

}

# ----------------------------------------------------- Local Users



# Local Admins ----------------------------------------------------

Write-Progress -Activity "Collecting Local Administrators List"

$LocalAdmins = @()

$LocalAdminsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Local Administrators') {

    $LocalAdmins = (Get-LocalGroupMember -Name Administrators  | Select-Object @{N = "Name"; E = { $_.Name -replace ".+\\" } })

    foreach ($LocalAdmin in $LocalAdmins.Name) {

        $LocalAdminsHTML += "<div class=MultiCells>$LocalAdmin</div>"

    }

    $LocalAdminsHTML = "<div class = MultiCellsContainer>$LocalAdminsHTML</div>"

    $ReportElements += "====== Local Admins =======" , ($LocalAdmins | Format-Table)

    $ReportElementsHTML += "<h2>Local Admins</h2>" , "$LocalAdminsHTML" , "<hr>"

}

# ----------------------------------------------------- Local Admins



# Profiles List ----------------------------------------------------

Write-Progress -Activity "Collecting Users Profile List"

$ProfileListResults = @()

$ProfileListResultsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Users Profile') {

    $ProfileListPath = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    $ProfileLists = Get-ItemProperty -path $ProfileListPath 

    $ProfileListTable = @()

    Foreach ($ProfileList in $ProfileLists) {

        $UserProfileNote = $null

        try { 

            $ProfileUser = New-Object System.Security.Principal.SecurityIdentifier($ProfileList.PSChildName)

            $ProfileUserName = $ProfileUser.Translate([System.Security.Principal.NTAccount]) 

            $ProfileList.PSChildName = $ProfileUserName.value
    
        }

        catch [Exception] {

            if ($_.Exception -match "Some or all identity references could not be translated.") {

                $ProfileList.PSChildName = ($ProfileList | Select-Object @{N = "ProfileImagePath"; E = { $_.ProfileImagePath -replace ".+\\", "$env:Computername\" } }).ProfileImagePath
            
                $UserProfileNote = 'Deleted/NotFound'

            }
        }

        if ($ProfileList.PsChildName -like "*$env:Computername*") {
        
            $UserType = 'Local User'
    
        }

        elseif ($ProfileList.PsChildName -like "*NT AUTHORITY*") {

            $UserType = 'System Account'

        }

        elseif ($ProfileList.PsChildName -like "*NT SERVICE*") {

            $UserType = 'Service Account'

        }

        else {

            $UserType = 'Domain User'

        }


        $ProfileListTable += [PSCustomObject] @{'User' = $ProfileList.PSChildName ; 'ProfilePath' = $ProfileList.ProfileImagePath ; 'UserType' = $UserType; 'Notes' = $UserProfileNote }
    
    }

    $ProfileList = $ProfileListTable | Where-Object { $_.User -notlike '*NT AUTHORITY*' -and $_.User -notlike '*NT SERVICE*'} 

    $ProfileListResults = $ProfileList | Select-Object -Property User, ProfilePath, UserType, Notes

    $ProfileListResultsHTML = $ProfileListResults | ConvertTo-Html -Property User, ProfilePath, UserType, Notes -Fragment

    $ReportElements += "====== Users Profile =======" , ($ProfileListResults | Format-Table)

    $ReportElementsHTML += "<h2>Users Profile</h2>" , "$ProfileListResultsHTML" , "<hr>"

}

# --------------------------------------------- End of Profiles List



# Deleted Users ----------------------------------------------------

Write-Progress -Activity "Collecting Deleted User Events"

if ($toDo -contains 'All' -or $toDO -contains 'Deleted Local Accounts') {

    $DeletedUserFilter = @{LogName = 'Security'; ID = 4726 }

    try {

        $DeletedUserEvents = Get-Winevent -FilterHashtable $DeletedUserFilter -ErrorAction Stop

        ForEach ($Event in $DeletedUserEvents) {    

            $eventXML = [xml]$Event.ToXml()  

            For ($i = 0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {   

                Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'  

            }            
        }       

        $DeletedUsers = $DeletedUserEvents | Select-Object TimeCreated, TargetUserName, TargetSid, SubjectUserName, SubjectUserSid

        $DeletedUsersHTML = $DeletedUsers | ConvertTo-Html -Property TimeCreated, TargetUserName, TargetSid, SubjectUserName, SubjectUserSid -Fragment

        $DeletedUsersHTML = $DeletedUsersHTML -replace '<th>TargetUserName</th>', '<th >User</th>'

        $DeletedUsersHTML = $DeletedUsersHTML -replace '<th>SubjectUserName</th>', '<th >Deleted By</th>'

    }

    catch [Exception] {

        if ($_.Exception -match "No events were found that match the specified selection criteria") {

            $DeletedUsers = [PSCustomObject] @{'INFO' = "No Deleted User History Found" }

            $DeletedUsersHTML = $DeletedUsers | ConvertTo-Html -Property INFO -Fragment
        }
    }

    $ReportElements += "====== Deleted Local Accounts =======" , ($DeletedUsers | Format-Table)

    $ReportElementsHTML += "<h2>Deleted Local Accounts</h2>" , "$DeletedUsersHTML" , "<hr>"

}

# --------------------------------------------- End of Deleted Users



# Users GPO --------------------------------------------------------

Write-Progress -Activity "Collecting Users GPO"

$UsersGPOResults = @()

$UsersGPOResultsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Users GPO') {

    $ProfileListPath = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    $ProfileLists = Get-ItemProperty -path $ProfileListPath 

    $ProfileListTable = @()

    Foreach ($ProfileList in $ProfileLists) {

        $UserProfileNote = $null

        try { 

            $ProfileUser = New-Object System.Security.Principal.SecurityIdentifier($ProfileList.PSChildName)

            $ProfileUserName = $ProfileUser.Translate([System.Security.Principal.NTAccount]) 

            $ProfileList.PSChildName = $ProfileUserName.value
    
        }

        catch [Exception] {

            if ($_.Exception -match "Some or all identity references could not be translated.") {

                $ProfileList.PSChildName = ($ProfileList | Select-Object @{N = "ProfileImagePath"; E = { $_.ProfileImagePath -replace ".+\\", "$env:Computername\" } }).ProfileImagePath
            
                $UserProfileNote = 'Deleted/NotFound'

            }
        }

        if ($ProfileList.PsChildName -like "*$env:Computername*") {
        
            $UserType = 'Local User'
    
        }

        elseif ($ProfileList.PsChildName -like "*NT AUTHORITY*") {

            $UserType = 'System User'

        }

       elseif ($ProfileList.PsChildName -like "*NT SERVICE*") {

            $UserType = 'Service Account'

        }

        else {

            $UserType = 'Domain User'

        }


        $ProfileListTable += [PSCustomObject] @{'User' = $ProfileList.PSChildName ; 'ProfilePath' = $ProfileList.ProfileImagePath ; 'UserType' = $UserType; 'Notes' = $UserProfileNote }
    
    }

    $ProfileList = $ProfileListTable | Where-Object { $_.User -notlike '*NT AUTHORITY*' -and $_.User -notlike '*NT SERVICE*'} 

    $UserGPOTable = @()

    $UserGPOTableHTML = @()

    Foreach ($UsersGPO in $ProfileList.User) {

        Write-Progress -Activity "Collecting Users GPO" -Status "Current User: $UsersGPO"

        $AppliedUserGPO = @()

        $FilteredUserGPO = @()

        $SecurityGroups = @()

        $AppliedUserGPOHTML = @()

        $FilteredUserGPOHTML = @()

        $SecurityGroupsHTML = @()

        $UserGPOTable += "--[$UsersGPO]--"

        $UserGPOTableHTML += "<h3>$UsersGPO</h3>"

        $UserGPOs = cmd.exe /c "chcp 1256 > nul & Gpresult /r /Scope User /User:$UsersGPO"

        if ($UserGPOs -notlike '*does not have RSoP data.*') {


            For ($i = 0; $i -le $UserGPOs.Length; $i++) {


                if ($UserGPOs[$i] -like '*Applied Group Policy Objects*') {

                    $i = $i + 2

                    while ($UserGPOs[$i] -notlike $null) {

                        $AppliedUserGPO += [PSCustomObject] @{'AppliedGPO' = $UserGPOs[$i].Trim() }

                        $i++
                    }

                }

                if ($UserGPOs[$i] -like '*The following GPOs were not applied because they were filtered out*') {
    
                    $i = $i + 2

                    while ($UserGPOs[$i] -notlike '*The user is a part of the following security groups*') {
            
                        $FilteredUserGPO += [PSCustomObject] @{'FliteredGPO' = $UserGPOs[$i].trim(); 'FilterReason' = $UserGPOs[$i + 1].Replace('Filtering:', '').Trim() }

                        $i = $i + 3
                    }

                }

                if ($UserGPOs[$i] -like '*The user is a part of the following security groups*') {
    
                    $i = $i + 2

                    while ($null -notlike $UserGPOs[$i].Trim() ) {
           
                        $SecurityGroups += [PSCustomObject] @{'SecurityGroups' = $UserGPOs[$i].Trim() }

                        $i++
                    }
    
                }

            }

            if ("0" -eq $AppliedUserGPO.Length) {

                $AppliedUserGPO = [PSCustomObject] @{'AppliedGPO' = "No Applied GPO Found" }

                $AppliedUserGPOHTML = $AppliedUserGPO | ConvertTo-Html -Property AppliedGPO -Fragment
                 

            }

            else {

                foreach ($AppliedUserGPOItem in $AppliedUserGPO.AppliedGPO) {

                    $AppliedUserGPOHTML += "<div class=MultiCells>$AppliedUserGPOItem</div>"

                }

                $AppliedUserGPOHTML = "<div class = MultiCellsContainer>$AppliedUserGPOHTML</div>"

                $AppliedUserGPOHTML = "<div class = SubHeaders>Applied GPO</div>$AppliedUserGPOHTML"
            
            
            }

            if ("0" -eq $FilteredUserGPO.Length) {

                $FilteredUserGPO = [PSCustomObject] @{'FilteredGPO' = "No Filtered GPO Found" }

                $FilteredUserGPOHTML = $FilteredUserGPO | ConvertTo-Html -Property FliteredGPO -Fragment


            }

            else {
            
                $FilteredUserGPOHTML = $FilteredUserGPO | ConvertTo-Html -Property FliteredGPO, FilterReason -Fragment

            }

            if ("0" -eq $SecurityGroups.Length) {

                $SecurityGroups = [PSCustomObject] @{'SecurityGroups' = "No Security Group Found" }

                $SecurityGroupsHTML = $SecurityGroups | ConvertTo-Html -Property SecurityGroups -Fragment


            }

            else {


            foreach ($SecurityGroupsItem in $SecurityGroups.SecurityGroups) {

                $SecurityGroupsHTML += "<div class=MultiCells>$SecurityGroupsItem</div>"

            }

            $SecurityGroupsHTML = "<div class = MultiCellsContainer>$SecurityGroupsHTML</div>"

            $SecurityGroupsHTML = "<div class = SubHeaders>Security Groups</div>$SecurityGroupsHTML"
            
            
            }

            $UserGPOTable += ($AppliedUserGPO | Format-Table) , ($FilteredUserGPO | Format-Table ), ($SecurityGroups | Format-Table)

            $UserGPOTableHTML += "$AppliedUserGPOHTML $FilteredUserGPOHTML $SecurityGroupsHTML"

            $UserGPOTableHTML += "<br><br>"

        }

        else {

            $UserGPOTable += [PSCustomObject] @{'INFO' = "The user $UsersGPO does not have RSoP data. Reason: Probably Either Service or Deleted Account" } 

            $UserGPOTableHTML += $UserGPOTable | ConvertTo-Html -Property INFO -Fragment

            $UserGPOTable = $UserGPOTable | Format-Table

            $UserGPOTableHTML += "<br><br>"

        }

        $UsersGPOResults = $UserGPOTable | Format-Table

        $UsersGPOResultsHTML = "$UserGPOTableHTML"

    }

    $ReportElements += "====== Users GPO =======`n" , $UsersGPOResults

    $ReportElementsHTML += "<h2>Users GPO</h2>" , "$UsersGPOResultsHTML" , "<hr>"

}

# ------------------------------------------------- End Of Users GPO



# Successful Logon -------------------------------------------------

Write-Progress -Activity "Collecting Successful Logon Events"

$SuccessfulUserEvents = @()

$SuccessfulUserEventsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Last Successful Logon') {

    $SuccessfulUserLogon = @{LogName = 'Security'; ID = 4624; StartTime = ((Get-Date).AddDays(-10)) }

    try {

        $SuccessfulUserEvents = Get-Winevent -FilterHashtable $SuccessfulUserLogon -ErrorAction Stop  

        ForEach ($Event in $SuccessfulUserEvents) { 
            
            $eventXML = [xml]$Event.ToXml()    

            For ($i = 0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) { 

                Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'            

            }            
        }       

        $SuccessfulUserEvents = $SuccessfulUserEvents  | Where-Object { $_.TargetUserName -ne 'SYSTEM' -and $_.LogonProcessName -like '*User32*' } | Select-Object TargetUserName, TimeCreated

        $SuccessfulUserEventsHTML = $SuccessfulUserEvents | ConvertTo-Html -Property TargetUserName, TimeCreated -Fragment

    }

    catch [Exception] {

        if ($_.Exception -match "No events were found that match the specified selection criteria") {

            $SuccessfulUserEvents = [PSCustomObject] @{'INFO' = "No Successful Logon History Found" }

            $SuccessfulUserEventsHTML = $SuccessfulUserEvents | ConvertTo-Html -Property INFO -Fragment

        }
    }

    $ReportElements += "====== Successful Logon (10 Days) =======" , ($SuccessfulUserEvents | Format-Table)

    $ReportElementsHTML += "<h2>Successful Logon (10 Days)</h2>" , "$SuccessfulUserEventsHTML" , "<hr>"

}

# ------------------------------------------ End of Successful Logon



# Failed Logon -----------------------------------------------------

Write-Progress -Activity "Collecting Failed Logon Events"

$FailedUserEvents = @()

$FailedUserEventsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Last Failed Logon') {

    $FailedUserLogon = @{LogName = 'Security'; ID = 4625; StartTime = ((Get-Date).AddDays(-10)) }

    try {

        $FailedUserEvents = Get-Winevent -FilterHashtable $FailedUserLogon -ErrorAction Stop 

        ForEach ($Event in $FailedUserEvents) {    

            $eventXML = [xml]$Event.ToXml() 

            For ($i = 0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {    

                Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'            

            }            
        }       

        $FailedUserEvents = $FailedUserEvents | Select-Object TargetUserName, TimeCreated

        $FailedUserEventsHTML = $FailedUserEvents | ConvertTo-Html -Property TargetUserName, TimeCreated -Fragment
    }

    catch [Exception] {

        if ($_.Exception -match "No events were found that match the specified selection criteria") {

            $FailedUserEvents = [PSCustomObject] @{'INFO' = "No Failed Logon History Found" }

            $FailedUserEventsHTML = $FailedUserEvents | ConvertTo-Html -Property INFO -Fragment
        }
    } 

    $ReportElements += "====== Failed Logon Attempts (10 Days) =======" , ($FailedUserEvents | Format-Table)

    $ReportElementsHTML += "<h2>Failed Logon Attempts (10 Days)</h2>" , "$FailedUserEventsHTML" , "<hr>"

}

# ----------------------------------------------------- Failed Logon



# Installed Programs -----------------------------------------------

Write-Progress -Activity "Collecting Installed Programs List"

$Software_Paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'

$InstalledPrograms = @()

$InstalledProgramsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Intsalled Programs') {

    foreach ($Software_Path in $Software_Paths) {

        $InstalledProgram = Get-ItemProperty -Path $Software_Path | Where-Object { $_.DisplayName -NotLike $null } | Select-Object  Publisher, @{Name = "InstallDate"; Expression = { ([datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)).toshortdatestring() } }, DisplayName 

        foreach ($InstalledProgramItem in $InstalledProgram) {

            $InstalledPrograms += [PSCustomObject] @{'Source' = $Software_Path -replace ":+.*" ; 'DisplayName' = $InstalledProgramItem.DisplayName ; 'Publisher' = $InstalledProgramItem.Publisher; 'InstallDate' = $InstalledProgramItem.InstallDate }
        }

    }

    $ProfileListPath = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    $ProfileLists = Get-ItemProperty -path $ProfileListPath 

    $ProfileListTable = @()

    Foreach ($ProfileList in $ProfileLists) {

        $UserProfileNote = $null

        try { 

            $ProfileUser = New-Object System.Security.Principal.SecurityIdentifier($ProfileList.PSChildName)

            $ProfileUserName = $ProfileUser.Translate([System.Security.Principal.NTAccount]) 

            $ProfileList.PSChildName = $ProfileUserName.value
    
        }

        catch [Exception] {

            if ($_.Exception -match "Some or all identity references could not be translated.") {

                $ProfileList.PSChildName = ($ProfileList | Select-Object @{N = "ProfileImagePath"; E = { $_.ProfileImagePath -replace ".+\\", "$env:Computername\" } }).ProfileImagePath
            
                $UserProfileNote = 'Deleted/NotFound'

            }
        }

        if ($ProfileList.PsChildName -like "*$env:Computername*") {
        
            $UserType = 'Local User'
    
        }

        elseif ($ProfileList.PsChildName -like "*NT AUTHORITY*") {

            $UserType = 'System User'

        }

       elseif ($ProfileList.PsChildName -like "*NT SERVICE*") {

            $UserType = 'Service Account'

        }

        else {

            $UserType = 'Domain User'

        }


        $ProfileListTable += [PSCustomObject] @{'User' = $ProfileList.PSChildName ; 'ProfilePath' = $ProfileList.ProfileImagePath ; 'UserType' = $UserType; 'Notes' = $UserProfileNote }
    
    }

    $ProfileList = $ProfileListTable | Where-Object { $_.User -notlike '*NT AUTHORITY*' -and $_.User -notlike '*NT SERVICE*'} 

    $UserUninstallKeyPathsTable = @()

    $UserRegKeysPaths = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    $UserUninstallResults = @()

    foreach ($UserRegKeyPath in $UserRegKeysPaths) {

        $UserRegKeyValue = $UserRegKeyPath -replace ".+\\" 

        $UserUninstallKeyPathsTable += [PSCustomObject] @{'Path' = $UserRegKeyPath  ; 'Key' = $UserRegKeyValue }
    }

    $UsersList = ($ProfileList | Select-Object @{N = "User"; E = { $_.User -replace ".+\\" } }).User

    $ActiveRegHive = (Get-ChildItem -Path 'Registry::HKEY_USERS\' | Where-Object { $_.PSChildName -notlike '*Classes*' }).PSChildName

    $LoggedInUserList = @()

    foreach ($UserHive in $ActiveRegHive) {

        if ($UserHive -ne '.DEFAULT') {

            $UserProfileHive = New-Object System.Security.Principal.SecurityIdentifier($UserHive)

            $LoggedInUserList += ($UserProfileHive.Translate([System.Security.Principal.NTAccount]) | Where-Object { $_.Value -notlike '*NT AUTHORITY*' } | Select-Object @{N = "Value"; E = { $_.Value -replace ".+\\" } }).Value

        }

    }

    $RegHiveUsers = @()

    foreach ($User in $UsersList) {

        if ($LoggedInUserList -contains $User) {

            foreach ($UserUninstallKeyPathRow in $UserUninstallKeyPathsTable) {

                $GetUserSID = New-Object System.Security.Principal.NTAccount($User)
        
                $UserSID = ($GetUserSID.Translate([System.Security.Principal.SecurityIdentifier])).Value

                $UserUninstallKeyPath = 'Registry::HKEY_USERS\' + $UserSID + $UserUninstallKeyPathRow.Path

                $UserUninstallKeyPathItems = Get-ChildItem -Path $UserUninstallKeyPath | Get-ItemProperty | Where-Object { $_.DisplayName -NotLike $null } | Select-Object  Publisher, @{Name = "InstallDate"; Expression = { ([datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)).toshortdatestring() } }, DisplayName 

                Foreach ($UserUninstallKeyPathItem in $UserUninstallKeyPathItems) {

                    $UserUninstallResults += [PSCustomObject] @{'Source' = "HKU_$User" ; 'DisplayName' = $UserUninstallKeyPathItem.DisplayName ; 'Publisher' = $UserUninstallKeyPathItem.Publisher; 'InstallDate' = $UserUninstallKeyPathItem.InstallDate }

                }

            }

        }

        else {

            $RegHive = 'HKU\Temp-' + $User

            $RegHiveData = 'C:\Users\' + $User + '\ntuser.dat'

            if (Test-Path -Path $RegHiveData ) {

                $RegHiveUsers += $RegHive

                if (!(Test-Path -Path $RegHive)){

                    reg.exe load $RegHive $RegHiveData | Out-Null

                }
        
                foreach ($UserUninstallKeyPathRow in $UserUninstallKeyPathsTable) {

                    $UserUninstallKeyPath = 'Registry::HKEY_USERS\Temp-' + $User + $UserUninstallKeyPathRow.Path

                    if (Test-Path -Path $UserUninstallKeyPath ) {

                        $UserUninstallKeyPathItems = Get-ChildItem -Path $UserUninstallKeyPath | Get-ItemProperty | Where-Object { $_.DisplayName -NotLike $null } | Select-Object  Publisher, @{Name = "InstallDate"; Expression = { ([datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)).toshortdatestring() } }, DisplayName 

                        Foreach ($UserUninstallKeyPathItem in $UserUninstallKeyPathItems) {

                            $UserUninstallResults += [PSCustomObject] @{'Source' = "HKU_$User" ; 'DisplayName' = $UserUninstallKeyPathItem.DisplayName ; 'Publisher' = $UserUninstallKeyPathItem.Publisher; 'InstallDate' = $UserUninstallKeyPathItem.InstallDate }

                        }

                    }

                    else {
                    
                        $UserUninstallResults += [PSCustomObject] @{'Source' = "HKU_$User" ; 'DisplayName' = "*INFO: Uninstall Key Not Found*" ; 'Publisher' = "*INFO: Uninstall Key Not Found*" ; 'InstallDate' = "*INFO: Uninstall Key Not Found*" }
                    
                    } 
               
                }

            }

            else {

                $UserUninstallResults += [PSCustomObject] @{'Source' = "HKU_$User" ; 'DisplayName' = "No NTUSER.DAT" ; 'Publisher' = "No NTUSER.DAT"; 'InstallDate' = "No NTUSER.DAT" } 
            }

        }

    }
    
    [gc]::collect()

    [gc]::WaitForPendingFinalizers()

    foreach ( $RegHiveUser in $RegHiveUsers) {

        reg.exe unload $RegHiveUser | Out-Null

    }

    $InstalledPrograms += $UserUninstallResults

    $InstalledPrograms = $InstalledPrograms | Sort-Object -Property Source

    $InstalledProgramsHTML = $InstalledPrograms | ConvertTo-Html -Property Source, DisplayName , Publisher, InstallDate  -Fragment

    $ReportElements += "====== Installed Programs =======" , ($InstalledPrograms | Format-Table -Wrap -AutoSize )

    $ReportElementsHTML += "<h2>Installed Programs</h2>" , "$InstalledProgramsHTML" , "<hr>"

}

# ----------------------------------------------- Installed Programs



# Browsers Extensions -----------------------------------------------------

Write-Progress -Activity "Browsers Extensions"



if ($toDo -contains 'All' -or $toDO -contains 'Browsers Extensions') {

    $ExtensionsTable = @()

    $ProfileListPath = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    $ProfileLists = Get-ItemProperty -path $ProfileListPath 

    $ProfileListTable = @()

    Foreach ($ProfileList in $ProfileLists) {

        $UserProfileNote = $null

        try { 

            $ProfileUser = New-Object System.Security.Principal.SecurityIdentifier($ProfileList.PSChildName)

            $ProfileUserName = $ProfileUser.Translate([System.Security.Principal.NTAccount]) 

            $ProfileList.PSChildName = $ProfileUserName.value

        }

        catch [Exception] {

            if ($_.Exception -match "Some or all identity references could not be translated.") {

                $ProfileList.PSChildName = ($ProfileList | Select-Object @{N = "ProfileImagePath"; E = { $_.ProfileImagePath -replace ".+\\", "$env:Computername\" } }).ProfileImagePath
        
                $UserProfileNote = 'Deleted/NotFound'

            }
        }

        if ($ProfileList.PsChildName -like "*$env:Computername*") {
    
            $UserType = 'Local User'

        }

        elseif ($ProfileList.PsChildName -like "*NT AUTHORITY*") {

            $UserType = 'System User'

        }

       elseif ($ProfileList.PsChildName -like "*NT SERVICE*") {

            $UserType = 'Service Account'

        }

        else {

            $UserType = 'Domain User'

        }


        $ProfileListTable += [PSCustomObject] @{'User' = $ProfileList.PSChildName ; 'ProfilePath' = $ProfileList.ProfileImagePath ; 'UserType' = $UserType; 'Notes' = $UserProfileNote }

    }

    $ProfileList = $ProfileListTable | Where-Object { $_.User -notlike '*NT AUTHORITY*' -and $_.User -notlike '*NT SERVICE*'} 


    #$UsersList = ($ProfileList | Select-Object @{N = "User"; E = { $_.User -replace ".+\\" } }).User



    $ExtensionsTable = @()

    $ExtensionsTableHTML = @()

    $BrowsersList = @()

    $BrowsersList += [PSCustomObject] @{'Name'= "Chrome" ; 'Path' = "AppData\Local\Google\Chrome\User Data\Default"}

    $BrowsersList += [PSCustomObject] @{'Name'= "Edge" ; 'Path' = "AppData\Local\Microsoft\Edge\User Data\Default"}

    $BrowsersList += [PSCustomObject] @{'Name'= "Firefox" ; 'Path' = "AppData\Roaming\Mozilla\Firefox\Profiles\*"}

    foreach ( $ExtensionUser in $ProfileList) {
    
        foreach ( $Browser in $BrowsersList) {    

            # Chrome and Edge -------------------------------------------

            if ($Browser.Name -eq "Chrome" -or $Browser.Name -eq "Edge"){

                if (Test-Path $ExtensionUser.ProfilePath) {

                    if ((Test-Path ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\Secure Preferences")) -and (Test-Path ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\Preferences")) -and ( Test-Path ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\Extensions"))){

                        $ExtensionPref = (Get-Content ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\Secure Preferences") -Raw | ConvertFrom-Json).extensions.settings

                        if ($null -eq $ExtensionPref) {

                            $ExtensionPref = (Get-Content ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\Preferences") -Raw | ConvertFrom-Json).extensions.settings

                        }

                        $ExtensionPathFolders = (Get-ChildItem ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\Extensions")).FullName

                        foreach ($ExtensionFolder in $ExtensionPathFolders){

                            $ExtensionFolderID = $ExtensionFolder -replace ".+\\"

                            $ExtensionPrefID = $ExtensionPref.$ExtensionFolderID

                            if ($ExtensionFolderID -eq "Temp" -or $null -eq $ExtensionPrefID.withholding_permissions ) {

                                continue

                            }

                            if ($ExtensionPrefID.state -eq '1'){

                                $ExtensionStatus ="Enabled"

                            }

                            else {

                                $ExtensionStatus ="Disabled"

                            }

                            $ExtensionPathItem = Get-Content "$ExtensionFolder\*\manifest.json" -Raw | ConvertFrom-Json | Select-Object Name , Description , Version

                            if ($ExtensionPathItem.name -like "*__MSG*"){

                                $ExtensionPathItem.name = ($ExtensionPathItem.name -replace ("__|MSG_" ,"")).Trim()

                            }

                            if ( $ExtensionPathItem.Description -like "*__MSG*") {

                                $ExtensionPathItem.Description = ($ExtensionPathItem.Description -replace ("__|MSG_" ,"")).Trim()

                            }

                            if (Test-Path "$ExtensionFolder\*\_locales\en") {

                                $ExtensionPathValues = Get-Content "$ExtensionFolder\*\_locales\en\messages.json" -Raw | ConvertFrom-Json | Select-Object $ExtensionPathItem.name , $ExtensionPathItem.Description 

                            }

                            elseif (Test-Path "$ExtensionFolder\*\_locales\en_US"){

                                $ExtensionPathValues = Get-Content "$ExtensionFolder\*\_locales\en_US\messages.json" -Raw | ConvertFrom-Json | Select-Object $ExtensionPathItem.name , $ExtensionPathItem.Description 

                            }

                            else {

                                $ExtensionPathValues = Get-Content "$ExtensionFolder\*\_locales\en_GB\messages.json" -Raw | ConvertFrom-Json | Select-Object $ExtensionPathItem.name , $ExtensionPathItem.Description 

                            }

                            $ExtensionName = $ExtensionPathValues.($ExtensionPathItem.name).message

                            $ExtensionDescription = $ExtensionPathValues.($ExtensionPathItem.Description).message
                        
                            if ($null -eq $ExtensionName ){

                                $ExtensionName  = $ExtensionPathItem.name

                            }

                            if ($null -eq $ExtensionDescription ){

                                $ExtensionDescription = $ExtensionPathItem.description

                            }
                        
                        #$ExtensionsTable += [PSCustomObject] @{'Browser' = $Browser.Name ; 'User'= $ExtensionUser.User ;'Folder' = $ExtensionFolderID  ;'Status' = $ExtensionStatus ; 'Name' = $ExtensionName ; 'Version' = $ExtensionPathItem.version ;'Descripton' = $ExtensionDescription  }

                        $ExtensionsTable += [PSCustomObject] @{'User'= $ExtensionUser.User ; 'Browser' = $Browser.Name ; 'Status' = $ExtensionStatus ; 'Name' = $ExtensionName ; 'Version' = $ExtensionPathItem.version ;'Descripton' = $ExtensionDescription  }


                        }



                    }

                }

            }

            # ------------------------------------ End of Chrome and Edge




            # FireFox ---------------------------------------------------

            elseif ($Browser.Name -eq "Firefox") {

                if (Test-Path $ExtensionUser.ProfilePath) {
                    
                    if (Test-Path ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\extensions.json")){
        
                        $ExtensionPref = ((Get-Content ($ExtensionUser.ProfilePath + "\" + $Browser.Path + "\extensions.json") -Raw | ConvertFrom-Json).addons | Where-Object {$_.type -match "extension" -and $_.hidden -match "False"})

                        #$ExtensionPref.defaultLocale >> Name + Description

                        #$ExtensionPref

                        foreach ($ExtensionPrefItem in $ExtensionPref) {

                            if ($ExtensionPrefItem.Active -match "True") {
    
                                $ExtensionPrefItem.Active = "Enabled"

                            }

                            else {
    
                                $ExtensionPrefItem.Active = "Disabled"
    
                            }

                            $ExtensionsTable += [PSCustomObject] @{'User' = $ExtensionUser.User ; 'Browser' = $Browser.Name ;'Status' = $ExtensionPrefItem.Active ; 'Name' = $ExtensionPrefItem.defaultLocale.name ; 'Version' = $ExtensionPrefItem.version ;'Descripton' = $ExtensionPrefItem.defaultLocale.Description  }

                        }
        
                    }


                }
            
            }

            # -------------------------------------------- End of Firefox
  
        }

    }








    $ExtensionsTableHTML = $ExtensionsTable | ConvertTo-Html -Property * -Fragment

    $ExtensionsTableHTML = $ExtensionsTableHTML -replace '<td>Enabled</td>', '<td class="EnabledStatus">Enabled</td>' 

    $ExtensionsTableHTML = $ExtensionsTableHTML -replace '<td>Disabled</td>', '<td class="DisabledStatus">Disabled</td>'

    $ReportElements += "====== Browsers Extension =======" , ($ExtensionsTable | Format-Table)

    $ReportElementsHTML += "<h2>Browsers Extension</h2>" , "$ExtensionsTableHTML" , "<hr>"


}

# ----------------------------------------------- End of Browsers Extensions




# Run Registry -----------------------------------------------------

Write-Progress -Activity "Collecting Run Registries List"

$ComputerRunResults = @()

$ComputerRunResultsHTML = @()

$UserRunResults = @()

$UserRunResultsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Run Registry') {

    $ComputerRunKeyPathsTable = @()

    $ComputerRegKeysPaths = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" , "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

    $ComputerRunResults = @()

    foreach ($ComputerRegKeyPath in $ComputerRegKeysPaths) {

        $ComputerRegKeyValue = $ComputerRegKeyPath -replace ".+\\" 

        $ComputerRunKeyPathsTable += [PSCustomObject] @{'Path' = $ComputerRegKeyPath  ; 'Key' = $ComputerRegKeyValue }
    }

    foreach ($ComputerRunKeyPathRow in $ComputerRunKeyPathsTable) {

        if (Test-Path -Path $ComputerRunKeyPathRow.Path) {

            $ComputerRunKeyPathRowItems = (Get-Item -Path $ComputerRunKeyPathRow.Path ).Property

            if ("$null" -ne $ComputerRunKeyPathRowItems) {

                foreach ($ComputerRunKeyPathRowItem in $ComputerRunKeyPathRowItems) {

                    if ($ComputerRunKeyPathRowItem -eq '(default)') {

                        continue

                    }
 
                    $ComputerRunKeyPathRowItemValue = Get-ItemPropertyValue -Path $ComputerRunKeyPathRow.path -Name $ComputerRunKeyPathRowItem

                    $ComputerRunResults += [PSCustomObject] @{'Path' = $ComputerRunKeyPathRow.key ; 'Key' = $ComputerRunKeyPathRowItem ; 'Data' = $ComputerRunKeyPathRowItemValue }

                }

            }

            else {

                $ComputerRunResults += [PSCustomObject] @{'Path' = $ComputerRunKeyPathRow.key ; 'Key' = '*INFO: No Keys Found*' ; 'Data' = '*INFO: No Keys Found*' }

            }

        }
    
        else {
    
            $ComputerRunResults += [PSCustomObject] @{'Path' = $ComputerRunKeyPathRow.key ; 'Key' = '*INFO: No Path Found*' ; 'Data' = '*INFO: No Path Found*' }

        }

    }

    $ProfileListPath = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    $ProfileLists = Get-ItemProperty -path $ProfileListPath 

    $ProfileListTable = @()

    Foreach ($ProfileList in $ProfileLists) {

        $UserProfileNote = $null

        try { 

            $ProfileUser = New-Object System.Security.Principal.SecurityIdentifier($ProfileList.PSChildName)

            $ProfileUserName = $ProfileUser.Translate([System.Security.Principal.NTAccount]) 

            $ProfileList.PSChildName = $ProfileUserName.value
    
        }

        catch [Exception] {

            if ($_.Exception -match "Some or all identity references could not be translated.") {

                $ProfileList.PSChildName = ($ProfileList | Select-Object @{N = "ProfileImagePath"; E = { $_.ProfileImagePath -replace ".+\\", "$env:Computername\" } }).ProfileImagePath
            
                $UserProfileNote = 'Deleted/NotFound'

            }
        }

        if ($ProfileList.PsChildName -like "*$env:Computername*") {
        
            $UserType = 'Local User'
    
        }

        elseif ($ProfileList.PsChildName -like "*NT AUTHORITY*") {

            $UserType = 'System User'
        
        }

       elseif ($ProfileList.PsChildName -like "*NT SERVICE*") {

            $UserType = 'Service Account'

        }

        else {

            $UserType = 'Domain User'

        }


        $ProfileListTable += [PSCustomObject] @{'User' = $ProfileList.PSChildName ; 'ProfilePath' = $ProfileList.ProfileImagePath ; 'UserType' = $UserType; 'Notes' = $UserProfileNote }
    
    }

    # $ProfileList = $ProfileListTable | Where-Object { $_.User -notlike '*NT AUTHORITY*' -and $_.User -notlike '*NT SERVICE*'} 

    $UserRunKeyPathsTable = @()

    $UserRegKeysPaths = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" , "\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

    $UserRunResults = @()

    foreach ($UserRegKeyPath in $UserRegKeysPaths) {

        $UserRegKeyValue = $UserRegKeyPath -replace ".+\\" 

        $UserRunKeyPathsTable += [PSCustomObject] @{'Path' = $UserRegKeyPath  ; 'Key' = $UserRegKeyValue }
    }

    $UsersList = ($ProfileListTable | Select-Object @{N = "User"; E = { $_.User -replace ".+\\" } }).User

    $UsersList += ".DEFAULT"

    $ActiveRegHive = (Get-ChildItem -Path 'Registry::HKEY_USERS\' | Where-Object { $_.PSChildName -notlike '*Classes*' }).PSChildName

    $LoggedInUserList = @()

    foreach ($UserHive in $ActiveRegHive) {

        if ($UserHive -ne '.DEFAULT' -and $UserHive -notlike '*Temp-*') {

            $UserProfileHive = New-Object System.Security.Principal.SecurityIdentifier($UserHive)

            $LoggedInUserList += ($UserProfileHive.Translate([System.Security.Principal.NTAccount]) | Select-Object @{N = "Value"; E = { $_.Value -replace ".+\\" } }).Value

        }

        elseif ($UserHive -eq '.DEFAULT'){

            $LoggedInUserList += '.DEFAULT'

        }

    }

    $RegHiveUsers = @()

    foreach ($User in $UsersList) {

        if ($LoggedInUserList -contains $User) {

            foreach ($UserRunKeyPathRow in $UserRunKeyPathsTable) {

                if ($User -ne ".DEFAULT") {

                    $GetUserSID = New-Object System.Security.Principal.NTAccount($User)
        
                    $UserSID = ($GetUserSID.Translate([System.Security.Principal.SecurityIdentifier])).Value

                    $UserRunKeyPath = 'Registry::HKEY_USERS\' + $UserSID + $UserRunKeyPathRow.Path
        
                }
                elseif ($User -eq '.DEFAULT') {
        
                    $UserRunKeyPath = 'Registry::HKEY_USERS\' + $User + $UserRunKeyPathRow.Path
        
                }
        
                if (Test-Path -Path $UserRunKeyPath) {

                    $UserRunKeyPathItems = (Get-Item -Path $UserRunKeyPath).Property
        
                    if ("$null" -ne $UserRunKeyPathItems) {

                        foreach ($UserRunKeyPathItem in $UserRunKeyPathItems) {

                            if ($UserRunKeyPathItem -eq '(default)') {

                                continue

                            }

                            $UserRunKeyPathItemValue = Get-ItemPropertyValue -Path $UserRunKeyPath -Name $UserRunKeyPathItem

                            $UserRunResults += [PSCustomObject] @{'User' = $User ; 'Path' = $UserRunKeyPathRow.Key  ; 'Key' = $UserRunKeyPathItem ; 'Data' = $UserRunKeyPathItemValue }

                        }

                    }

                    else {

                        $UserRunResults += [PSCustomObject] @{'User' = $User ; 'Path' = $UserRunKeyPathRow.Key ; 'Key' = '*INFO: No Keys Found*' ; 'Data' = '*INFO: No Keys Found*' }
                    }

                }

                else {
    
                    $UserRunResults += [PSCustomObject] @{'User' = $User ; 'Path' = $UserRunKeyPathRow.Key ; 'Key' = '*INFO: No Path Found*' ; 'Data' = '*INFO: No Path Found*' }
    
                }

            }

        }

        else {

            $RegHive = 'HKU\Temp-' + $User

            $RegHiveData = 'C:\Users\' + $User + '\ntuser.dat'

            if (Test-Path -Path $RegHiveData ) {

                $RegHiveUsers += $RegHive

                if (!(Test-Path -Path $RegHive)){

                    reg.exe load $RegHive $RegHiveData | Out-Null

                }
        
                foreach ($UserRunKeyPathRow in $UserRunKeyPathsTable) {

                    $UserRunKeyPath = 'Registry::HKEY_USERS\Temp-' + $User + $UserRunKeyPathRow.Path

                    if (Test-Path -Path $UserRunKeyPath) {

                        $UserRunKeyPathItems = (Get-Item -Path $UserRunKeyPath ).Property

                        if ("$null" -ne $UserRunKeyPathItems) {

                            foreach ($UserRunKeyPathItem in $UserRunKeyPathItems) {

                                if ($UserRunKeyPathItem -eq '(default)') {

                                    continue

                                }

                                $UserRunKeyPathItemValue = Get-ItemPropertyValue -Path $UserRunKeyPath -Name $UserRunKeyPathItem

                                $UserRunResults += [PSCustomObject] @{'User' = $User ; 'Path' = $UserRunKeyPathRow.Key  ; 'Key' = $UserRunKeyPathItem ; 'Data' = $UserRunKeyPathItemValue }

                            }
                
                        }

                        else {

                            $UserRunResults += [PSCustomObject] @{'User' = $User ; 'Path' = $UserRunKeyPathRow.Key  ; 'Key' = '*INFO: No Keys Found*' ; 'Data' = '*INFO: No Keys Found*' }
            
                        }

                    }

                    else { 

                        $UserRunResults += [PSCustomObject] @{'User' = $User ; 'Path' = $UserRunKeyPathRow.Key  ; 'Key' = '*INFO: No Path Found*' ; 'Data' = '*INFO: No Path Found*' }
        
                    }

                }

            }

            else {

                $UserRunResults += [PSCustomObject] @{'User' = $User ; 'Path' = '*INFO: No NTUSER.DAT*'  ; 'Key' = '*INFO: No NTUSER.DAT*' ; 'Data' = '*INFO: No NTUSER.DAT*' }

            }

        }

    }


    [gc]::collect()

    [gc]::WaitForPendingFinalizers()

    foreach ( $RegHiveUser in $RegHiveUsers) {

        reg.exe unload $RegHiveUser | Out-Null

    }

    $ComputerRunResultsHTML = $ComputerRunResults | ConvertTo-Html -Property Path, Key, Data -Fragment

    $UserRunResultsHTML = $UserRunResults | ConvertTo-Html -Property User, Path, Key, Data -Fragment

    $ReportElements += "====== Run Registry======= `n" , "Computer Run Registry" , ($ComputerRunResults | Format-Table -Wrap -AutoSize) , "Users Run Registry" , ($UserRunResults | Format-Table)

    $ReportElementsHTML += "<h2>Run Registry</h2>" , "<h3>Computer Run Registry</h3>" , "$ComputerRunResultsHTML" , "<h3>User Run Registry</h3>" , "$UserRunResultsHTML" , "<hr>"

}

# ---------------------------------------------- End of Run Registry



# SMB Shares -------------------------------------------------------

Write-Progress -Activity "Collecting SMB Information"

$SmbResults = @()

$SmbResultsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains "SMB") {

    $SmbShared = Get-SmbShare | Select-Object Name, Path, Description

    if ($null -ne $SmbShared ) {

        $SmbSharedHTML = $SmbShared | ConvertTo-Html -Property Name, Path, Description -Fragment

        $SmbResults += "SMB Shared" , ($SmbShared | Format-Table)

        $SmbResultsHTML += "<h3>SMB Shared</h3>" , "$SmbSharedHTML"
 
    }

    $SmbConnection = Get-SmbConnection | Select-Object ServerName, UserName, Credential, ShareName 

    if ($null -ne $SmbConnection ) {

        $SmbConnectionHTML = $SmbConnection | ConvertTo-Html -Property ServerName, UserName, Credential, ShareName -Fragment

        $SmbResults += "SMB/OUT Connections" , ($SmbConnection | Format-Table)

        $SmbResultsHTML += "<h3>SMB/OUT Connections</h3>" , "$SmbConnectionHTML"

    }

    $SmbSession = Get-SmbSession | Select-Object ClientComputerName, ClientUserName, SessionId

    if ($null -ne $SmbSession ) {

        $SmbSessionHTML = $SmbSession  | ConvertTo-Html -Property ClientComputerName, ClientUserName, SessionId -Fragment

        $SmbResults += "SMB/IN Sessions" , ($SmbSession | Format-Table)

        $SmbResultsHTML += "<h3>SMB/IN Sessions</h3>" , "$SmbSessionHTML"

    }

    $SmbOpen = Get-SmbOpenFile | Select-Object -Property ClientComputerName, ClientUserName, SessionId, Path  | Sort-Object -Property Path -Unique

    if ($null -ne $SmbOpen ) {

        $SmbOpenHTML = $SmbOpen | ConvertTo-Html -Property Path, ClientComputerName, ClientUserName, SessionId -Fragment

        $SmbResults += "SMB/IN Open Folder/Files" , ($SmbOpen | Format-Table)

        $SmbResultsHTML += "<h3>SMB/IN Open Folder/Files</h3>" , "$SmbOpenHTML"

    }

    $ReportElements += "====== SMB ======= `n" , ($SmbResults | Format-Table )

    $ReportElementsHTML += "<h2>SMB</h2>" , "$SmbResultsHTML"

}

# ------------------------------------------------ End of SMB Shares



# Wireless Network -------------------------------------------------

Write-Progress -Activity "Collecting Wireless Network Info"

$Wireless_Events = @()

$Wireless_EventsHTML = @()

$WirelessInterfaceResults = @()

$WirelessInterfaceResultsHTML = @()

$FiltersRules = @()

$FiltersRulesHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Wireless Network') {

    $Wireless_Filter = @{ LogName = "Microsoft-Windows-WLAN-AutoConfig/Operational" ;ID = 8001 ,11001 }

    try {

        $Wireless_Event = Get-Winevent -FilterHashtable $Wireless_Filter -ErrorAction Stop  

        ForEach ($Event in $Wireless_Event) {   

            $eventXML = [xml]$Event.ToXml()  

            For ($i = 0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) { 

                Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'            

            }            
        }       

        $Wireless_Events = $Wireless_Event | Where-Object { $_.ID -like '8001' } | Select-Object MachineName, UserId, Id, TimeCreated, SSID, AuthenticationAlgorithm, Adapter, LocalMAC | Sort-Object -Property @{Expression = "$_.TimeCreated"; Descending = $True}, @{Expression = "$_.SSID"; Descending = $False} | Sort-Object -Property SSID -Unique

        $Wireless_Events += $Wireless_Event | Where-Object { $_.ID -like '11001' } | Select-Object MachineName, UserId, Id, TimeCreated, SSID, AuthenticationAlgorithm, Adapter, LocalMAC | Sort-Object -Property @{Expression = "$_.TimeCreated"; Descending = $True}, @{Expression = "$_.SSID"; Descending = $False} | Sort-Object -Property SSID -Unique

        $Wireless_Events = $Wireless_Events | Sort-Object -Property SSID

        $Wireless_EventsHTML = $Wireless_Events | ConvertTo-Html -Property MachineName, UserId, Id, TimeCreated, SSID, AuthenticationAlgorithm, Adapter, LocalMAC -Fragment
    
    }

    catch [Exception] {

        if ($_.Exception -match "No events were found that match the specified selection criteria") {

            $Wireless_Events = [PSCustomObject] @{'INFO' = "No Wireless History Found" }

            $Wireless_EventsHTML = $Wireless_Events | ConvertTo-Html -Property INFO -Fragment

        }
    }

    $WirelessInterfaces = Get-NetAdapter | Where-Object { $_.InterfaceName -like "*Wireless*" } | Select-Object Name , Status, MacAddress , DriverDescription

    foreach ($WirelessInterface in $WirelessInterfaces) {

        $InterfaceName = $WirelessInterface.Name

        $WirelessInterfaceProfiles = ((netsh wlan show profiles interface="$InterfaceName") -match '\s{2,}:\s') -replace '.*:\s' , ''

        foreach ($WirelessInterfaceProfile in $WirelessInterfaceProfiles) {

            $WirelessInterfaceResults += [PSCustomObject] @{'Interface' = $InterfaceName ; 'Profile' = $WirelessInterfaceProfile ; 'Status' = $WirelessInterface.Status ; 'MacAddress' = $WirelessInterface.MacAddress ; 'DriverDescription' = $WirelessInterface.DriverDescription }

        }

    }

    If ('0' -ne $WirelessInterfaceResults.Length) {

    $WirelessInterfaceResultsHTML = $WirelessInterfaceResults |  ConvertTo-Html -Property Interface , Profile , Status , MacAddress , DriverDescription -Fragment

    $WirelessInterfaceResultsHTML = $WirelessInterfaceResultsHTML -replace '<td>Up</td>', '<td class="InterfaceUp">Up</td>'

    $WirelessInterfaceResultsHTML = $WirelessInterfaceResultsHTML -replace '<td>Disconnected</td>', '<td class="InterfaceDisconnected">Disconnected</td>'

    }

    else {
    
    $WirelessInterfaceResults = [PSCustomObject] @{'INFO' = "No Wireless Network Profiles Found"}

    $WirelessInterfaceResultsHTML = $WirelessInterfaceResults | ConvertTo-Html -Property INFO -Fragment

    }

 If ( (netsh wlan show filters).toString() -notlike "*The Wireless AutoConfig Service (wlansvc) is not running.*")  {
 
     $AllowFilters = netsh wlan show filters permission=allow

    For ($i = 0; $i -le $AllowFilters.Length; $i++) {

        if ($AllowFilters[$i] -like '*Allow list on the system (group policy)*') {

            $i = $i + 2

            while ($AllowFilters[$i] -notlike $null) {

                $FiltersRules += [PSCustomObject] @{'Source' = "Group Policy" ; "Action" = "Allow" ; 'SSID' = $AllowFilters[$i].Trim() }

                $i++
            }
        
            $i++

            if ($AllowFilters[$i] -like '*Allow list on the system (user)*') {

                $i = $i + 2

                while ($AllowFilters[$i] -notlike $null) {

                    $FiltersRules += [PSCustomObject] @{'Source' = "User" ; "Action" = "Allow" ; 'SSID' = $AllowFilters[$i].Trim() }

                    $i++
                }

            }

        }

    }

    $BlockFilters = netsh wlan show filters permission=block

    For ($i = 0; $i -le $BlockFilters.Length; $i++) {

        if ($BlockFilters[$i] -like '*Block list on the system (group policy)*') {

            $i = $i + 2

            while ($BlockFilters[$i] -notlike $null) {

                $FiltersRules += [PSCustomObject] @{'Source' = "Group Policy" ; "Action" = "Block" ; 'SSID' = $BlockFilters[$i].Trim() }

                $i++
            }
        
            $i++

            if ($BlockFilters[$i] -like '*Block list on the system (user)*') {

                $i = $i + 2

                while ($BlockFilters[$i] -notlike $null) {

                    $FiltersRules += [PSCustomObject] @{'Source' = "User" ; "Action" = "Block" ; 'SSID' = $BlockFilters[$i].Trim() }

                    $i++
                }

            }

        }

    }

    $FiltersRulesHTML = $FiltersRules |  ConvertTo-Html -Property Source , Action , SSID -Fragment

    $FiltersRulesHTML = $FiltersRulesHTML -replace '<td>Allow</td>', '<td class="AllowSSID">Allow</td>' 

    $FiltersRulesHTML = $FiltersRulesHTML -replace '<td>Block</td>', '<td class="BlockSSID">Block</td>' 
 
 }

 else {
 
        $FiltersRules = [PSCustomObject] @{'INFO' = "The Wireless AutoConfig Service (wlansvc) is not running."}

        $FiltersRulesHTML = $FiltersRules |  ConvertTo-Html -Property INFO -Fragment
 
 }


    $ReportElements += "====== Wireless Network =======`n" , "Wireless History" , ($Wireless_Events | Format-Table -AutoSize -Wrap ) , "Wireless Profiles" , ($WirelessInterfaceResults | Format-Table) , "Wireless Filter Rules" , ($FiltersRules | Format-Table)

    $ReportElementsHTML += "<h2>Wireless Network</h2>" , "<h3>Wireless History</h3>" , "$Wireless_EventsHTML" , "<h3>Wireless Profiles</h3>" , "$WirelessInterfaceResultsHTML", "<h3>Wireless Filter Rules</h3>" , "$FiltersRulesHTML" , "<hr>"

}

# ------------------------------------------ End of Wireless Network



# Task Scheduler ---------------------------------------------------

Write-Progress -Activity "Collecting Task Scheduler List"

$TaskSchedulerResult = @()

$TaskSchedulerResultHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'TaskScheduler List') {

    $TaskSchedulerResult = Get-ScheduledTask | Where-Object { ($_.TaskPath -notlike '*Microsoft*') } | Get-ScheduledTaskInfo | Select-Object TaskPath, TaskName, LastRunTime | Sort-Object -Property TaskPath

    $TaskSchedulerResultHTML = $TaskSchedulerResult | ConvertTo-Html -Property TaskPath, TaskName, LastRunTime -Fragment

    $ReportElements += "====== Task Scheduler =======" , ($TaskSchedulerResult | Format-Table )

    $ReportElementsHTML += "<h2>Task Scheduler</h2>" , "$TaskSchedulerResultHTML" , "<hr>"

}

# -------------------------------------------- End of Task Scheduler



# Services ---------------------------------------------------------

Write-Progress -Activity "Collecting Services List"

$WorkstationServices = @()

$WorkstationServicesHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Workstation Services') {

    $WorkstationServices = Get-CimInstance Win32_Service | Select-Object DisplayName, StartName, State, StartMode, ProcessId, PathName ,Description | Sort-Object  -Property DisplayName 

    $WorkstationServicesHTML = $WorkstationServices | ConvertTo-Html -Property * -Fragment

    $WorkstationServicesHTML = $WorkstationServicesHTML -replace '<td>Running</td>', '<td class="RunningStatus">Running</td>' 

    $WorkstationServicesHTML = $WorkstationServicesHTML -replace '<td>Stopped</td>', '<td class="StopStatus">Stopped</td>'

    $ReportElements += "====== Workstation Services =======" , ($WorkstationServices | Format-Table -AutoSize -Wrap )

    $ReportElementsHTML += "<h2>Workstation Services</h2>" , "$WorkstationServicesHTML" , "<hr>"

}

# -------------------------------------------------- End of Services





# RDP Connections --------------------------------------------------

Write-Progress -Activity "Collecting RDP Info"

$RDPResults = @()

$RDPResultsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'RDP') {


# Check RDP State

$RDPPathSystem = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

$RDPPathGPO = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$RDPPathGPO = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    if((Get-ItemProperty $RDPPathSystem).fDenyTSConnections -ne '1' -or ($null -ne (Get-ItemProperty $RDPPathGPO).fDenyTSConnections) -and (Get-ItemProperty $RDPPathGPO).fDenyTSConnections -ne '1'){

        $RDPPort = (Get-ItemProperty "$RDPPathSystem\WinStations\RDP-Tcp").PortNumber

        $RDPState = [PSCustomObject] @{'State' = "Enabled" ; 'Port' = $RDPPort }

        $RDPStateHTML = $RDPState | ConvertTo-Html -Property State , Port -Fragment

    }

    else {

        $RDPState = [PSCustomObject] @{'State' = "Disabled" ; 'Port' = $RDPPort }

        $RDPStateHTML = $RDPState | ConvertTo-Html -Property State , Port -Fragment

    }


# Check RDP Users


$RDPUsers = @()

if ($null -ne (Get-LocalGroup | Where-Object {$_.Name -eq "Remote Desktop Users"})){

    $RDPUsers = Get-LocalGroupMember -Group "Remote Desktop Users" | Select-Object Name , PrincipalSource
 
    if ( '0' -eq $RDPUsers.length){

    $RDPUsers = [PSCustomObject] @{'INFO' = "Remote Desktop Users Group Found. However, It Has No Members / Default Settings" }

    $RDPUsersHTML = $RDPUsers | ConvertTo-Html -Property INFO -Fragment

    }

    else {

    $RDPUsersHTML = $RDPUsers | ConvertTo-Html -Property Name , PrincipalSource -Fragment

    }

}

else {

    $RDPUsers = [PSCustomObject] @{'INFO' = "Remote Desktop Users Group Not Found" }

    $RDPUsersHTML = $RDPUsers | ConvertTo-Html -Property INFO -Fragment

}

# Check Attempts

$RDPAttemptEvents = @()

$RDPAttemptEventsHTML = @()

$RDPAttempt =  @{LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID = 261; StartTime = ((Get-Date).AddDays(-30)) }

    try {

        $RDPAttemptEvents = Get-Winevent -FilterHashtable $RDPAttempt -ErrorAction Stop 

        ForEach ($Event in $RDPAttemptEvents) {    

            $eventXML = [xml]$Event.ToXml() 

            For ($i = 0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {    

                Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'            

            }            
        }       

        $RDPAttemptEvents = $RDPAttemptEvents | Select-Object Id, TimeCreated , Message

        $RDPAttemptEventsHTML = $RDPAttemptEvents | ConvertTo-Html -Property Id, TimeCreated , Message -Fragment

    }

    catch [Exception] {

        if ($_.Exception -match "No events were found that match the specified selection criteria") {

            $RDPAttemptEvents = [PSCustomObject] @{'INFO' = "No RDP Connection attempts History Found" }

            $RDPAttemptEventsHTML = $RDPAttemptEvents | ConvertTo-Html -Property INFO -Fragment

        }

    } 


# Check Successful RDP Connections

$RDPSuccessEvents = @()

$RDPSuccessEventsHTML = @()

$RDPSuccess =  @{LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID = 25; StartTime = ((Get-Date).AddDays(-30)) }

    try {

        $RDPSuccessEvent = Get-Winevent -FilterHashtable $RDPSuccess -ErrorAction Stop 

        $RDPSuccessEvent |ForEach-Object {    

            $RDPEvent = [xml]$_.ToXml()

            $RDPSuccessEvents += New-Object PSObject -Property @{

            TimeCreated = $_.TimeCreated

            User = $RDPEvent.Event.UserData.EventXML.User

            IPAddress = $RDPEvent.Event.UserData.EventXML.Address

            EventID = $RDPEvent.Event.System.EventID

            }           

        }

        $RDPSuccessEvents = $RDPSuccessEvents | Select-Object EventID, TimeCreated , IPAddress , User

        $RDPSuccessEventsHTML = $RDPSuccessEvents | ConvertTo-Html -Property EventID, TimeCreated , IPAddress , User -Fragment

    }

    catch [Exception] {

        if ($_.Exception -match "No events were found that match the specified selection criteria") {

            $RDPSuccessEvents = [PSCustomObject] @{'INFO' = "No Successful RDP Connection History Found"}

            $RDPSuccessEventsHTML = $RDPSuccessEvents | ConvertTo-Html -Property INFO -Fragment

        }

    } 

$RDPResults = "RDP State" , ($RDPState | Format-Table) , "RDP Users" , ($RDPUsers | Format-Table) , "RDP Connections Attempts (30 Days)" , ($RDPAttemptEvents | Format-Table) , "Successful RDP Connections (30 Days)" , ($RDPSuccessEvents | Format-Table)

$RDPResultsHTML = "<h3>RDP State</h3>" , "$RDPStateHTML" , "<h3>RDP Users</h3>" , "$RDPUsersHTML" , "<h3>RDP Connections Attempts (30 Days)</h3>" , "$RDPAttemptEventsHTML" , "<h3>Successful RDP Connections (30 Days)</h3>" , "$RDPSuccessEventsHTML"

$ReportElements += "====== RDP =======`n" , ($RDPResults | Format-Table)

$ReportElementsHTML += "<h2>RDP</h2>" , "$RDPResultsHTML" , "<hr>"

}
# ------------------------------------------- End of RDP Connections



# TCP Connections --------------------------------------------------

Write-Progress -Activity "Collecting TCP Connections"

$TCPConnectionsResults = @()

$TCPConnectionsResultsHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'TCP Connections') {

    $TCPConnections = Get-NetTCPConnection | Select-Object State , CreationTime , LocalAddress , LocalPort , RemoteAddress , RemotePort , OwningProcess | Sort-Object CreationTime -Descending

    $TCPConnectionsBound = $TCPConnections | Where-Object {$_.State -eq "Bound"}

        if ('0' -ne $TCPConnectionsBound.Length){
        
            $TCPConnectionsBoundHTML = $TCPConnectionsBound | ConvertTo-Html -Property State , CreationTime , LocalAddress , LocalPort , RemoteAddress , RemotePort , OwningProcess -Fragment
        
        }

        else {
        
            $TCPConnectionsBound = [PSCustomObject] @{'INFO' = "No Bound TCP Connections Found"}

            $TCPConnectionsBoundHTML = $TCPConnectionsBound | ConvertTo-Html -Property INFO -Fragment
        
        }



    $TCPConnectionsEstablished = $TCPConnections | Where-Object {$_.State -eq "Established"}

        if ('0' -ne $TCPConnectionsEstablished.Length){
        
            $TCPConnectionsEstablishedHTML = $TCPConnectionsEstablished | ConvertTo-Html -Property State , CreationTime , LocalAddress , LocalPort , RemoteAddress , RemotePort , OwningProcess -Fragment
        
        }

        else {
        
            $TCPConnectionsEstablished = [PSCustomObject] @{'INFO' = "No Established TCP Connections Found"}

            $TCPConnectionsEstablishedHTML = $TCPConnectionsEstablished | ConvertTo-Html -Property INFO -Fragment
        
        }



    $TCPConnectionsListen = $TCPConnections | Where-Object {$_.State -eq "Listen"}

        if ('0' -ne $TCPConnectionsListen.Length){
        
            $TCPConnectionsListenHTML = $TCPConnectionsListen | ConvertTo-Html -Property State , CreationTime , LocalAddress , LocalPort , RemoteAddress , RemotePort , OwningProcess -Fragment
        
        }

        else {
        
            $TCPConnectionsListen = [PSCustomObject] @{'INFO' = "No Established TCP Connections Found"}

            $TCPConnectionsListenHTML = $TCPConnectionsListen | ConvertTo-Html -Property INFO -Fragment
        
        }



    $TCPConnectionsCloseWait = $TCPConnections | Where-Object {$_.State -eq "CloseWait"}

        if ('0' -ne $TCPConnectionsCloseWait.Length){
        
            $TCPConnectionsCloseWaitHTML = $TCPConnectionsCloseWait | ConvertTo-Html -Property State , CreationTime , LocalAddress , LocalPort , RemoteAddress , RemotePort , OwningProcess -Fragment
        
        }

        else {
        
            $TCPConnectionsCloseWait = [PSCustomObject] @{'INFO' = "No Established TCP Connections Found"}

            $TCPConnectionsCloseWaitHTML = $TCPConnectionsCloseWait | ConvertTo-Html -Property INFO -Fragment
        
        }



    $TCPConnectionsResults = "Bound State" , ($TCPConnectionsBound | Format-Table) , "Established State" , ($TCPConnectionsEstablished | Format-Table) , "Listen State" , ($TCPConnectionsListen | Format-Table), "CloseWait State" , ($TCPConnectionsCloseWait | Format-Table)

    $TCPConnectionsResultsHTML = "<h3>Bound State</h3>" , "$TCPConnectionsBoundHTML", "<h3>Established State</h3>" , "$TCPConnectionsEstablishedHTML" , "<h3>Listen State</h3>" , "$TCPConnectionsListenHTML" , "<h3>CloseWait State</h3>" , "$TCPConnectionsCloseWaitHTML"

    $ReportElements += "====== TCP Connections =======`n" , ($TCPConnectionsResults | Format-Table)

    $ReportElementsHTML += "<h2>TCP Connections</h2>" , "$TCPConnectionsResultsHTML" , "<hr>"

}

# ------------------------------------------- End of TCP Connections



# Groupless Firewall Rules -----------------------------------------

Write-Progress -Activity "Collecting Groupless Firewall Rules List"

$FirewallRules = @()

$FirewallRulesHTML = @()

if ($toDo -contains 'All' -or $toDO -contains 'Groupless Firewall Rules') {

    $FirewallRules = Get-NetFirewallRule -Enabled True | Where-Object { $_.DisplayGroup -eq $null } |  Select-Object -Property DisplayName, @{Name = 'Protocol'; Expression = { ($PSItem | Get-NetFirewallPortFilter).Protocol } }, @{Name = 'LocalPort'; Expression = { ($PSItem | Get-NetFirewallPortFilter).LocalPort } }, @{Name = 'RemotePort'; Expression = { ($PSItem | Get-NetFirewallPortFilter).RemotePort } }, @{Name = 'RemoteAddress'; Expression = { ($PSItem | Get-NetFirewallAddressFilter).RemoteAddress } }, Enabled, Profile, Direction, Action 

    $FirewallRulesHTML = $FirewallRules | ConvertTo-Html -Property DisplayName, Protocol, LocalPort, RemotePort, RemoteAddress, Enabled, Profile, Direction, Action -Fragment

    $ReportElements += "====== Groupless Firewall Rules =======" , ($FirewallRules | Format-Table)

    $ReportElementsHTML += "<h2>Groupless Firewall Rules</h2>" , "$FirewallRulesHTML" , "<hr>"

}

# ---------------------------------- End of Groupless Firewall Rules


# Report -----------------------------------------------------------

Write-Progress -Activity "Generating Report"

#Clear-Host

if ('0' -ne $ReportElements.Length) {

    $FinalReport = "`n" , "$env:ComputerName CSIR Report `n"

    $FinalReport += $ReportElements

    Write-Progress -Activity "Done" -Completed

    $FinalReport

}

if ('0' -ne $ReportElementsHTML.Length) {

    $FinalReportHTML += "<h1>$env:ComputerName CSIR Report</h1>" , "$ReportElementsHTML"

    $HTMLResultsFileName = "C:\" + $env:ComputerName + "_CSIR_Report.html"

    $Report = ConvertTo-HTML -Body "

    $FinalReportHTML

    " -Title "ComputerReport" -Head $header -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

    $Report | Out-File "$HTMLResultsFileName"

}




# ---------------------------------------------------- End Of Report