Import-Module ActiveDirectory
$path = "./" #path to folder
$file = (get-addomain).name + ".csv" #create a filename
$FilePath = $path+$file # add path and filename
$Members = @()
$count=0
$Test = test-path $path
If($test -eq $false) {
write-host "`nExport Path not accessible" -ForegroundColor Red
break}

$Servers = get-adcomputer -Filter { OperatingSystem -like "*Server*" }
foreach ($Server in $Servers) {
    $count ++
    write-host "Trying " $count "of" $($Servers.count) " $($server.name)"
    try {
        $Members += Invoke-Command -ScriptBlock {
            if ($PSVersionTable.PSVersion -ge "5.1") {
                Get-LocalGroupMember -Group "Administrators" | ForEach-Object { [string]$PS = $_.PrincipalSource; New-Object psobject -Property @{
                        Name            = $_.Name
                        SID             = $_.SID
                        PrincipalSource = $PS
                        ObjectClass     = $_.ObjectClass
                        Error           = ""
                    } }
            }
            else {
                New-Object PSObject -Property @{
                    Name            = ""
                    SID             = ""
                    PrincipalSource = ""
                    ObjectClass     = ""
                    Error           = "PowerShell version below 5.1"
                }
            }
        } -ComputerName $Server.DNSHostName -ErrorAction Stop
    }
    catch [System.Management.Automation.RemoteException] { # found by running $Error[0].exception.GetType().fullname
        $Members += New-Object PSObject -Property @{
            Name            = ""
            SID             = ""
            PrincipalSource = ""
            ObjectClass     = ""
            Error           = "User exists that is not in AD please review."
            PSComputerName  = $Server
            RunspaceId      = ""
        }
            
    }
    catch {
        $Members += New-Object PSObject -Property @{
            Name            = ""
            SID             = ""
            PrincipalSource = ""
            ObjectClass     = ""
            Error           = $_.Exception.Message
            PSComputerName  = $Server
            RunspaceId      = ""
        }
    }
}

$Users = $Members | Where-Object ObjectClass -EQ "User" | select ObjectClass, PrincipalSource, Name, PSComputerName, @{n = "Via"; e = { "Named Directly" } }, Error
$Users += $Members | Where-Object ObjectClass -EQ "" | select ObjectClass, PrincipalSource, Name, PSComputerName, Error
$Users += $Members | Where { $_.ObjectClass -EQ "Group" -and $_.PrincipalSource -NE "ActiveDirectory" } | select ObjectClass, PrincipalSource, Name, PSComputerName, @{n = "Via"; e = { "Named Directly" } }, Error
    
#get a unique list of AD groups and get the members for later look up
$ADGroups = $Members | Where { $_.ObjectClass -EQ "Group" -and $_.PrincipalSource -EQ "ActiveDirectory" } | Select-Object @{n = "Name"; e = { ($_.Name -split '\\')[1] } }, PrincipalSource, @{n = "Domain"; e = { ($_.Name -split '\\')[0] } } -Unique
$ADGroupMembers = @()
foreach ($ADGroup in $ADGroups) {
    try {
        $ADGroupMembers += Get-ADGroupMember $ADGroup.Name -Server $ADGroup.Domain -Recursive |
        select @{n = "Group"; e = { "$($ADGroup.Domain)\$($ADGroup.Name)" } }, SamAccountName, ObjectClass, @{n = "Domain"; e = { ($_.distinguishedName -split "," | where { $_ -match "DC=" })[0] -replace "DC=", "" } }, Error
    }
    catch {
        $ADGroupMembers += New-Object PSObject -Property @{
            Group          = "$($ADGroup.Domain)\$($ADGroup.Name)"
            SamAccountName = ""
            ObjectClass    = ""
            Domain         = ""
            Error          = "$($_.Exception.ItemName) $($_.Exception.Message)"
        }
    }
}

ForEach ( $G in ($Members | Where { $_.ObjectClass -EQ "Group" -and $_.PrincipalSource -EQ "ActiveDirectory" })) {
    $Users += $ADGroupMembers | Where Group -EQ $G.Name | select ObjectClass, @{n = "PrincipalSource"; e = { "ActiveDirectory" } }, @{n = "Name"; e = { "$($_.Domain)\$($_.SamAccountName)" } }, @{n = "PSComputerName"; e = { $G.PSComputerName } }, @{n = "Via"; e = { $G.Name } }, Error 
}

$Users | export-csv $filepath -notypeinformation
Pause