Function Get-COMObjects {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, HelpMessage="Registry hive to read from")] 
        [string]$hive,
    )

    BEGIN { 
        Write-Host "Begin"
    }
    PROCESS {  
        Write-Host "Process"
    }        
    END { 
        Write-Host "End"
    }
}

Function Get-ExportedMethods {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, HelpMessage="Registry hive to read from")] 
        [string]$hive,
    )

    BEGIN { 
        Write-Host "Begin"
    }
    PROCESS {  
        $Position  = 1
        $Filename = "win10-clsid-members.txt"
        $inputFilename = "clsids.txt"
        ForEach($CLSID in Get-Content $inputFilename) {
            Write-Output "$($Position) - $($CLSID)"
            Write-Output "------------------------" | Out-File $Filename -Append
            Write-Output $($CLSID) | Out-File $Filename -Append
            $handle = [activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))
            $handle | Get-Member | Out-File $Filename -Append
            $Position += 1
        }
    }        
    END { 
        Write-Host "End"
    }
}

# Get-ChildItem -Path HKCU:\Software\Classes