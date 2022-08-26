 #requires -version 2

<#
Author: Ezra Buckingham (@BuckinghamEzra)
#>


function Get-COMObjects {
<#
.SYNOPSIS
Get all COM Objects from the registry and export them as a CSV
Author: Ezra Buckingham (@BuckinghamEzra)
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION
This will search through the registry and pull back all the CLSIDs
found and export them to a CSV file for later processing

.PARAMETER OutputFile
Specifies the path to the output csv file

.EXAMPLE
Get-COMObjects -OutputFile conrad.csv
#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$false, HelpMessage="Output file for the CLSIDs")] 
        [String]
        $OutputFile
    )

    BEGIN { 

        # Try creating the Output file
        try {
            New-Item -Path $OutputFile -ItemType "File"
        }
        catch {

        }

        # Try mapping the HKCR
        try {
            New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR 
        }
        catch {

        }
    }

    PROCESS {  
        Write-Host "Processing all CLSIDs in the Registry"

        $reg_paths = @(
            "HKCU:\SOFTWARE\Classes\CLSID", # HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\
            "HKLM:\SOFTWARE\Classes\CLSID", # HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\
            "HKCR:\CLSID" # HKEY_CLASSES_ROOT\WOW6432Node\CLSID\
            "HKCR:\WOW6432Node\CLSID" # HKEY_CLASSES_ROOT\WOW6432Node\CLSID\
        )

        $all_keys = @()

        # Iterate over all the hives
        ForEach($reg in $reg_paths) {
            # Get the keys from the hive
            Write-Host "Getting Keys from ${reg}"
            $keys = Get-ChildItem -Path $reg
            $num_keys = $keys.Length

            Write-Host "Got ${num_keys} Keys from ${reg}"

            $all_keys += $keys
        } 

        # Hold the list of retrieved CLSIDs
        $clsids = @()

        # Iterate over all the keys found
        ForEach($key in $all_keys) {
            # Get the last key value
            $split_key = $key -split "\\"
            $last_element = $split_key[$split_key.Length - 1]

            if ($last_element -match "^{[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]}?$") {
                $clsids += $key
            }
        } 

        $clsids | Export-Csv $OutputFile
    }  

    END { 
        Write-Host "End"
    }
}

Function Get-ExportedMethods {
<#
.SYNOPSIS
Get all COM Objects from the registry and export them as a CSV
Author: Ezra Buckingham (@BuckinghamEzra)
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION


.PARAMETER ModuleName
Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE
$Module = New-InMemoryModule -ModuleName Win32
#>

    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true, HelpMessage="Input file from the Get-COMObjects function")] 
        [String]
        $InputFile,

        [Parameter(Mandatory=$true, HelpMessage="Output file for all class members")] 
        [String]
        $OutputFile,

        [Parameter(Mandatory=$true, HelpMessage="Output file for all class members")] 
        [String]
        $ExclusionFile
    )

    BEGIN { 
        # Try creating the Output file
        try {
            New-Item -Path $OutputFile -ItemType "File"
        }
        catch {

        }
        [string[]]$exclusion_list = Get-Content -Path $ExclusionFile
    }

    PROCESS {  

        $index = 0
        $input_file = Import-Csv -Path $InputFile
        $classes = @()

        ForEach($class in $input_file) {
            $clsid = $class.PSChildName

            $excluded = $false
            ForEach($exc_clsid in $exclusion_list) {
                $exc_clsid = $exc_clsid.replace('{', '')
                $exc_clsid = $exc_clsid.replace('}', '')

                if ($clsid -like "*${exc_clsid}*") {
                    $excluded = $true
                    break
                }
            }

            if ($excluded) {
                Write-Output "Skipping ${clsid} object"
                continue
            }

            Write-Output "Creating ${clsid} object"

            try {
                $handle = [activator]::CreateInstance([type]::GetTypeFromCLSID($clsid))
                try {
                    $methods = $handle | Get-Member
                    $modified_methods = @()

                    foreach($method in $methods) {
                        $method | Add-Member -MemberType NoteProperty -Name "CLSID" -Value $clsid
                        $modified_methods += $method
                    }
                    $classes += $modified_methods

                    $modified_methods | Export-Csv $OutputFile -Append

                    $index += 1
                }
                catch {
                    Write-Host "Unable to get members of ${clsid} object"
                }
            }
            catch {
                Write-Host "Unable to create ${clsid} object"
            }
        }

        Write-Host "Found ${index} classes" 

    }        
    END { 
        Write-Host "End"
    }
}

Get-ExportedMethods -InputFile conrad22.csv -OutputFile conrad22_out.csv -ExclusionFile C:\Users\Victim\Desktop\exc.txt.txt 
    