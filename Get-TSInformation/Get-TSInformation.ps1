#region <Get-TSInformation>
<#
.SYNOPSIS
Retrieve information about TS properties

.DESCRIPTION
Retrieve information about TS properties of AD accounts

.PARAMETER SamAccountName
Get Terminal Server Information for a specific user.

Specifies an Active Directory user object by providing one of the following property values. The identifier in parentheses is the LDAP display name for the attribute. The acceptable values for this parameter are:

1. A distinguished name
2. A GUID (objectGUID)
3. A security identifier (objectSid)
4. A SAM account name (sAMAccountName)
The cmdlet searches the default naming context or partition to find the object. If two or more objects are found, the cmdlet returns a non-terminating error.

.EXAMPLE
Get-TSInformation

.NOTES
General notes
#>
Function Get-TSInformation {
    #Start Function Get-TSInformation
    [CmdletBinding()]
    [OutputType([Array])]
    param (
        [parameter(Position = 0,
            Mandatory = $false)]
        [string]$SamAccountName = $null
    
    )

    Begin {
        Write-Verbose ('[{0:O}] Starting {1}' -f (get-date), $myinvocation.mycommand)
        Write-Verbose ('[{0:O}] Creating an empty array' -f (get-date))
        $Result = @()

    }

    Process {
        if ($null -eq $SamAccountName) {
            $ADUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties *
            foreach ($UserObject in $ADUsers) {
                If (!($Null -eq $UserObject.userParameters)) {
                    $ADSIObject = [adsi]"LDAP://$($UserObject.DistinguishedName)"
                    $Value = [PSCustomObject]@{}

                    $Value | Add-Member -MemberType NoteProperty -Name "Name" -Value $UserObject.SamAccountName
                    $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesallowLogon" -Value ($ADSIObject.PSBase.invokeget("allowLogon"))
                    $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesHomeDirectory" -Value ($ADSIObject.PSBase.invokeget("TerminalServicesHomeDirectory"))
                    $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesHomeDrive" -Value ($ADSIObject.PSBase.invokeget("TerminalServicesHomeDrive"))
                    $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesProfilePath" -Value ($ADSIObject.PSBase.invokeget("TerminalServicesProfilePath"))
                    $result += $Value
                }
            }
        }
        else {
            $ADUser = Get-ADUser -Identity $SamAccountName -Properties *
            If (!($Null -eq $ADUser.userParameters)) {
                $ADSIObject = [adsi]"LDAP://$($ADUser.DistinguishedName)"
                $Value = [PSCustomObject]@{}

                $Value | Add-Member -MemberType NoteProperty -Name "Name" -Value $ADUser.SamAccountName
                $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesallowLogon" -Value ($ADSIObject.PSBase.invokeget("allowLogon"))
                $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesHomeDirectory" -Value ($ADSIObject.PSBase.invokeget("TerminalServicesHomeDirectory"))
                $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesHomeDrive" -Value ($ADSIObject.PSBase.invokeget("TerminalServicesHomeDrive"))
                $Value | Add-Member -MemberType NoteProperty -Name "TerminalServicesProfilePath" -Value ($ADSIObject.PSBase.invokeget("TerminalServicesProfilePath"))
                $result += $Value
            }
        }
    }

    End {
        Write-Verbose ('[{0:O}] Ending {1}' -f (get-date), $myinvocation.mycommand)
        Return $Result
    }
}	 #End Function Get-TSInformation
#endregion <Get-TSInformation>