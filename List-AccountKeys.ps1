<#
.SYNOPSIS
Retrieves the observed Account Key types
.DESCRIPTION
Searches the Security Event Logs for intstances of Event Id 4769 and Event Id 4768 to determine which account keys are used.

.EXAMPLE
List-AccountKeys # This will list all accounts and their key types found in the past 90 days

.PARAMETER Since
Specifies the earliest time to be searched since
.PARAMETER SearchScope
Specifies whether we should search all KDCs in the domain or just the local machine

.NOTES
Author: Will Aftring (wiaftrin)

When specifying AllKdcs, to pull the event log results remote Event Log reading must be enabled.

Copyright (c) Microsoft Corporation. All rights reserved.

#>


[CmdletBinding()]
param(
    [DateTime]$Since = $(Get-Date).AddDays(-30),
    [ValidateSet("DES", "RC4", "AES-SHA1", "All")]
    [string]$ContainsKeyType = "All",
    [ValidateSet("DES", "RC4", "AES-SHA1", "None")]
    [string]$NotContainsKeyType = "None",
    [ValidateSet("This", "AllKdcs")]
    [string]$SearchScope = "This"
)

#region Classes

class EncryptionType {
    [string]$Name
    [int]$Value
    EncryptionType([string]$name, [int]$value) {
        $this.Name = $name
        $this.Value = $value
    }
    [string]ToDataString() {
        return "Data='0x{0:x}'" -f $this.Value
    }

    [string]ToString() {
        return $this.Name
    }

    [bool]Equals([object]$other) {
        if ($null -eq $other -or $this.GetType() -ne $other.GetType()) {
            return $false
        }
        $EType = [EncryptionType]$other
        return $EType.Name -eq $this.Name -and $EType.Value -eq $this.Value
    }
}

enum AccountType {
    User
    Machine
    Service
}

class Account {
    [datetime]$Time
    [string]$Name
    [AccountType]$Type
    [EncryptionType[]]$Keys

    Account([datetime]$tc, [string]$name, [AccountType]$ct, [string]$ckeys) {
        $this.Time = $tc
        $this.Name = $name
        $this.Type = $ct
        $this.Keys = $ckeys.Split(",").Trim() | ForEach-Object {
            $script:EncryptionNameTypeMap[$_]
        }
    }
}

#endregion

#region Globals

$script:XPathQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4769) and (TimeCreated[@SystemTime >= '$($Since.ToString("yyyy-MM-ddTHH:mm:ss"))'])]]
    </Select>
  </Query>
  <Query Id="1" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4768) and (TimeCreated[@SystemTime >= '$($Since.ToString("yyyy-MM-ddTHH:mm:ss"))'])]]
    </Select>
  </Query>
</QueryList>
"@

$script:DES_CRC = [EncryptionType]::new("DES_CRC", 0x1)
$script:DES_MD5 = [EncryptionType]::new("DES_MD5", 0x3)
$script:DES = [EncryptionType]::new("DES", 0x1)
$script:RC4 = [EncryptionType]::new("RC4", 0x17)
$script:AES_SHA1 = [EncryptionType]::new("AES-SHA1", 0x11)
$script:AES128 = [EncryptionType]::new("AES128-SHA96", 0x11)
$script:AES256 = [EncryptionType]::new("AES256-SHA96", 0x12)
$script:AES128_SHA256 = [EncryptionType]::new("AES128-SHA256", 0x13)
$script:AES256_SHA384 = [EncryptionType]::new("AES256-SHA384", 0x14)

$script:EncryptionNameTypeMap = @{}
$script:EncryptionNameTypeMap.Add($script:DES.Name, $script:DES)
$script:EncryptionNameTypeMap.Add($script:DES_CRC.Name, $script:DES_CRC)
$script:EncryptionNameTypeMap.Add($script:DES_MD5.Name, $script:DES_MD5)
$script:EncryptionNameTypeMap.Add($script:RC4.Name, $script:RC4)
$script:EncryptionNameTypeMap.Add($script:AES_SHA1.Name, $script:AES_SHA1)
$script:EncryptionNameTypeMap.Add($script:AES128.Name, $script:AES128)
$script:EncryptionNameTypeMap.Add($script:AES256.Name, $script:AES256)
$script:EncryptionNameTypeMap.Add($script:AES128_SHA256.Name, $script:AES128_SHA256)
$script:EncryptionNameTypeMap.Add($script:AES256_SHA384.Name, $script:AES256_SHA384)

<#
    N.B(wiaftrin): On Windows Server 2022 the AES-SHA1 keys are aggregated into a single string.
    On Windows Server 2025+, the keys are called out individually.
#>

# AES-SHA1 on 2022-
$script:AES_SHA1_FILTER_2022 = "AES-SHA1"
#AES-SHA1 on 2025+
$script:AES_SHA1_FILTER_2025 = "SHA96"
$script:AES_SHA1_FILTER = $script:AES_SHA1_FILTER_2022
if ([System.Environment]::OSVersion.Version.Build -gt 20348) {
    $script:AES_SHA1_FILTER = $script:AES_SHA1_FILTER_2025
}

$script:KeyFilter = ""
$script:NotKeyFilter = ""

#endregion

#region Functions

function Get-AccountsFromKDC {
    param(
        [string]$KDCName = $null,
        [string]$Query
    )
    Write-Debug "Query:`n$Query to KDC '$KDCName'"
    $Results = $null
    try {
        if ([string]::IsNullOrEmpty($KDCName)) {
            $Results = Get-WinEvent -FilterXPath $Query -LogName Security -ErrorAction Stop
        }
        else {
            $Results = Get-WinEvent -ComputerName $KDCName -FilterXPath $Query -LogName Security -ErrorAction Stop
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -eq "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand") {
            Write-Warning "No events found"
        }
        else {
            throw $_
        }
    }
    return $Results
}

#endregion

if ("All" -ne $ContainsKeyType) {
    # translate AES-SHA1 into either
    if ("AES-SHA1" -eq $ContainsKeyType) {
        $script:KeyFilter = $script:AES_SHA1_FILTER
    } elseif ("DES" -eq $ContainsKeyType) {
        $script:KeyFilter = "DES"
    }
     else {
        $script:KeyFilter = $ContainsKeyType
    }
}

if ("None" -ne $NotContainsKeyType) {
    if ("AES-SHA1" -eq $NotContainsKeyType) {
        $script:NotKeyFilter = $script:AES_SHA1_FILTER
    } elseif ("DES" -eq $ContainsKeyType) {
        $script:NotKeyFilter = "DES"
    } else {
        $script:NotKeyFilter = $NotContainsKeyType
    }
}

$accounts = [System.Collections.ArrayList]::new()
if ("This" -eq $SearchScope) {
    [Array]$r = $(Get-AccountsFromKDC -Query $script:XPathQuery)
    $accounts.AddRange($r)
}
else {
    Get-ADDomainController -Service KDC -Discover | ForEach-Object {
        $KDCName = $_.HostName
        try {
            [Array]$r = $(Get-AccountsFromKDC -KDCName $KDCName -Query $script:XPathQuery)
            $accounts.AddRange($r)
        }
        catch {
            Write-Error "Failed to get event logs from $KDCName with result: $_"
        }
    }
}

$originalLimit = $FormatEnumerationLimit
$FormatEnumerationLimit = -1
Write-Verbose "Accounts returned: $($accounts.Count)"
$accounts | ForEach-Object {
    [string]$keys = $_.Properties[16].Value
    if (-not [string]::IsNullOrEmpty($script:NotKeyFilter)) {
        if ($keys.Contains($script:NotKeyFilter)) {
            continue
        }
    }

    if(-not [string]::IsNullOrEmpty($script:KeyFilter)) {
        if (-not $keys.Contains($script:KeyFilter)) {
            continue
        }
    }

    if (4769 -eq $_.Id) {
        $type = [AccountType]::Service
        $target = $_.Properties[2].Value
        if ($target.EndsWith("$")) {
            $type = [AccountType]::Machine
        }
        [Account]::new($_.TimeCreated, $target, $type, $keys)
    }
    else {
        [Account]::new($_.TimeCreated, $_.Properties[0].Value, [AccountType]::User, $keys)
    }
}

$FormatEnumerationLimit = $originalLimit