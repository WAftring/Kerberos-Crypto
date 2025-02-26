<#
.SYNOPSIS
Retrieves ticket and session key encryption types
.DESCRIPTION
Searches the Security Event Log for instances of Event Id 4769 and Event Id 4768 to create a list of encryption types used in Kerberos tickets
.EXAMPLE
Get-KerbEncryptionUsage # This will list all requests seen in the the past 30 days
.EXAMPLE
Get-KerbEncryptionUsage -Encryption RC4 -EncryptionUsage Ticket # This will list all requests that used RC4 in the Ticket encryption
.EXAMPLE
Get-KerbEncryptionUsage -Searchscope AllKdcs -Since (Get-Date).AddDays(-7) # This will list all requests querying all KDCs for events in the past 7 days

.PARAMETER Encryption
Specifies the encryption type to be queried
.PARAMETER Since
Specifies the earliest point to be queried from
.PARAMETER SearchScope
Specifies whether the query should be the local machine or all KDCs
.PARAMETER EncryptionUsage
Specifies where to check for encryption usage. Ticket, SessionKey, Either or Both

.NOTES
Author: Will Aftring (wiaftrin)

When specifying AllKdcs, to pull the event log results remote Event Log reading must be enabled.

Copyright (c) Microsoft Corporation. All rights reserved.

#>

[CmdletBinding()]
param(
    [ValidateSet("RC4", "DES", "AES-SHA1", "AES128-SHA96", "AES256-SHA96", "All")]
    [string]$Encryption = "All",
    [DateTime]$Since = $(Get-Date).AddDays(-30),
    [ValidateSet("This", "AllKdcs")]
    [string]$SearchScope = "This",
    [ValidateSet("Ticket", "SessionKey", "Either", "Both")]
    [string]$EncryptionUsage = "Either"
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

enum RequestType {
    AS
    TGS
}

class KerbRequest {
    [DateTime]$Time
    [string]$Requestor
    [string]$Source
    [string]$Target
    [RequestType]$Type
    [EncryptionType]$Ticket
    [EncryptionType]$SessionKey
    KerbRequest([datetime]$tc, [string]$r, [string]$s, [string]$t, [RequestType]$rt, [EncryptionType]$te, [EncryptionType]$se) {
        $this.Time = $tc
        if ($r.StartsWith("::ffff:")) {
            $r = $r.Replace("::ffff:", "")
        }
        $this.Requestor = $r
        $this.Source = $s
        $this.Target = $t
        $this.Type = $rt
        $this.Ticket = $te
        $this.SessionKey = $se
    }
}

#endregion



#region Globals

$script:DES_CRC = [EncryptionType]::new("DES-CRC", 0x1)
$script:DES_MD5 = [EncryptionType]::new("DES-MD5", 0x3)
$script:RC4 = [EncryptionType]::new("RC4", 0x17)
$script:AES128 = [EncryptionType]::new("AES128-SHA96", 0x11)
$script:AES256 = [EncryptionType]::new("AES256-SHA96", 0x12)
$script:AES128_SHA256 = [EncryptionType]::new("AES128-SHA256", 0x13)
$script:AES256_SHA384 = [EncryptionType]::new("AES256-SHA384", 0x14)

$script:EncryptionNameTypeMap = @{}
$script:EncryptionNameTypeMap.Add($script:DES_CRC.Name, $script:DES_CRC)
$script:EncryptionNameTypeMap.Add($script:DES_MD5.Name, $script:DES_MD5)
$script:EncryptionNameTypeMap.Add($script:RC4.Name, $script:RC4)
$script:EncryptionNameTypeMap.Add($script:AES128.Name, $script:AES128)
$script:EncryptionNameTypeMap.Add($script:AES256.Name, $script:AES256)
$script:EncryptionNameTypeMap.Add($script:AES128_SHA256.Name, $script:AES128_SHA256)
$script:EncryptionNameTypeMap.Add($script:AES256_SHA384.Name, $script:AES256_SHA384)

$script:EncryptionValueTypeMap = @{}
$script:EncryptionValueTypeMap.Add($script:DES_CRC.Value, $script:DES_CRC)
$script:EncryptionValueTypeMap.Add($script:DES_MD5.Value, $script:DES_MD5)
$script:EncryptionValueTypeMap.Add($script:RC4.Value, $script:RC4)
$script:EncryptionValueTypeMap.Add($script:AES128.Value, $script:AES128)
$script:EncryptionValueTypeMap.Add($script:AES256.Value, $script:AES256)
$script:EncryptionValueTypeMap.Add($script:AES128_SHA256.Value, $script:AES128_SHA256)
$script:EncryptionValueTypeMap.Add($script:AES256_SHA384.Value, $script:AES256_SHA384)

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

#endregion

#region Functions
function Get-KdcEventLog {
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

function Check-ETypeUsage {
    param(
        [string]$UsageMode,
        [EncryptionType]$TicketEtype,
        [EncryptionType]$SKEtype,
        [EncryptionType]$SearchEtype
    )

    if ("Both" -eq $EncryptionUsage) {
        return $($TicketEtype -eq $SKEtype -and $SearchEtype -eq $TicketEtype)
    }
    elseif ("Ticket" -eq $EncryptionUsage) {
        return $($TicketEtype -eq $SearchEtype)
    }
    elseif ("SessionKey" -eq $EncryptionUsage) {
        return $($SKEtype -eq $SearchEtype)
    }
    else {
        return $($SKEtype -eq $SearchEtype -or $TicketEtype -eq $SearchEtype)
    }
}

#endregion

#region Main

$Events = [System.Collections.ArrayList]::new()
if ("AllKdcs" -eq $SearchScope) {

    Get-ADDomainController -Service KDC -Discover | ForEach-Object {
        $KDCName = $_.HostName
        try {
            [Array]$r = $(Get-KdcEventLog -KDCName $KDCName -Query $script:XPathQuery)
            $Events.AddRange($r)
        }
        catch {
            Write-Error "Failed to get event logs from $KDCName with result: $_"
        }
    }
}
else {
    [Array]$r = $(Get-KdcEventLog -Query $script:XPathQuery)
    $Events.AddRange($r)
}
Write-Verbose "Total events: $($Events.Count)"
$Events | ForEach-Object {
    $ShowRequest = $true
    $T = $null
    $SK = $null
    $R = $null
    $Target = $null
    $IP = $null

    if ($_.Id -eq 4769) {
        $Target = $_.Properties[2].Value
        $T = $script:EncryptionValueTypeMap[$_.Properties[5].Value]
        $SK = $script:EncryptionValueTypeMap[$_.Properties[20].Value]
        $R = [RequestType]::TGS
        $IP = $_.Properties[6].Value

    }
    else {
        $Target = $_.Properties[3].Value
        $T = $script:EncryptionValueTypeMap[$_.Properties[7].Value]
        $SK = $script:EncryptionValueTypeMap[$_.Properties[22].Value]
        $R = [RequestType]::AS
        $IP = $_.Properties[9].Value
    }

    if ("DES" -eq $Encryption) {
        $D1 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:DES_CRC
        $D2 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:DES_MD5
        $ShowRequest = $D1 -or $D2
    }
    elseif("AES-SHA1" -eq $Encryption) {
        $A1 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:AES128
        $A2 = Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $script:AES256
        $ShowRequest = $A1 -or $A2
    }
    elseif ("All" -ne $Encryption) {
        $Etype = $script:EncryptionNameTypeMap[$Encryption]
        $ShowRequest = $(Check-ETypeUsage -UsageMode $EncryptionUsage -TicketEtype $T -SKEtype $SK -SearchEtype $EType)
    }

    if ($ShowRequest) {
        [KerbRequest]::new($_.TimeCreated, $IP, $_.Properties[0].Value, $Target, $R, $T, $SK)
    }
}

#endregion