#region Globals

$script:KEY_PATH = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

class EncryptionType {
        [uint]$Mask
        [int]$Value
        [string]$Name

        EncryptionType([uint]$m, [int]$v, [string]$n) {
                $this.Mask = $m
                $this.Value =$v
                $this.Name = $n
        }

        [bool] EnabledInMask([uint]$mask) {
            return ($mask -band $this.Mask) -eq $this.Mask
        }
}

class KerbRegDwordSetting
{
    [string]$Name
    hidden [uint]$Value
    hidden [uint]$DefaultValue
    hidden [bool]$IsDefined
    [string]$Setting

    hidden [void] Init($name, $defaultValue, $callback)
    {
        $this.Name = $name
        $this.DefaultValue = $defaultValue

        try {
            $this.Value = Get-ItemPropertyValue -Path $script:KEY_PATH -Name $this.Name -ErrorAction Stop
            $this.IsDefined = $true
        }
        catch {
            $this.Value = $this.DefaultValue
            $this.IsDefined = $false
        }

        if ($null -ne $callback) {
            $this.Setting = $callback.Invoke($this.Value)
        } else {
            $this.Setting = $this.Value
        }
    }

    KerbRegDwordSetting($name, $defaultValue, $callback)
    {
        $this.Init($name, $defaultValue, $callback)
    }

    KerbRegDwordSetting($name, $defaultValue)
    {
        $this.Init($name, $defaultValue, $null)
    }

    [pscustomobject] Verbose()
    {
        return [pscustomobject]@{
            Name = $this.Name
            Setting = $this.Setting
            Value = $this.Value
            DefaultValue = $this.DefaultValue
            IsDefined = $this.IsDefined
            IsDefault = $this.Value -eq $this.DefaultValue
        }
    }
}

#region definitions

$script:DES_CRC = [EncryptionType]::new(0x1, 1, "DES-CRC")
$script:DES_MD5 = [EncryptionType]::new(0x2, 3,"DES-MD5")
$script:RC4 = [EncryptionType]::new(0x4, -128, "RC4")
$script:AES128 = [EncryptionType]::new(0x8, 17, "AES128-SHA96")
$script:AES256 = [EncryptionType]::new(0x10, 18, "AES256-SHA96")
$script:AES_SK = [EncryptionType]::new(0x20, 18, "AES-SK")
$script:AES128_SHA2 = [EncryptionType]::new(0x40, 19, "AES128-SHA256")
$script:AES256_SHA2 = [EncryptionType]::new(0x80, 20, "AES256-SHA384")
$script:ETYPES = (
    $script:DES_CRC,
    $script:DES_MD5,
    $script:RC4,
    $script:AES128,
    $script:AES256,
    $script:AES_SK,
    $script:AES128_SHA2,
    $script:AES256_SHA2
)

$script:KEY_SET = [KerbRegDwordSetting]::new("SupportedEncryptionTypes", 0x1c, {
        param([uint]$mask)
        $etypes_string = ""

        foreach($etype in $script:ETYPES) {

            if($etype.EnabledInMask($mask)) {
                if (-not [string]::IsNullOrEmpty($etypes_string)) {
                    $etypes_string += ", "
                }
                $etypes_string += $etype.Name
            }
        }

        if ([string]::IsNullOrEmpty($etypes_string)) {
            $etypes_string = "None"
        }

        return $etypes_string.TrimEnd()
    })

$script:KEY_SKEWTIME = [KerbRegDwordSetting]::new("SkewTime", 5, { return "$args minutes"})
$script:KEY_LOGLEVEL = [KerbRegDwordSetting]::new("LogLevel", 0)
$script:KEY_MAXPACKETSIZE = [KerbRegDwordSetting]::new("MaxPacketSize", 1465, { return "$args bytes" })
$script:KEY_STARTUPTIME = [KerbRegDwordSetting]::new("StartupTime", 120, { return "$args seconds" })
$script:KEY_KDCWAITTIME = [KerbRegDwordSetting]::new("KdcWaitTime", 10, { return "$args seconds" })
$script:KEY_KDCBACKOFFTIME = [KerbRegDwordSetting]::new("KdcBackoffTime", 10, { return "$args seconds" })
$script:KEY_KDCSENDRETRIES = [KerbRegDwordSetting]::new("KdcSendRetries", 3)
$script:KEY_DEFAULTENCRYPTIONTYPE = [KerbRegDwordSetting]::new("DefaultEncryptionType", 18, {
    param([int]$value)
    foreach($etype in $script:ETYPES) {
        if ($etype.Value -eq $value) {
            return $etype.Name
        }
    }
    return "None"
})
$script:KEY_FARKDCTIMEOUT = [KerbRegDwordSetting]::new("FarKdcTimeout", 10, { return "$args minutes" })
$script:KEY_NEARKDCTIMEOUT = [KerbRegDwordSetting]::new("NearKdcTimeout", 30, { return "$args minutes" })
$script:KEY_STRONGLYENCRYPTDATAGRAM = [KerbRegDwordSetting]::new("StronglyEncryptDatagram", 1, { return $args -eq 1 })
$script:KEY_MAXREFERRALCOUNT = [KerbRegDwordSetting]::new("MaxReferralCount", 6)
$script:KEY_MAXTOKENSIZE = [KerbRegDwordSetting]::new("MaxTokenSize", 48000)
$script:KEY_SPNCACHETIMEOUT = [KerbRegDwordSetting]::new("SpnCacheTimeout", 15, { return "$args minutes" })
$script:KEY_S4UCACHETIMEOUT = [KerbRegDwordSetting]::new("S4UCacheTimeout", 15, { return "$args minutes" })
$script:KEY_S4UTICKETLIFETIME = [KerbRegDwordSetting]::new("S4UTicketLifetime", 15, { return "$args minutes" })
$script:KEY_RETRYPDC = [KerbRegDwordSetting]::new("RetryPdc", 0, {  if ($args -ne 0) {"True"} else {"False"} })
$script:KEY_REQUESTOPTIONS = [KerbRegDwordSetting]::new("RequestOptions", 0x00010000, { return "0x{0:x}" -f $args })
$script:KEY_CLIENTIPADDRESSES = [KerbRegDwordSetting]::new("ClientIpAddresses", 0, { if ($args -ne 0) { "True" } else { "False" } })
$script:KEY_TGTRENEWALTIME = [KerbRegDwordSetting]::new("TgtRenewalTime", 600, { return "$args seconds" })
$script:KEY_ALLOWTGTSESSIONKEY = [KerbRegDwordSetting]::new("AllowTgtSessionKey", 0, { if ($args -ne 0) { "True" } else { "False" } })
$script:KEYS = (
    $script:KEY_SET,
    $script:KEY_SKEWTIME,
    $script:KEY_LOGLEVEL,
    $script:KEY_MAXPACKETSIZE,
    $script:KEY_STARTUPTIME,
    $script:KEY_KDCWAITTIME,
    $script:KEY_KDCBACKOFFTIME,
    $script:KEY_KDCSENDRETRIES,
    $script:KEY_DEFAULTENCRYPTIONTYPE,
    $script:KEY_FARKDCTIMEOUT,
    $script:KEY_NEARKDCTIMEOUT,
    $script:KEY_STRONGLYENCRYPTDATAGRAM,
    $script:KEY_MAXREFERRALCOUNT,
    $script:KEY_MAXTOKENSIZE,
    $script:KEY_SPNCACHETIMEOUT,
    $script:KEY_S4UCACHETIMEOUT,
    $script:KEY_S4UTICKETLIFETIME,
    $script:KEY_RETRYPDC,
    $script:KEY_REQUESTOPTIONS,
    $script:KEY_CLIENTIPADDRESSES,
    $script:KEY_TGTRENEWALTIME,
    $script:KEY_ALLOWTGTSESSIONKEY
)

#endregion




#region Functions

function Get-KerbConfig {
    [CmdletBinding()]
    param(
        [ValidateSet("All",
    "SupportedEncryptionTypes",
    "SkewTime",
    "LogLevel",
    "MaxPacketSize",
    "StartupTime",
    "KdcWaitTime",
    "KdcBackoffTime",
    "KdcSendRetries",
    "DefaultEncryptionType",
    "FarKdcTimeout",
    "NearKdcTimeout",
    "StronglyEncryptDatagram",
    "MaxReferralCount",
    "MaxTokenSize",
    "SpnCacheTimeout",
    "S4UTicketLifetime",
    "RetryPdc",
    "RequestOptions",
    "ClientIpAddresses",
    "TgtRenewalTime",
    "AllowTgtSessionKey")]
        [string[]]$Configurations = "All"
    )

    $IsVerbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

    if ("All" -ne $Configurations[0]) {
        foreach($name in $Configurations) {
            foreach($key in $script:KEYS) {
                if ($key.Name -eq $name) {
                    if ($IsVerbose) {
                        $key.Verbose()
                    } else {
                        $key
                    }
                }
            }
        }
    } else {
        if ($IsVerbose) {
            $script:KEYS | ForEach-Object { $_.Verbose() } | Format-Table
        } else {
            $script:KEYS
        }
    }
}

Export-ModuleMember -Function 'Get-KerbConfig'

#end region