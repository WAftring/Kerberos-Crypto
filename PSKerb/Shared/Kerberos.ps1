class EncryptionType {
    [int]$Mask
    [int]$Value
    [string]$Name

    EncryptionType([int]$m, [int]$v, [string]$n) {
        $this.Mask = $m
        $this.Value = $v
        $this.Name = $n
    }

    [bool] EnabledInMask([int]$mask) {
        return ($mask -band $this.Mask) -eq $this.Mask
    }
}

class KerbRegDwordSetting {
    [string]$Name
    hidden [int]$Value
    hidden [int]$DefaultValue
    hidden [bool]$IsDefined
    hidden [scriptblock]$Callback
    hidden [string]$Key
    [string]$Setting

    hidden [void] Init($key, $name, $defaultValue, $callback) {
        $this.Name = $name
        $this.DefaultValue = $defaultValue
        $this.Callback = $callback
        $this.IsDefined = $false
        $this.Key = $key
        $this.Setting = ""
    }

    [void] Update() {
        try {
            $this.Value = Get-ItemPropertyValue -Path $this.Key -Name $this.Name -ErrorAction Stop
            $this.IsDefined = $true
        }
        catch {
            Write-Verbose "Exception while processing registry key $($this.Key) with value $($this.Name)`n$_)"
            $this.Value = $this.DefaultValue
            $this.IsDefined = $false
        }

        if ($null -ne $this.Callback) {
            $this.Setting = $this.Callback.Invoke($this.Value)
        }
        else {
            $this.Setting = $this.Value
        }
    }

    KerbRegDwordSetting($key, $name, $defaultValue, $callback) {
        $this.Init($key, $name, $defaultValue, $callback)
    }

    KerbRegDwordSetting($key, $name, $defaultValue) {
        $this.Init($key, $name, $defaultValue, $null)
    }

    [void] Set([int]$value) {
        $hex = "{0:X}" -f $value
        Write-Verbose "Setting $($this.Name) to $hex"
        if (-not $(Test-Path -Path $this.Key)) {
            New-Item -Path $this.Key -Force
        }
        Set-ItemProperty -Path $this.Key -Name $this.Name -Value $value -Type DWord
    }

    [void] Clear() {
        if ($null -ne $(Get-ItemProperty -Path $this.Key -Name $this.Name -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $this.Key -Name $this.Name
        }
    }

    [pscustomobject] Display([bool]$detailed) {
        $obj = [pscustomobject]@{
            Name    = $this.Name
            Setting = $this.Setting
        }

        if ($detailed) {
            Add-Member -InputObject $obj -Name "Value" -Value $this.Value -MemberType NoteProperty
            Add-Member -InputObject $obj -Name "DefaultValue" -Value $this.DefaultValue -MemberType NoteProperty
            Add-Member -InputObject $obj -Name "IsDefined" -Value $this.IsDefined -MemberType NoteProperty
            Add-Member -InputObject $obj -Name "IsDefault" -Value $($this.Value -eq $this.DefaultValue) -MemberType NoteProperty
        }

        return $obj
    }
}

#region definitions

$script:DES_CRC = [EncryptionType]::new(0x1, 1, "DES-CRC")
$script:DES_MD5 = [EncryptionType]::new(0x2, 3, "DES-MD5")
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



$script:KERBEROS_KEY_PATH = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

$script:KERBEROS_KEYS_SET = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "SupportedEncryptionTypes", 0x1c, {
        param([int]$mask)
        $etypes_string = ""

        foreach ($etype in $script:ETYPES) {

            if ($etype.EnabledInMask($mask)) {
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

$script:KERBEROS_KEYS_SKEWTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "SkewTime", 5, { return "$args minutes" })
$script:KERBEROS_KEYS_LOGLEVEL = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "LogLevel", 0)
$script:KERBEROS_KEYS_MAXPACKETSIZE = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "MaxPacketSize", 1465, { return "$args bytes" })
$script:KERBEROS_KEYS_STARTUPTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "StartupTime", 120, { return "$args seconds" })
$script:KERBEROS_KEYS_KDCWAITTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "KdcWaitTime", 10, { return "$args seconds" })
$script:KERBEROS_KEYS_KDCBACKOFFTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "KdcBackoffTime", 10, { return "$args seconds" })
$script:KERBEROS_KEYS_KDCSENDRETRIES = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "KdcSendRetries", 3)
$script:KERBEROS_KEYS_DEFAULTENCRYPTIONTYPE = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "DefaultEncryptionType", 18, {
        param([int]$value)
        foreach ($etype in $local:ETYPES) {
            if ($etype.Value -eq $value) {
                return $etype.Name
            }
        }
        return "None"
    })
$script:KERBEROS_KEYS_FARKDCTIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "FarKdcTimeout", 10, { return "$args minutes" })
$script:KERBEROS_KEYS_NEARKDCTIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "NearKdcTimeout", 30, { return "$args minutes" })
$script:KERBEROS_KEYS_STRONGLYENCRYPTDATAGRAM = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "StronglyEncryptDatagram", 1, { return $args -eq 1 })
$script:KERBEROS_KEYS_MAXREFERRALCOUNT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "MaxReferralCount", 6)
$script:KERBEROS_KEYS_MAXTOKENSIZE = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "MaxTokenSize", 48000)
$script:KERBEROS_KEYS_SPNCACHETIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "SpnCacheTimeout", 15, { return "$args minutes" })
$script:KERBEROS_KEYS_S4UCACHETIMEOUT = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "S4UCacheTimeout", 15, { return "$args minutes" })
$script:KERBEROS_KEYS_S4UTICKETLIFETIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "S4UTicketLifetime", 15, { return "$args minutes" })
$script:KERBEROS_KEYS_RETRYPDC = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "RetryPdc", 0, { if ($args -ne 0) { "True" } else { "False" } })
$script:KERBEROS_KEYS_REQUESTOPTIONS = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "RequestOptions", 0x00010000, { return "0x{0:x}" -f $args })
$script:KERBEROS_KEYS_CLIENTIPADDRESSES = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "ClientIpAddresses", 0, { if ($args -ne 0) { "True" } else { "False" } })
$script:KERBEROS_KEYS_TGTRENEWALTIME = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "TgtRenewalTime", 600, { return "$args seconds" })
$script:KERBEROS_KEYS_ALLOWTGTSESSIONKEY = [KerbRegDwordSetting]::new($script:KERBEROS_KEY_PATH, "AllowTgtSessionKey", 0, { if ($args -ne 0) { "True" } else { "False" } })
$script:KERBEROS_KEYS = (
    $script:KERBEROS_KEYS_SET,
    $script:KERBEROS_KEYS_SKEWTIME,
    $script:KERBEROS_KEYS_LOGLEVEL,
    $script:KERBEROS_KEYS_MAXPACKETSIZE,
    $script:KERBEROS_KEYS_STARTUPTIME,
    $script:KERBEROS_KEYS_KDCWAITTIME,
    $script:KERBEROS_KEYS_KDCBACKOFFTIME,
    $script:KERBEROS_KEYS_KDCSENDRETRIES,
    $script:KERBEROS_KEYS_DEFAULTENCRYPTIONTYPE,
    $script:KERBEROS_KEYS_FARKDCTIMEOUT,
    $script:KERBEROS_KEYS_NEARKDCTIMEOUT,
    $script:KERBEROS_KEYS_STRONGLYENCRYPTDATAGRAM,
    $script:KERBEROS_KEYS_MAXREFERRALCOUNT,
    $script:KERBEROS_KEYS_MAXTOKENSIZE,
    $script:KERBEROS_KEYS_SPNCACHETIMEOUT,
    $script:KERBEROS_KEYS_S4UCACHETIMEOUT,
    $script:KERBEROS_KEYS_S4UTICKETLIFETIME,
    $script:KERBEROS_KEYS_RETRYPDC,
    $script:KERBEROS_KEYS_REQUESTOPTIONS,
    $script:KERBEROS_KEYS_CLIENTIPADDRESSES,
    $script:KERBEROS_KEYS_TGTRENEWALTIME,
    $script:KERBEROS_KEYS_ALLOWTGTSESSIONKEY
)

$script:KERBEROS_PARAMETER_MAPPING = @{
    "SupportedEncryptionTypes"   = $script:KERBEROS_KEYS_SET
    "SkewTimeInMinutes"          = $script:KERBEROS_KEYS_SKEWTIME
    "LogLevel"                   = $script:KERBEROS_KEYS_LOGLEVEL
    "MaxPacketSize"              = $script:KERBEROS_KEYS_MAXPACKETSIZE
    "StartupTimeInSeconds"       = $script:KERBEROS_KEYS_STARTUPTIME
    "KdcWaitTimeInSeconds"       = $script:KERBEROS_KEYS_KDCWAITTIME
    "KdcBackoffTimeInSeconds"    = $script:KERBEROS_KEYS_KDCBACKOFFTIME
    "KdcSendRetries"             = $script:KERBEROS_KEYS_KDCSENDRETRIES
    "DefaultEncryptionType"      = $script:KERBEROS_KEYS_DEFAULTENCRYPTIONTYPE
    "FarKdcTimeoutInMinutes"     = $script:KERBEROS_KEYS_FARKDCTIMEOUT
    "NearKdcTimeoutInMinutes"    = $script:KERBEROS_KEYS_NEARKDCTIMEOUT
    "StronglyEncryptDatagram"    = $script:KERBEROS_KEYS_STRONGLYENCRYPTDATAGRAM
    "MaxReferralCount"           = $script:KERBEROS_KEYS_MAXREFERRALCOUNT
    "MaxTokenSize"               = $script:KERBEROS_KEYS_MAXTOKENSIZE
    "SpnCacheTimeoutInMinutes"   = $script:KERBEROS_KEYS_SPNCACHETIMEOUT
    "S4UCacheTimeoutInMinutes"   = $script:KERBEROS_KEYS_S4UCACHETIMEOUT
    "S4UTicketLifetimeInMinutes" = $script:KERBEROS_KEYS_S4UTICKETLIFETIME
    "ShouldRetryPdc"             = $script:KERBEROS_KEYS_RETRYPDC
    "RequestOptions"             = $script:KERBEROS_KEYS_REQUESTOPTIONS
    "EnableClientIpAddresses"    = $script:KERBEROS_KEYS_CLIENTIPADDRESSES
    "TgtRenewalTimeInSeconds"    = $script:KERBEROS_KEYS_TGTRENEWALTIME
    "AllowTgtSessionKey"         = $script:KERBEROS_KEYS_ALLOWTGTSESSIONKEY
}

#endregion


