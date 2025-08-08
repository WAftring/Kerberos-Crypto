# PSKerb

This PowerShell module is intended to make interfacing with Windows Kerberos simpler.

## Install

### New

This module can be downloaded using the follwing cmdlet in PowerShell. The module is downloaded from the [PSGallery](https://www.powershellgallery.com/packages/PSKerb/)

```powershell
Install-Module -Name PSKerb
```

### Updating

The Update-Module cmdlet can be used to install newer versions of the module if already installed.

```powershell
Update-Module PSKerb
```

## Usage

### Get-KerbConfig

Display the current Microsoft Windows Kerberos client configuration.

```powershell
Name                     Setting
----                     -------
SupportedEncryptionTypes RC4, AES128-SHA96, AES256-SHA96
SkewTime                 5 minutes
LogLevel                 0
MaxPacketSize            1465 bytes
StartupTime              120 seconds
KdcWaitTime              10 seconds
KdcBackoffTime           10 seconds
KdcSendRetries           3
DefaultEncryptionType    AES256-SHA96
FarKdcTimeout            10 minutes
NearKdcTimeout           30 minutes
StronglyEncryptDatagram  1
MaxReferralCount         6
MaxTokenSize             48000
SpnCacheTimeout          15 minutes
S4UCacheTimeout          15 minutes
S4UTicketLifetime        15 minutes
RetryPdc                 False
RequestOptions           0x10000
ClientIpAddresses        False
TgtRenewalTime           600 seconds
AllowTgtSessionKey       False
```