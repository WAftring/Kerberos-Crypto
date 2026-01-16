# Kerberos Encryption Type Detection Scripts

These scripts are intended to help detect specific Kerberos encryption type usage via the Windows [Event Id 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
and [Event Id 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769) generated on Windows Key Distribution Centers (KDCs) in the Security Event Log.

For additional information and examples please see: [Detect and remediate RC4 usage in Kerberos | Use PowerShell to audit RC4 usage](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos#use-powershell-to-audit-rc4-usage)

## Scripts:

### `List-AccountKeys.ps1`

This script queries for the events described above to determine the [long-term keys](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)?redirectedfrom=MSDN#long-term-symmetric-keys-user-system-service-and-inter-realm-keys) available for accounts.

Basic help text:

```powershell

NAME
    C:\List-AccountKeys.ps1

SYNOPSIS
    Retrieves the observed Account Key types


SYNTAX
    C:\List-AccountKeys.ps1 [[-Since] <DateTime>] [[-ContainsKeyType] <String>] [[-NotContainsKeyType] <String>] [[-SearchScope] <String>] [<CommonParameters>]


DESCRIPTION
    Searches the Security Event Logs for intstances of Event Id 4769 and Event Id 4768 to determine which account keys are used.


RELATED LINKS

REMARKS
    To see the examples, type: "Get-Help C:\List-AccountKeys.ps1 -Examples"
    For more information, type: "Get-Help C:\List-AccountKeys.ps1 -Detailed"
    For technical information, type: "Get-Help C:\List-AccountKeys.ps1 -Full"
```

Example output:

```
Time                  Name         Type  Keys
----                  ----         ----  ----
1/21/2025 2:00:10 PM  VM01$      Machine {RC4, AES128-SHA96, AES256-SHA96, AES128-SHA256...}
1/21/2025 2:00:10 PM  AdminUser     User {RC4, AES128-SHA96, AES256-SHA96, AES128-SHA256...}
1/21/2025 6:50:34 PM  VM01$      Machine {RC4, AES128-SHA96, AES256-SHA96, AES128-SHA256...}
1/21/2025 6:50:34 PM  AdminUser     User {RC4, AES128-SHA96, AES256-SHA96, AES128-SHA256...}
1/21/2025 6:50:34 PM  VM01$      Machine {RC4, AES128-SHA96, AES256-SHA96, AES128-SHA256...}
```

### `Get-KerbEncryptionUsage.ps1`

This script can be queries for the events described about to identify Kerberos encryption types in use, with filtering options for specific algorithms like RC4.

Basic help text:

```powershell❯ Get-Help .\Get-KerbEncryption.ps1
NAME
    C:\Get-KerbEncryption.ps1

SYNOPSIS
    Retrieves ticket and session key encryption types


SYNTAX
    C:\Get-KerbEncryption.ps1 [[-Encryption] <String>] [[-Since] <DateTime>] [[-SearchScope] <String>] [[-EncryptionUsage] <String>] [<CommonParameters>]


DESCRIPTION
    Searches the Security Event Log for instances of Event Id 4769 and Event Id 4768 to create a list of encryption types used in Kerberos tickets


RELATED LINKS

REMARKS
    To see the examples, type: "Get-Help C:\Get-KerbEncryption.ps1 -Examples"
    For more information, type: "Get-Help C:\Get-KerbEncryption.ps1 -Detailed"
    For technical information, type: "Get-Help C:\Get-KerbEncryption.ps1 -Full"
```

Example output:

```
Time       : 1/21/2025 2:00:10 PM
Requestor  : ::1
Source     : AdminUser@CONTOSO.COM
Target     : VM01$
Type       : TGS
Ticket     : AES256-SHA96
SessionKey : AES256-SHA96

Time       : 1/21/2025 2:00:10 PM
Requestor  : 192.168.1.1
Source     : AdminUser
Target     : krbtgt
Type       : AS
Ticket     : AES256-SHA96
SessionKey : AES256-SHA96
```
