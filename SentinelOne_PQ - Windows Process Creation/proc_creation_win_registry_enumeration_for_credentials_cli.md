```sql
// Translated content (automatically translated on 31-01-2025 01:18:01):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\Software\SimonTatham\PuTTY\Sessions" or tgt.process.cmdline contains "\Software\SimonTatham\PuTTY\SshHostKeys\" or tgt.process.cmdline contains "\Software\Mobatek\MobaXterm\" or tgt.process.cmdline contains "\Software\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin" or tgt.process.cmdline contains "\Software\Aerofox\FoxmailPreview" or tgt.process.cmdline contains "\Software\Aerofox\Foxmail\V3.1" or tgt.process.cmdline contains "\Software\IncrediMail\Identities" or tgt.process.cmdline contains "\Software\Qualcomm\Eudora\CommandLine" or tgt.process.cmdline contains "\Software\RimArts\B2\Settings" or tgt.process.cmdline contains "\Software\OpenVPN-GUI\configs" or tgt.process.cmdline contains "\Software\Martin Prikryl\WinSCP 2\Sessions" or tgt.process.cmdline contains "\Software\FTPWare\COREFTP\Sites" or tgt.process.cmdline contains "\Software\DownloadManager\Passwords" or tgt.process.cmdline contains "\Software\OpenSSH\Agent\Keys" or tgt.process.cmdline contains "\Software\TightVNC\Server" or tgt.process.cmdline contains "\Software\ORL\WinVNC3\Password" or tgt.process.cmdline contains "\Software\RealVNC\WinVNC4"))
```


# Original Sigma Rule:
```yaml
title: Enumeration for 3rd Party Creds From CLI
id: 87a476dc-0079-4583-a985-dee7a20a03de
related:
    - id: e0b0c2ab-3d52-46d9-8cb7-049dc775fbd1
      type: derived
status: test
description: Detects processes that query known 3rd party registry keys that holds credentials via commandline
references:
    - https://isc.sans.edu/diary/More+Data+Exfiltration/25698
    - https://github.com/synacktiv/Radmin3-Password-Cracker/blob/acfc87393e4b7c06353973a14a6c7126a51f36ac/regkey.txt
    - https://github.com/HyperSine/how-does-MobaXterm-encrypt-password
    - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#inside-the-registry
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-20
tags:
    - attack.credential-access
    - attack.t1552.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: # Add more paths as they are discovered
            - '\Software\SimonTatham\PuTTY\Sessions'
            - '\Software\\SimonTatham\PuTTY\SshHostKeys\'
            - '\Software\Mobatek\MobaXterm\'
            - '\Software\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin'
            - '\Software\Aerofox\FoxmailPreview'
            - '\Software\Aerofox\Foxmail\V3.1'
            - '\Software\IncrediMail\Identities'
            - '\Software\Qualcomm\Eudora\CommandLine'
            - '\Software\RimArts\B2\Settings'
            - '\Software\OpenVPN-GUI\configs'
            - '\Software\Martin Prikryl\WinSCP 2\Sessions'
            - '\Software\FTPWare\COREFTP\Sites'
            - '\Software\DownloadManager\Passwords'
            - '\Software\OpenSSH\Agent\Keys'
            - '\Software\TightVNC\Server'
            - '\Software\ORL\WinVNC3\Password'
            - '\Software\RealVNC\WinVNC4'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
