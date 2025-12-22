```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\sqlcmd.exe" and (tgt.process.cmdline contains "SELECT" and tgt.process.cmdline contains "TOP" and tgt.process.cmdline contains "[VeeamBackup].[dbo].[Credentials]")))
```


# Original Sigma Rule:
```yaml
title: VeeamBackup Database Credentials Dump Via Sqlcmd.EXE
id: b57ba453-b384-4ab9-9f40-1038086b4e53
status: test
description: Detects dump of credentials in VeeamBackup dbo
references:
    - https://thedfirreport.com/2021/12/13/diavol-ransomware/
    - https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.html
author: frack113
date: 2021-12-20
modified: 2023-02-13
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith: '\sqlcmd.exe'
    selection_query:
        CommandLine|contains|all:
            - 'SELECT'
            - 'TOP'
            - '[VeeamBackup].[dbo].[Credentials]'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
