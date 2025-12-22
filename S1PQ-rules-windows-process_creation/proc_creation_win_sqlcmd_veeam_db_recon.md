```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\sqlcmd.exe" and (tgt.process.cmdline contains "VeeamBackup" and tgt.process.cmdline contains "From ")) and (tgt.process.cmdline contains "BackupRepositories" or tgt.process.cmdline contains "Backups" or tgt.process.cmdline contains "Credentials" or tgt.process.cmdline contains "HostCreds" or tgt.process.cmdline contains "SmbFileShares" or tgt.process.cmdline contains "Ssh_creds" or tgt.process.cmdline contains "VSphereInfo")))
```


# Original Sigma Rule:
```yaml
title: Veeam Backup Database Suspicious Query
id: 696bfb54-227e-4602-ac5b-30d9d2053312
status: test
description: Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-04
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_sql:
        Image|endswith: '\sqlcmd.exe'
        CommandLine|contains|all:
            - 'VeeamBackup'
            - 'From '
    selection_db:
        CommandLine|contains:
            - 'BackupRepositories'
            - 'Backups'
            - 'Credentials'
            - 'HostCreds'
            - 'SmbFileShares'
            - 'Ssh_creds'
            - 'VSphereInfo'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
