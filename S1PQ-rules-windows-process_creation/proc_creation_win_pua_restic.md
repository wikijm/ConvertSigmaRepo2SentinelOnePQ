```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "--password-file" and tgt.process.cmdline contains "init" and tgt.process.cmdline contains " -r ") or (tgt.process.cmdline contains "--use-fs-snapshot" and tgt.process.cmdline contains "backup" and tgt.process.cmdline contains " -r ")) or ((tgt.process.cmdline contains "sftp:" or tgt.process.cmdline contains "rest:http" or tgt.process.cmdline contains "s3:s3." or tgt.process.cmdline contains "s3.http" or tgt.process.cmdline contains "azure:" or tgt.process.cmdline contains " gs:" or tgt.process.cmdline contains "rclone:" or tgt.process.cmdline contains "swift:" or tgt.process.cmdline contains " b2:") and (tgt.process.cmdline contains " init " and tgt.process.cmdline contains " -r "))))
```


# Original Sigma Rule:
```yaml
title: PUA - Restic Backup Tool Execution
id: 6ddff2e8-ea1a-45d0-8938-93dfc1d67ae7
status: experimental
description: |
    Detects the execution of the Restic backup tool, which can be used for data exfiltration.
    Threat actors may leverage Restic to back up and exfiltrate sensitive data to remote storage locations, including cloud services.
    If not legitimately used in the enterprise environment, its presence may indicate malicious activity.
references:
    - https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/#exfiltration
    - https://restic.net/
    - https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html
author: Nounou Mbeiri, Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-17
tags:
    - attack.exfiltration
    - attack.t1048
    - attack.t1567.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_specific:
        - CommandLine|contains|all:
              - '--password-file'
              - 'init'
              - ' -r '
        - CommandLine|contains|all:
              - '--use-fs-snapshot'
              - 'backup'
              - ' -r '
    selection_restic:
        CommandLine|contains:
            - 'sftp:'
            - 'rest:http'
            - 's3:s3.'
            - 's3.http'
            - 'azure:'
            - ' gs:'
            - 'rclone:'
            - 'swift:'
            - ' b2:'
        CommandLine|contains|all:
            - ' init '
            - ' -r '
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Restic for backup purposes within the organization.
level: high
```
