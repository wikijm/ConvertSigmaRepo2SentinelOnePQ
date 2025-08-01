```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\System\CurrentControlSet\Control\Lsa\" and tgt.process.cmdline contains "DisableRestrictedAdmin"))
```


# Original Sigma Rule:
```yaml
title: RestrictedAdminMode Registry Value Tampering - ProcCreation
id: 28ac00d6-22d9-4a3c-927f-bbd770104573
related:
    - id: d6ce7ebd-260b-4323-9768-a9631c8d4db2 # Registry
      type: similar
status: test
description: |
    Detects changes to the "DisableRestrictedAdmin" registry value in order to disable or enable RestrictedAdmin mode.
    RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system to which you connect using Remote Desktop.
    This prevents your credentials from being harvested during the initial connection process if the remote server has been compromise
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/a8e3cf63e97b973a25903d3df9fd55da6252e564/atomics/T1112/T1112.md
    - https://social.technet.microsoft.com/wiki/contents/articles/32905.remote-desktop-services-enable-restricted-admin-mode.aspx
    - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
author: frack113
date: 2023-01-13
modified: 2023-12-15
tags:
    - attack.defense-evasion
    - attack.t1112
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - '\System\CurrentControlSet\Control\Lsa\'
            - 'DisableRestrictedAdmin'
    condition: selection
falsepositives:
    - Unknown
level: high
```
