```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "lockoutduration" or tgt.process.cmdline contains "lockoutthreshold" or tgt.process.cmdline contains "lockoutobservationwindow" or tgt.process.cmdline contains "maxpwdage" or tgt.process.cmdline contains "minpwdage" or tgt.process.cmdline contains "minpwdlength" or tgt.process.cmdline contains "pwdhistorylength" or tgt.process.cmdline contains "pwdproperties") or tgt.process.cmdline contains "-sc admincountdmp" or tgt.process.cmdline contains "-sc exchaddresses"))
```


# Original Sigma Rule:
```yaml
title: PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE
id: 455b9d50-15a1-4b99-853f-8d37655a4c1b
related:
    - id: 9a132afa-654e-11eb-ae93-0242ac130002
      type: similar
    - id: 514e7e3e-b3b4-4a67-af60-be20f139198b
      type: similar
status: test
description: Detects active directory enumeration activity using known AdFind CLI flags
references:
    - https://www.joeware.net/freetools/tools/adfind/
    - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.002/T1087.002.md
author: frack113
date: 2021-12-13
modified: 2023-03-05
tags:
    - attack.discovery
    - attack.t1087.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_password: # Listing password policy
        CommandLine|contains:
            - lockoutduration
            - lockoutthreshold
            - lockoutobservationwindow
            - maxpwdage
            - minpwdage
            - minpwdlength
            - pwdhistorylength
            - pwdproperties
    selection_enum_ad: # Enumerate Active Directory Admins
        CommandLine|contains: '-sc admincountdmp'
    selection_enum_exchange: # Enumerate Active Directory Exchange AD Objects
        CommandLine|contains: '-sc exchaddresses'
    condition: 1 of selection_*
falsepositives:
    - Authorized administrative activity
level: high
```
