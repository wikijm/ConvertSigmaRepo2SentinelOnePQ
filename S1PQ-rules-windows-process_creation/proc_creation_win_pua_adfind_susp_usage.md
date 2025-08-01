```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "domainlist" or tgt.process.cmdline contains "trustdmp" or tgt.process.cmdline contains "dcmodes" or tgt.process.cmdline contains "adinfo" or tgt.process.cmdline contains " dclist " or tgt.process.cmdline contains "computer_pwdnotreqd" or tgt.process.cmdline contains "objectcategory=" or tgt.process.cmdline contains "-subnets -f" or tgt.process.cmdline contains "name=\"Domain Admins\"" or tgt.process.cmdline contains "-sc u:" or tgt.process.cmdline contains "domainncs" or tgt.process.cmdline contains "dompol" or tgt.process.cmdline contains " oudmp " or tgt.process.cmdline contains "subnetdmp" or tgt.process.cmdline contains "gpodmp" or tgt.process.cmdline contains "fspdmp" or tgt.process.cmdline contains "users_noexpire" or tgt.process.cmdline contains "computers_active" or tgt.process.cmdline contains "computers_pwdnotreqd"))
```


# Original Sigma Rule:
```yaml
title: PUA - AdFind Suspicious Execution
id: 9a132afa-654e-11eb-ae93-0242ac130002
related:
    - id: 455b9d50-15a1-4b99-853f-8d37655a4c1b
      type: similar
    - id: 75df3b17-8bcc-4565-b89b-c9898acef911
      type: obsolete
status: test
description: Detects AdFind execution with common flags seen used during attacks
references:
    - https://www.joeware.net/freetools/tools/adfind/
    - https://thedfirreport.com/2020/05/08/adfind-recon/
    - https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
    - https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
    - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
    - https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/bf62ece1c679b07b5fb49c4bae947fe24c81811f/fin6/Emulation_Plan/Phase1.md
    - https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1087.002/T1087.002.md#atomic-test-7---adfind---enumerate-active-directory-user-objects
author: Janantha Marasinghe (https://github.com/blueteam0ps), FPT.EagleEye Team, omkar72, oscd.community
date: 2021-02-02
modified: 2023-03-05
tags:
    - attack.discovery
    - attack.t1018
    - attack.t1087.002
    - attack.t1482
    - attack.t1069.002
    - stp.1u
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'domainlist'
            - 'trustdmp'
            - 'dcmodes'
            - 'adinfo'
            - ' dclist '
            - 'computer_pwdnotreqd'
            - 'objectcategory='
            - '-subnets -f'
            - 'name="Domain Admins"'
            - '-sc u:'
            - 'domainncs'
            - 'dompol'
            - ' oudmp '
            - 'subnetdmp'
            - 'gpodmp'
            - 'fspdmp'
            - 'users_noexpire'
            - 'computers_active'
            - 'computers_pwdnotreqd'
    condition: selection
falsepositives:
    - Legitimate admin activity
level: high
```
