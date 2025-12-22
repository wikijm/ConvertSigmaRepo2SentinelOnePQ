```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/jamf" and (tgt.process.cmdline contains "createAccount" or tgt.process.cmdline contains "manage" or tgt.process.cmdline contains "removeFramework" or tgt.process.cmdline contains "removeMdmProfile" or tgt.process.cmdline contains "resetPassword" or tgt.process.cmdline contains "setComputerName")))
```


# Original Sigma Rule:
```yaml
title: JAMF MDM Execution
id: be2e3a5c-9cc7-4d02-842a-68e9cb26ec49
status: test
description: |
    Detects execution of the "jamf" binary to create user accounts and run commands. For example, the binary can be abused by attackers on the system in order to bypass security controls or remove application control polices.
references:
    - https://github.com/MythicAgents/typhon/
    - https://www.zoocoup.org/casper/jamf_cheatsheet.pdf
    - https://docs.jamf.com/10.30.0/jamf-pro/administrator-guide/Components_Installed_on_Managed_Computers.html
author: Jay Pandit
date: 2023-08-22
tags:
    - attack.execution
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/jamf'
        CommandLine|contains:
            # Note: add or remove commands according to your policy
            - 'createAccount'
            - 'manage'
            - 'removeFramework'
            - 'removeMdmProfile'
            - 'resetPassword'
            - 'setComputerName'
    condition: selection
falsepositives:
    - Legitimate use of the JAMF CLI tool by IT support and administrators
level: low
```
