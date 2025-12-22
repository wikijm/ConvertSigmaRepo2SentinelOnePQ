```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "wmic" and tgt.process.cmdline contains "product where " and tgt.process.cmdline contains "call" and tgt.process.cmdline contains "uninstall" and tgt.process.cmdline contains "/nointeractive") or ((tgt.process.cmdline contains "wmic" and tgt.process.cmdline contains "caption like ") and (tgt.process.cmdline contains "call delete" or tgt.process.cmdline contains "call terminate")) or (tgt.process.cmdline contains "process " and tgt.process.cmdline contains "where " and tgt.process.cmdline contains "delete")) and (tgt.process.cmdline contains "%carbon%" or tgt.process.cmdline contains "%cylance%" or tgt.process.cmdline contains "%endpoint%" or tgt.process.cmdline contains "%eset%" or tgt.process.cmdline contains "%malware%" or tgt.process.cmdline contains "%Sophos%" or tgt.process.cmdline contains "%symantec%" or tgt.process.cmdline contains "Antivirus" or tgt.process.cmdline contains "AVG " or tgt.process.cmdline contains "Carbon Black" or tgt.process.cmdline contains "CarbonBlack" or tgt.process.cmdline contains "Cb Defense Sensor 64-bit" or tgt.process.cmdline contains "Crowdstrike Sensor" or tgt.process.cmdline contains "Cylance " or tgt.process.cmdline contains "Dell Threat Defense" or tgt.process.cmdline contains "DLP Endpoint" or tgt.process.cmdline contains "Endpoint Detection" or tgt.process.cmdline contains "Endpoint Protection" or tgt.process.cmdline contains "Endpoint Security" or tgt.process.cmdline contains "Endpoint Sensor" or tgt.process.cmdline contains "ESET File Security" or tgt.process.cmdline contains "LogRhythm System Monitor Service" or tgt.process.cmdline contains "Malwarebytes" or tgt.process.cmdline contains "McAfee Agent" or tgt.process.cmdline contains "Microsoft Security Client" or tgt.process.cmdline contains "Sophos Anti-Virus" or tgt.process.cmdline contains "Sophos AutoUpdate" or tgt.process.cmdline contains "Sophos Credential Store" or tgt.process.cmdline contains "Sophos Management Console" or tgt.process.cmdline contains "Sophos Management Database" or tgt.process.cmdline contains "Sophos Management Server" or tgt.process.cmdline contains "Sophos Remote Management System" or tgt.process.cmdline contains "Sophos Update Manager" or tgt.process.cmdline contains "Threat Protection" or tgt.process.cmdline contains "VirusScan" or tgt.process.cmdline contains "Webroot SecureAnywhere" or tgt.process.cmdline contains "Windows Defender")))
```


# Original Sigma Rule:
```yaml
title: Potential Tampering With Security Products Via WMIC
id: 847d5ff3-8a31-4737-a970-aeae8fe21765
related:
    - id: b53317a0-8acf-4fd1-8de8-a5401e776b96 # Generic Uninstall
      type: derived
status: test
description: Detects uninstallation or termination of security products using the WMIC utility
references:
    - https://twitter.com/cglyer/status/1355171195654709249
    - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
    - https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions
    - https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/
    - https://www.trendmicro.com/en_us/research/23/a/vice-society-ransomware-group-targets-manufacturing-companies.html
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021-01-30
modified: 2023-02-14
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_cli_1:
        CommandLine|contains|all:
            - 'wmic'
            - 'product where '
            - 'call'
            - 'uninstall'
            - '/nointeractive'
    selection_cli_2:
        CommandLine|contains|all:
            - 'wmic'
            - 'caption like '
        CommandLine|contains:
            - 'call delete'
            - 'call terminate'
    selection_cli_3:
        CommandLine|contains|all:
            - 'process '
            - 'where '
            - 'delete'
    selection_product:
        CommandLine|contains:
            - '%carbon%'
            - '%cylance%'
            - '%endpoint%'
            - '%eset%'
            - '%malware%'
            - '%Sophos%'
            - '%symantec%'
            - 'Antivirus'
            - 'AVG '
            - 'Carbon Black'
            - 'CarbonBlack'
            - 'Cb Defense Sensor 64-bit'
            - 'Crowdstrike Sensor'
            - 'Cylance '
            - 'Dell Threat Defense'
            - 'DLP Endpoint'
            - 'Endpoint Detection'
            - 'Endpoint Protection'
            - 'Endpoint Security'
            - 'Endpoint Sensor'
            - 'ESET File Security'
            - 'LogRhythm System Monitor Service'
            - 'Malwarebytes'
            - 'McAfee Agent'
            - 'Microsoft Security Client'
            - 'Sophos Anti-Virus'
            - 'Sophos AutoUpdate'
            - 'Sophos Credential Store'
            - 'Sophos Management Console'
            - 'Sophos Management Database'
            - 'Sophos Management Server'
            - 'Sophos Remote Management System'
            - 'Sophos Update Manager'
            - 'Threat Protection'
            - 'VirusScan'
            - 'Webroot SecureAnywhere'
            - 'Windows Defender'
    condition: 1 of selection_cli_* and selection_product
falsepositives:
    - Legitimate administration
level: high
```
