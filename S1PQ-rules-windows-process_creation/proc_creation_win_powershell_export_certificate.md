```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Export-PfxCertificate " or tgt.process.cmdline contains "Export-Certificate "))
```


# Original Sigma Rule:
```yaml
title: Certificate Exported Via PowerShell
id: 9e716b33-63b2-46da-86a4-bd3c3b9b5dfb
related:
    - id: aa7a3fce-bef5-4311-9cc1-5f04bb8c308c
      type: similar
status: test
description: Detects calls to cmdlets that are used to export certificates from the local certificate store. Threat actors were seen abusing this to steal private keys from compromised machines.
references:
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-112a
    - https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate?view=windowsserver2022-ps
    - https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-18
tags:
    - attack.credential-access
    - attack.execution
    - attack.t1552.004
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Export-PfxCertificate '
            - 'Export-Certificate '
    condition: selection
falsepositives:
    - Legitimate certificate exports by administrators. Additional filters might be required.
level: medium
```
