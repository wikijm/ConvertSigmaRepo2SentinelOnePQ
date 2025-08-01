```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\System\CurrentControlSet\Services\" and tgt.process.cmdline contains "\NetworkProvider"))
```


# Original Sigma Rule:
```yaml
title: Potential Credential Dumping Attempt Using New NetworkProvider - CLI
id: baef1ec6-2ca9-47a3-97cc-4cf2bda10b77
related:
    - id: 0442defa-b4a2-41c9-ae2c-ea7042fc4701
      type: similar
status: test
description: Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it
references:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/network-provider-settings-removed-in-place-upgrade
    - https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-23
modified: 2023-02-02
tags:
    - attack.credential-access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\System\CurrentControlSet\Services\'
            - '\NetworkProvider'
    # filter:
    #     CommandLine|contains:
    #         - '\System\CurrentControlSet\Services\WebClient\NetworkProvider'
    #         - '\System\CurrentControlSet\Services\LanmanWorkstation\NetworkProvider'
    #         - '\System\CurrentControlSet\Services\RDPNP\NetworkProvider'
    #         - '\System\CurrentControlSet\Services\P9NP\NetworkProvider' # Related to WSL remove the comment if you use WSL in your ENV
    condition: selection
falsepositives:
    - Other legitimate network providers used and not filtred in this rule
level: high
```
