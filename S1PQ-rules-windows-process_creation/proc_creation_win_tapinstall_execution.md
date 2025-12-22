```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\tapinstall.exe" and (not ((tgt.process.image.path contains ":\\Program Files\\Avast Software\\SecureLine VPN\\" or tgt.process.image.path contains ":\\Program Files (x86)\\Avast Software\\SecureLine VPN\\") or tgt.process.image.path contains ":\\Program Files\\OpenVPN Connect\\drivers\\tap\\" or tgt.process.image.path contains ":\\Program Files (x86)\\Proton Technologies\\ProtonVPNTap\\installer\\"))))
```


# Original Sigma Rule:
```yaml
title: Tap Installer Execution
id: 99793437-3e16-439b-be0f-078782cf953d
status: test
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques
references:
    - https://community.openvpn.net/openvpn/wiki/ManagingWindowsTAPDrivers
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019-10-24
modified: 2023-12-11
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\tapinstall.exe'
    filter_optional_avast:
        Image|contains:
            - ':\Program Files\Avast Software\SecureLine VPN\'
            - ':\Program Files (x86)\Avast Software\SecureLine VPN\'
    filter_optional_openvpn:
        Image|contains: ':\Program Files\OpenVPN Connect\drivers\tap\'
    filter_optional_protonvpn:
        Image|contains: ':\Program Files (x86)\Proton Technologies\ProtonVPNTap\installer\'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Legitimate OpenVPN TAP installation
level: medium
```
