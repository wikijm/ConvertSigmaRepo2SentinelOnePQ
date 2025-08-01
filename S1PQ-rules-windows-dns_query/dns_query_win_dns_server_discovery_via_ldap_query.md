```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and (event.dns.request contains "_ldap." and (not ((src.process.image.path contains ":\Program Files\" or src.process.image.path contains ":\Program Files (x86)\" or src.process.image.path contains ":\Windows\") or (src.process.image.path contains ":\ProgramData\Microsoft\Windows Defender\Platform\" and src.process.image.path contains "\MsMpEng.exe") or src.process.image.path="<unknown process>" or not (src.process.image.path matches "\.*"))) and (not (src.process.image.path contains "C:\WindowsAzure\GuestAgent" or (src.process.image.path contains "\chrome.exe" or src.process.image.path contains "\firefox.exe" or src.process.image.path contains "\opera.exe")))))
```


# Original Sigma Rule:
```yaml
title: DNS Server Discovery Via LDAP Query
id: a21bcd7e-38ec-49ad-b69a-9ea17e69509e
status: test
description: Detects DNS server discovery via LDAP query requests from uncommon applications
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/980f3f83fd81f37c1ca9c02dccfd1c3d9f9d0841/atomics/T1016/T1016.md#atomic-test-9---dns-server-discovery-using-nslookup
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04
author: frack113
date: 2022-08-20
modified: 2023-09-18
tags:
    - attack.discovery
    - attack.t1482
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|startswith: '_ldap.'
    filter_main_generic:
        Image|contains:
            - ':\Program Files\'
            - ':\Program Files (x86)\'
            - ':\Windows\'
    filter_main_defender:
        Image|contains: ':\ProgramData\Microsoft\Windows Defender\Platform\'
        Image|endswith: '\MsMpEng.exe'
    filter_main_unknown:
        Image: '<unknown process>'
    filter_optional_azure:
        Image|startswith: 'C:\WindowsAzure\GuestAgent'
    filter_main_null:
        Image: null
    filter_optional_browsers:
        # Note: This list is for browsers installed in the user context. To avoid basic evasions based on image name. Best to baseline this list with the browsers you use internally and add their full paths.
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\opera.exe'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Likely
# Note: Incrase the level once a baseline is established
level: low
```
