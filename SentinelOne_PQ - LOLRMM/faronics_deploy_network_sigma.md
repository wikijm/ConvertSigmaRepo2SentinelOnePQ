```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "deploy.faronics.com" or url.address contains "www.faronicsdeploy.com" or url.address contains "faronicscloud.com" or url.address contains "nv0mddxkh7.execute-api.us-west-2.amazonaws.com" or url.address contains "29qoj3q0yf.execute-api.us-west-2.amazonaws.com" or url.address contains "8z5x4rqbxi.execute-api.eu-west-1.amazonaws.com" or url.address contains "1wuccjc4a3.execute-api.eu-west-1.amazonaws.com" or url.address contains "faronics-deploy-na-production-installers.s3.us-west-2.amazonaws.com" or url.address contains "faronics-deploy-int-production-installers.s3.eu-west-1.amazonaws.com" or url.address contains "remotepro-us-west-2.faronics.com" or url.address contains "remotepro-us-east-1.faronics.com" or url.address contains "remotepro-ca-central-1.faronics.com" or url.address contains "remotepro-eu-west-1.faronicsdeploy.com" or url.address contains "remotepro-ap-southeast-1.faronicsdeploy.com" or url.address contains "remotepro-sa-east-1.faronicsdeploy.com" or url.address contains "faronics.com" or url.address contains "support.faronics.com" or url.address contains "docs.faronics.com" or url.address contains "upd.faronicslabs.com") or (event.dns.request contains "deploy.faronics.com" or event.dns.request contains "www.faronicsdeploy.com" or event.dns.request contains "faronicscloud.com" or event.dns.request contains "nv0mddxkh7.execute-api.us-west-2.amazonaws.com" or event.dns.request contains "29qoj3q0yf.execute-api.us-west-2.amazonaws.com" or event.dns.request contains "8z5x4rqbxi.execute-api.eu-west-1.amazonaws.com" or event.dns.request contains "1wuccjc4a3.execute-api.eu-west-1.amazonaws.com" or event.dns.request contains "faronics-deploy-na-production-installers.s3.us-west-2.amazonaws.com" or event.dns.request contains "faronics-deploy-int-production-installers.s3.eu-west-1.amazonaws.com" or event.dns.request contains "remotepro-us-west-2.faronics.com" or event.dns.request contains "remotepro-us-east-1.faronics.com" or event.dns.request contains "remotepro-ca-central-1.faronics.com" or event.dns.request contains "remotepro-eu-west-1.faronicsdeploy.com" or event.dns.request contains "remotepro-ap-southeast-1.faronicsdeploy.com" or event.dns.request contains "remotepro-sa-east-1.faronicsdeploy.com" or event.dns.request contains "faronics.com" or event.dns.request contains "support.faronics.com" or event.dns.request contains "docs.faronics.com" or event.dns.request contains "upd.faronicslabs.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Deploy RMM Tool Network Activity
id: 19ae9d5f-364f-58d2-8f33-c426e8ace0d9
status: experimental
description: |
    Detects potential network activity of Faronics Deploy RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'deploy.faronics.com'
            - 'www.faronicsdeploy.com'
            - 'faronicscloud.com'
            - 'nv0mddxkh7.execute-api.us-west-2.amazonaws.com'
            - '29qoj3q0yf.execute-api.us-west-2.amazonaws.com'
            - '8z5x4rqbxi.execute-api.eu-west-1.amazonaws.com'
            - '1wuccjc4a3.execute-api.eu-west-1.amazonaws.com'
            - 'faronics-deploy-na-production-installers.s3.us-west-2.amazonaws.com'
            - 'faronics-deploy-int-production-installers.s3.eu-west-1.amazonaws.com'
            - 'remotepro-us-west-2.faronics.com'
            - 'remotepro-us-east-1.faronics.com'
            - 'remotepro-ca-central-1.faronics.com'
            - 'remotepro-eu-west-1.faronicsdeploy.com'
            - 'remotepro-ap-southeast-1.faronicsdeploy.com'
            - 'remotepro-sa-east-1.faronicsdeploy.com'
            - 'faronics.com'
            - 'support.faronics.com'
            - 'docs.faronics.com'
            - 'upd.faronicslabs.com'
    condition: selection
falsepositives:
    - Legitimate use of Faronics Deploy
level: medium
```
