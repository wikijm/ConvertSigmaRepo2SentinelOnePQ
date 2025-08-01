```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.image.path contains "/userdel")
```


# Original Sigma Rule:
```yaml
title: User Has Been Deleted Via Userdel
id: 08f26069-6f80-474b-8d1f-d971c6fedea0
status: test
description: Detects execution of the "userdel" binary. Which is used to delete a user account and related files. This is sometimes abused by threat actors in order to cover their tracks
references:
    - https://linuxize.com/post/how-to-delete-group-in-linux/
    - https://www.cyberciti.biz/faq/linux-remove-user-command/
    - https://www.cybrary.it/blog/0p3n/linux-commands-used-attackers/
    - https://linux.die.net/man/8/userdel
author: Tuan Le (NCSGroup)
date: 2022-12-26
tags:
    - attack.impact
    - attack.t1531
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/userdel'
    condition: selection
falsepositives:
    - Legitimate administrator activities
level: medium
```
