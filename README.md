# ConvertSigmaRepo2SentinelOnePQ
![banner](images/banner.png)
Scripts stolen and heavily based on [rcegan/ConvertSigmaRepo2KQL](https://github.com/rcegan/ConvertSigmaRepo2KQL), played by GitHub Actions that converts Sigma rules to SentinelOne PowerQuery via PySigma.

## Usage

Firstly, modify the 'rules_directory' variable to reflect the location of your Sigma process creation rules. If using in CI/CD and you're cloning the Sigma repo in each time, you can leave this value as-is.

Next, modify the 'output_directory' to match whichever folder you want the rules to be dumped into. Expect over 1000+ results.

## Sigma coverage

| Datasource           | Rule type            | Platform    | 3rd level            | Status                  |
|----------------------|----------------------|-------------|----------------------|-------------------------|
| SigmaHQ              | rules-threat-hunting | cloud       | 2 folders            | ❌ Not applicable      |
| SigmaHQ              | rules-threat-hunting | linux       | file_event           | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | linux       | process_creation     | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | macos       | file_event           | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | macos       | process_creation     | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | web         | proxy_generic        | ❌ Not applicable      |
| SigmaHQ              | rules-threat-hunting | windows     | builtin              | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | windows     | create_remote_threat | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | windows     | file                 | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | windows     | image_load           | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | windows     | network_connection   | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | windows     | pipe_created         | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | windows     | powershell           | ⚠️ Will be implemented |
| SigmaHQ              | rules-threat-hunting | windows     | process_access       | ✅ Implemented         |
| SigmaHQ              | rules-threat-hunting | windows     | process_creation     | ✅ Implemented         |
| SigmaHQ              | rules-threat-hunting | windows     | registry             | ⚠️ Will be implemented |
| SigmaHQ              | rules                | application | 10 folders           | ❌ Not applicable      |
| SigmaHQ              | rules                | category    | 2 folders            | ❌ Not applicable      |
| SigmaHQ              | rules                | cloud       | 9 folders            | ❌ Not applicable      |
| SigmaHQ              | rules                | compliance  | N/A                  | ❌ Not applicable      |
| SigmaHQ              | rules                | linux       | auditd               | ⚠️ Will be implemented |
| SigmaHQ              | rules                | linux       | builtin              | ⚠️ Will be implemented |
| SigmaHQ              | rules                | linux       | file_event           | ⚠️ Will be implemented |
| SigmaHQ              | rules                | linux       | network_connection   | ⚠️ Will be implemented |
| SigmaHQ              | rules                | linux       | process_creation     | ✅ Implemented         |
| SigmaHQ              | rules                | macos       | file_event           | ✅ Implemented         |
| SigmaHQ              | rules                | macos       | process_creation     | ✅ Implemented         |
| SigmaHQ              | rules                | network     | cisco                | ❌ Not applicable      |
| SigmaHQ              | rules                | network     | dns                  | ⚠️ Will be implemented |
| SigmaHQ              | rules                | network     | firewall             | ⚠️ Will be implemented |
| SigmaHQ              | rules                | network     | huawei               | ❌ Not applicable      |
| SigmaHQ              | rules                | network     | juniper              | ❌ Not applicable      |
| SigmaHQ              | rules                | network     | zeek                 | ❌ Not applicable      |
| SigmaHQ              | rules                | web         | 3 folders            | ❌ Not applicable      |
| SigmaHQ              | rules                | windows     | builtin              | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | create_remote_threat | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | dns_query            | ✅ Implemented         |
| SigmaHQ              | rules                | windows     | driver_load          | ❌ Not applicable      |
| SigmaHQ              | rules                | windows     | file                 | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | image_load           | ✅ Implemented         |
| SigmaHQ              | rules                | windows     | network_connection   | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | pipe_created         | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | powershell           | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | process_access       | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | process_creation     | ✅ Implemented         |
| SigmaHQ              | rules                | windows     | process_tampering    | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | raw_access_thread    | ⚠️ Will be implemented |
| SigmaHQ              | rules                | windows     | registry             | ✅ Implemented         |
| SigmaHQ              | rules                | windows     | sysmon               | ❌ Not applicable      |
| SigmaHQ              | rules                | windows     | wmi_event            | ❌ Not applicable      |


## GitHub Workflows status
| Category             | Operating System | Destination Folder                                 | Last GitHub Actions execution status                                                                                                                                                                                                                                                                                                                                                                            |
|----------------------|------------------|----------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SigmaHQ              | rules-threat-hunting | Windows          | S1PQ - Threat Hunting - Windows - Process Creation | [![Transform "sigma/rules-threat-hunting/windows/process_creation/" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-threathunting-windows-process_create-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-threathunting-windows-process_create-markdown.yml) |
| SigmaHQ              | rules                | Linux            | S1PQ - Linux - Network Connection                  | [![Transform "sigma/rules/linux/network_connection/" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma_to_s1pq_converter-rules-linux-network_connection-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma_to_s1pq_converter-rules-linux-network_connection-markdown.yml)                            |
| SigmaHQ              | rules                | Linux            | S1PQ - Linux - Process Creation                    | [![Transform "sigma/rules/linux/process_creation/" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-linux-process_creation-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-linux-process_creation-markdown.yml)                                            |
| SigmaHQ              | rules                | MacOS            | S1PQ - MacOS - File Event                          | [![Transform "sigma/rules/macos/file_event" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-macos-file_event-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-macos-file_event-markdown.yml)                                                              |
| SigmaHQ              | rules                | MacOS            | S1PQ - MacOS - Process Creation                    | [![Transform "sigma/rules/macos/process_creation" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-macos-process_creation-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-macos-process_creation-markdown.yml)                                            |
| SigmaHQ              | rules                | Windows          | S1PQ - Windows - DNS Query                         | [![Transform "sigma/rules/windows/dns_query/" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-dns_query-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-dns_query-markdown.yml)                                                      |
| SigmaHQ              | rules                | Windows          | S1PQ - Windows - Image Load                        | [![Transform "sigma/rules/windows/image_load/" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-image_load-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-image_load-markdown.yml)                                                    |
| SigmaHQ              | rules                | Windows          | S1PQ - Windows - Process Creation                  | [![Transform "sigma/rules/windows/process_creation/" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-process_creation-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-process_creation-markdown.yml)                                        |
| SigmaHQ              | rules                | Windows          | S1PQ - Windows - Registry                          | [![Transform "sigma/rules/windows/registry/" Sigma rules to S1PQ](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-registry-markdown.yml/badge.svg)](https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/actions/workflows/sigma-to-s1pq-converter-windows-registry-markdown.yml)                                                                |

## Example
For GitHub Workflow, you can find an example of workflow here: [Example Workflow.md](Example Workflow.md)

To see what result [sigma-to-s1pq-converter-win_process_creation_markdown.py](sigma-to-s1pq-converter-win_process_creation_markdown.py) is generating, please look at [SentinelOne_PQ - Windows Process Creation/proc_creation_win_addinutil_uncommon_child_process.md](SentinelOne_PQ - Windows Process Creation/proc_creation_win_addinutil_uncommon_child_process.md)
![image](https://github.com/user-attachments/assets/ca6af8ff-f15b-4142-a0e4-17e72bb619b4)

## Dependencies
### sigma-to-s1pq-converter-win_process_creation_markdown.py

1. Python Environment: Ensure you have Python installed on your system. You can download it from python.org.

2. Required Libraries:
        **os**: This is a standard library in Python, so no additional installation is needed.
        **datetime**: Also a standard library in Python.
        **sigma.rule**: This is part of the Sigma project. You need to install the Sigma library.
        **sigma.backends.sentinelone_pq**: This is a specific backend for Sigma, so you need to install the Sigma backends.

   You can install the Sigma library and its backends using pip:

    ```python
    pip install sigma
    pip install sigma-backends
    ```

3. Sigma Rules Directory: Ensure you have a directory containing Sigma rule files in YAML format. The script expects these files to be located in sigma/rules/windows/process_creation/.

4. Output Directory: The script creates an output directory named SentinelOne_PQ - Windows Process Creation if it doesn’t already exist. Ensure you have the necessary permissions to create directories and write files in the specified location.

5. File Handling: The script reads and writes files, so make sure the paths specified in rules_directory and output_directory are correct and accessible.

6. Error Handling: The script includes basic error handling to catch exceptions during file processing. Ensure you have proper error logging or handling mechanisms in place if you plan to run this script in a production environment.

### .github/workflows/sigma-to-s1pq-converter-win_process_creation_markdown.yml

1. GitHub Account: Ensure you have a GitHub account and a repository where you can add this workflow.

2. GitHub Actions: Enable GitHub Actions in your repository settings.

3. Python Environment:
        The workflow sets up Python 3.10 using the actions/setup-python action.
        Ensure your script (sigma-to-s1pq-converter-win_process_creation_markdown.py) is compatible with Python 3.10.

4. Required Libraries:

      **sigma-cli**: This is installed using pip install sigma-cli.

      **sigma-cli pipelines**: Installed using sigma plugin install sentinelone-pq.

5. Sigma Repository: The workflow clones the Sigma repository from GitHub. Ensure you have internet access to clone the repository.

6. Permissions: The workflow requires write permissions to the repository contents to commit and push changes.

7. Cron Schedule: The workflow is scheduled to run daily at midnight. Ensure the cron syntax ("0 0 * * *") is correct for your desired schedule.

8. Directory Structure:
        The workflow creates a directory named S1PQ - Windows Process Creation in the GitHub workspace.
        Ensure your script handles paths correctly and writes output to this directory.

9. GitHub Actions:
   - actions/checkout@v4.2.0: Used to check out the repository code.
   - actions/setup-python@v4.7.1: Used to set up the Python environment.
   - stefanzweifel/git-auto-commit-action@v5: Used to commit and push changes automatically.

10. Script Execution: Ensure your script (sigma-to-s1pq-converter-win_process_creation_markdown.py) is present in the repository and executable.


## Thanks
Many thanks to:
- [@SigmaHQ](https://github.com/SigmaHQ) for
    - [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
    - [pySigma](https://github.com/SigmaHQ/pySigma)
    - [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
- [@rcegan](https://github.com/rcegan) for [rcegan/ConvertSigmaRepo2KQL](https://github.com/rcegan/ConvertSigmaRepo2KQL)
- [@7RedViolin](https://github.com/7RedViolin) for [7RedViolin/pySigma-backend-sentinelone-pq)](https://github.com/7RedViolin/pySigma-backend-sentinelone-pq)
