import os
import datetime
from sigma.rule import SigmaRule
from sigma.backends.sentinelone_pq import SentinelOnePQBackend

# Put in the directory containing all the sigma rules
rules_directory = 'sigma/rules/windows/dns_query/'

# Create a folder to store all the translated .md files, if it does not exist already
output_directory = 'SentinelOne_PQ - Windows - DNS Query'
os.makedirs(output_directory, exist_ok=True)

# List all .yml files in the specified directory
yaml_files = [f for f in os.listdir(rules_directory) if f.endswith('.yml')]

# Initialize the SentinelOnePQBackend instance outside the loop for efficiency
s1pqdef_backend = SentinelOnePQBackend()

# Get the current date and time
current_datetime = datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S')

# Loop through each .yml file and process the rules
for yaml_file in yaml_files:
    with open(os.path.join(rules_directory, yaml_file), 'r') as file:
        try:
            # Read the YAML content and create a SigmaRule object
            sigma_rule_orig = SigmaRule.from_yaml(file.read())

            # Translate the rule using SentinelOnePQBackend
            translated_content = f"// Translated content (automatically translated on {current_datetime}):\n"
            translated_content += s1pqdef_backend.convert_rule(sigma_rule_orig)[0]

            # Create a unique file name with .md extension based on the original .yml file name
            md_file_name = os.path.splitext(yaml_file)[0] + '.md'

            # Write the translated content in a Markdown file with SentinelOne PowerQuery section in a code block
            with open(os.path.join(output_directory, md_file_name), 'w') as md_file:
                md_file.write('```sql\n')
                md_file.write(translated_content)
                md_file.write('\n```\n')

                # Append the original content below the translated content with the entire Sigma rule pre-translation. Also includes a nice heading
                md_file.write('\n\n# Original Sigma Rule:\n')
                file.seek(0)
                md_file.write('```yaml\n')
                md_file.write(file.read())
                md_file.write('```\n')

            print(f"Translated rule with original content written to {os.path.join(output_directory, md_file_name)}")
        except Exception as exc:
            print(f"Error occurred while processing {yaml_file}: {exc}")
            continue
