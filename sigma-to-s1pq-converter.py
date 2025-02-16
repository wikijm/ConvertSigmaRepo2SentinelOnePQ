import os
import datetime
import argparse
from sigma.rule import SigmaRule
from sigma.backends.sentinelone_pq import SentinelOnePQBackend

def main(rules_directory, output_directory):
    """
    Convert all Sigma .yml files from `rules_directory` into SentinelOne PowerQuery
    format, then write each translated rule + original YAML content to `output_directory`.
    """
    os.makedirs(output_directory, exist_ok=True)
    yaml_files = [f for f in os.listdir(rules_directory) if f.endswith('.yml')]
    s1pqdef_backend = SentinelOnePQBackend()
    current_datetime = datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    processed_count = 0

    for yaml_file in yaml_files:
        file_path = os.path.join(rules_directory, yaml_file)
        try:
            with open(file_path, 'r') as file:
                sigma_rule_orig = SigmaRule.from_yaml(file.read())
                translated_content = (
                    f"// Translated content (automatically translated on {current_datetime}):\n"
                    + s1pqdef_backend.convert_rule(sigma_rule_orig)[0]
                )

            md_file_name = os.path.splitext(yaml_file)[0] + '.md'
            out_path = os.path.join(output_directory, md_file_name)
            with open(out_path, 'w') as md_file:
                md_file.write('```sql\n')
                md_file.write(translated_content)
                md_file.write('\n```\n')
                md_file.write('\n\n# Original Sigma Rule:\n')
            # Reopen the YAML file to attach original content
            with open(file_path, 'r') as file:
                with open(out_path, 'a') as md_file:
                    md_file.write('```yaml\n')
                    md_file.write(file.read())
                    md_file.write('```\n')

            processed_count += 1
            print(f"Translated: {yaml_file}")
        except Exception as exc:
            print(f"Error processing {yaml_file}: {exc}")

    print(f"Completed! Processed {processed_count} file(s).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert Sigma rules to SentinelOne PowerQuery format.')
    parser.add_argument('rules_directory', type=str, help='Directory containing Sigma rules in .yml format')
    parser.add_argument('output_directory', type=str, help='Directory to store the translated .md files')
    args = parser.parse_args()
    main(args.rules_directory, args.output_directory)