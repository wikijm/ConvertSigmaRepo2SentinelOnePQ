import os
import argparse

def split_sigma_rules(input_file, output_folder):
    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Read the input file
    with open(input_file, 'r') as file:
        lines = file.readlines()

    # Remove lines containing '---'
    filtered_lines = [line for line in lines if '---' not in line]

    # Split the file into individual sigma rules
    rule_content = []
    rule_name = None

    for line in filtered_lines:
        if line.startswith('title: '):
            if rule_name and rule_content:
                # Save the previous rule to a file
                rule_filename = rule_name.lower().replace(' ', '_') + '.yml'
                rule_filepath = os.path.join(output_folder, rule_filename)
                with open(rule_filepath, 'w') as rule_file:
                    rule_file.writelines(rule_content)
            
            # Start a new rule
            rule_name = line[len('title: '):].strip()
            rule_content = [line]
        else:
            rule_content.append(line)

    # Save the last rule to a file
    if rule_name and rule_content:
        rule_filename = rule_name.lower().replace(' ', '_') + '.yml'
        rule_filepath = os.path.join(output_folder, rule_filename)
        with open(rule_filepath, 'w') as rule_file:
            rule_file.writelines(rule_content)

    print(f"File '{input_file}' split into individual sigma rules successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split Sigma rules from a YAML file.")
    parser.add_argument("--input_file", required=True, help="Path to the input YAML file.")
    parser.add_argument("--output_folder", required=True, help="Path to the output folder.")

    args = parser.parse_args()

    split_sigma_rules(args.input_file, args.output_folder)
