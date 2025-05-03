import os
import argparse

def main(rules_directory, output_directory):
    """
    For each .yml or .yaml file in the specified folder (rules_directory),
    insert 'title: <value>' immediately after any line beginning with 'Name: '.
    Then write the modified content to files in output_directory.
    """
    os.makedirs(output_directory, exist_ok=True)
    for filename in os.listdir(rules_directory):
        if filename.lower().endswith(('.yml', '.yaml')):
            in_filepath = os.path.join(rules_directory, filename)
            out_filepath = os.path.join(output_directory, filename)

            with open(in_filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            updated_lines = []
            for line in lines:
                updated_lines.append(line)
                if line.startswith("Name: "):
                    # Extract the value part of "Name: <value>"
                    name_value = line.split("Name: ", 1)[1].strip()
                    # Insert new line with 'title:' + name_value
                    updated_lines.append(f"title: {name_value}\n")

            with open(out_filepath, 'w', encoding='utf-8') as f:
                f.writelines(updated_lines)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Insert 'title: <value>' after each 'Name:' line in .yml/.yaml files, then write them to an output folder."
    )
    parser.add_argument("rules_directory", type=str, help="Path to the folder containing .yml or .yaml files.")
    parser.add_argument("output_directory", type=str, help="Path to the folder where modified files will be stored.")
    args = parser.parse_args()
    main(args.rules_directory, args.output_directory)