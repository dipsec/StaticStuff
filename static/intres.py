import os
import re
import sys
import concurrent.futures
import argparse
from termcolor import colored
import subprocess

def find_model_files(directory):
    """Find files with specific model extensions."""
    find_command = (
        f'find {directory} -type f '
        f'\\( -name "*.pkl" -o -name "*.h5" -o -name "*.pt" -o -name "*.tflite" '
        f'-o -name "*.pb" -o -name "*.onnx" -o -name "*.joblib" -o -name "*.sav" -o -name "*.bin" \\)'
    )
    result = subprocess.run(find_command, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()

def find_unexpected_files(directory):
    """Find files with extensions that should not be in the source code."""
    suspicious_extensions = [
    '.db', '.txt', '.log', '.bak', '.old', '.orig', '.tmp', '.swp', '.csv', '.json', 
    '.xml', '.sql', '.ini', '.env', '.yaml', '.yml', '.conf', '.properties', '.pem', 
    '.key', '.crt', '.pfx', '.p12', '.asc', '.passwd', '.htpasswd', '.sh', '.bash', 
    '.tfstate', '.tfstate.backup', '.kube/config', '.exe', '.dll', '.so', '.dylib', 
    '.class', '.jar', '.lic', '.rst', '.swp', '.lock', '.htaccess', '.htpasswd', 
    '.plist', '.toml', '.cnf', '.cfg', '.inc', '.bat', '.cmd', '.ps1', '.apk', '.run', 
    '.vbs', '.dbf', '.rdb', '.sqlite3', '.wallet', '.jsonl', '.keychain', '.log.*', '.orig', 
    '.rej', '.patch', '.diff', '.bundle', '.der', '.cer', '.cert', '.kdb', '.kdbx', 
    '.gpg', '.sln', '.vcxproj', '.proj', '.gradle', '.pom.xml', '.ipa', '.msg', '.eml', 
    '.md', '.pdf', '.docx', '.xlsx', '.pptx'
	]
    find_command = (
        f'find {directory} -type f '
        f'\\( {" -o ".join([f"-name *{ext}" for ext in suspicious_extensions])} \\)'
    )
    result = subprocess.run(find_command, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()

def find_patterns_in_file(file_path, patterns):
    """Search for URLs, prompts, or endpoint-like patterns in a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except UnicodeDecodeError:
        # Simply skip and do nothing
        return []

    found_items = []
    for pattern in patterns:
        found_items.extend(pattern.findall(content))

    return found_items

def scan_directory_for_patterns(directory, patterns, exclude_extensions, verbose=False):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file == "package-lock.json":
                    if verbose:
                        print(f"Skipping excluded file: {file}")
                    continue
                if any(file.endswith(ext) for ext in exclude_extensions):
                    if verbose:
                        print(f"Skipping excluded file: {file}")
                    continue
                file_path = os.path.join(root, file)
                futures.append((file_path, executor.submit(find_patterns_in_file, file_path, patterns)))

        for file_path, future in futures:
            found_items = future.result()
            if found_items:
                rel_path = os.path.relpath(file_path, directory)
                print(f"\nFile: {rel_path}")
                for item in found_items:
                    print(colored(f"  {item}", 'green'))

def main():
    parser = argparse.ArgumentParser(description="Search for URLs, prompts, or endpoints within source codes inside a directory.")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--exclude-extensions", nargs='+', default=[], help="File extensions to exclude from scanning (e.g., .jpg .png .exe)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Find specific model files
    model_files = find_model_files(args.directory)
    if model_files:
        print("Model files found:")
        for model_file in model_files:
            print(colored(f"  {model_file}", 'blue'))

    # Find unexpected files
    unexpected_files = find_unexpected_files(args.directory)
    if unexpected_files:
        print("Interesting files found:")
        for unexpected_file in unexpected_files:
            print(colored(f"  {unexpected_file}", 'red'))

    patterns = [
        re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'),  # URLs
        re.compile(r'["\'](/[\w\-./]+?)[ "\']'),  # Endpoints
        re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),  # IPv4 addresses
        re.compile(r'(mongodb|postgres|mysql|redis|mssql):\/\/[^\s]+'),  # Database connection strings
        re.compile(r'{\s*"[^"]+":\s*"http[s]?://[^\s]+"'),  # JSON with URL endpoints
        re.compile(r'ws[s]?://[^\s]+'),  # WebSocket URLs
        re.compile(r'ftp[s]?://[^\s]+'),  # FTP/SFTP URLs
        re.compile(r'\.(pkl|h5|pt|tflite|pb|onnx|joblib|bin)'),  # File extensions for ML models and binaries
        re.compile(r'.{0,1}ou are.*?(?=\n|[}\]])'),  # Capture "You are" and similar phrases, cutting off at newline, } or ]
        re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email addresses
        re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH|ENCRYPTED|PRIVATE) KEY-----[\s\S]+?-----END \1 KEY-----'),  # Private keys
        re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE)\b.*\bFROM\b', re.IGNORECASE),  # SQL queries
        re.compile(r'["\'](/etc/passwd|/etc/shadow|/var/www|/usr/bin|/usr/local/bin)["\']'),  # Sensitive file paths
        re.compile(r'(os\.system|subprocess\.Popen|`|exec)\s*\(.*\)'),  # Shell commands
        re.compile(r'input type=["\']file["\']'),  # HTML file upload fields
        re.compile(r'chmod\s+777\s+[^\s]+'),  # chmod 777 command
    ]

    scan_directory_for_patterns(args.directory, patterns, args.exclude_extensions, args.verbose)

if __name__ == "__main__":
    main()
