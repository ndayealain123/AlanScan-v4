import os
import re

directories = ['scanner/web/', 'scanner/network/']
root_dir = 'D:/AlanScan/'

replacements = [
    # Severity findings
    (r'Fore\.RED \+ f"  \[CRITICAL\]', 'Fore.LIGHTRED_EX + Style.BRIGHT + f"  [CRITICAL]'),
    (r'Fore\.RED \+ "  \[CRITICAL\]', 'Fore.LIGHTRED_EX + Style.BRIGHT + "  [CRITICAL]'),
    (r'Fore\.RED \+ f"  \[HIGH\]', 'Fore.RED + Style.BRIGHT + f"  [HIGH]'),
    (r'Fore\.RED \+ "  \[HIGH\]', 'Fore.RED + Style.BRIGHT + "  [HIGH]'),
    (r'Fore\.YELLOW \+ f"  \[MEDIUM\]', 'Fore.YELLOW + Style.BRIGHT + f"  [MEDIUM]'),
    (r'Fore\.YELLOW \+ "  \[MEDIUM\]', 'Fore.YELLOW + Style.BRIGHT + "  [MEDIUM]'),
    (r'Fore\.YELLOW \+ f"  \[LOW\]', 'Fore.GREEN + Style.BRIGHT + f"  [LOW]'),
    (r'Fore\.YELLOW \+ "  \[LOW\]', 'Fore.GREEN + Style.BRIGHT + "  [LOW]'),
    (r'Fore\.BLUE \+ f"  \[LOW\]', 'Fore.GREEN + Style.BRIGHT + f"  [LOW]'),
    (r'Fore\.BLUE \+ "  \[LOW\]', 'Fore.GREEN + Style.BRIGHT + "  [LOW]'),
    (r'Fore\.BLUE \+ f"  \[INFO\]', 'Fore.BLUE + Style.BRIGHT + f"  [INFO]'),
    (r'Fore\.BLUE \+ "  \[INFO\]', 'Fore.BLUE + Style.BRIGHT + "  [INFO]'),
    (r'Fore\.CYAN \+ f"  \[INFO\]', 'Fore.BLUE + Style.BRIGHT + f"  [INFO]'),
    (r'Fore\.CYAN \+ "  \[INFO\]', 'Fore.BLUE + Style.BRIGHT + "  [INFO]'),

    # Status markers
    (r'Fore\.WHITE \+ f"  \[\*\]', 'Fore.CYAN + f"  [*]'),
    (r'Fore\.WHITE \+ "  \[\*\]', 'Fore.CYAN + "  [*]'),
    (r'Fore\.WHITE \+ f"  \[i\]', 'Fore.CYAN + f"  [i]'),
    (r'Fore\.WHITE \+ "  \[i\]', 'Fore.CYAN + "  [i]'),
    # [!] and [OK] are usually already YELLOW and GREEN respectively, but let's be sure.
    (r'Fore\.YELLOW \+ f"  \[!\]', 'Fore.YELLOW + f"  [!]'),
    (r'Fore\.YELLOW \+ "  \[!\]', 'Fore.YELLOW + "  [!]'),
    (r'Fore\.GREEN \+ f"  \[OK\]', 'Fore.GREEN + f"  [OK]'),
    (r'Fore\.GREEN \+ "  \[OK\]', 'Fore.GREEN + "  [OK]'),
    (r'Fore\.GREEN \+ f"  \[✓\]', 'Fore.GREEN + f"  [✓]'),
    (r'Fore\.GREEN \+ "  \[✓\]', 'Fore.GREEN + "  [✓]'),
]

# Specific case for dynamic severity in xss.py and ssrf.py
# print(Fore.RED + f"  [{severity}] {kind} -> {url} [{param}]")
# This is harder to replace with simple regex if we want Style.BRIGHT.
# We'll handle common patterns first and then check for dynamic ones.

for dir_name in directories:
    full_path = os.path.join(root_dir, dir_name)
    for filename in os.listdir(full_path):
        if filename.endswith('.py'):
            file_path = os.path.join(full_path, filename)
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            new_content = content
            modified = False

            for pattern, replacement in replacements:
                if re.search(pattern, new_content):
                    new_content = re.sub(pattern, replacement, new_content)
                    modified = True

            # Handle dynamic severity if possible
            # print(Fore.RED + f"  [{severity}]
            dynamic_pattern = r'print\(Fore\.RED \+ f"  \[\{severity\}\]'
            if re.search(dynamic_pattern, new_content):
                new_content = re.sub(dynamic_pattern, 'print(Fore.RED + Style.BRIGHT + f"  [{severity}]', new_content)
                modified = True

            if modified:
                # Ensure Style is imported
                if 'Style' not in new_content and 'from colorama import Fore' in new_content:
                    new_content = new_content.replace('from colorama import Fore', 'from colorama import Fore, Style')
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"Updated {file_path}")
