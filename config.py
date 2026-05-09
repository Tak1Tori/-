#Constant

NUM_BENIGN_SESSIONS = 1000  # чисто легитимные сессии
NUM_MALICIOUS_SESSIONS = 600  # сессии с атаками (шум + пейлоад)
NUM_MIXED_SESSIONS = 400  # сессии, где атака спрятана глубоко в шуме
NUM_LOGS = 20000 # количество сессий для HTTP
RAW_RESERVED_USERNAME = 'Raw_data/reserved-usernames.csv'
RAW_RESERVED_PASSWORD = 'Raw_data/passwords.csv'
LINUX_LANGUAGES = {'bash', 'sh', 'python', 'perl', 'python3', 'php', 'ruby', 'lua', 'awk', 'gawk'}
ATOMIC_DIR = "Raw_data/atomics"  # путь к папке с техниками
RAW_LINUX_TERMINAL_COMMANDS = "Raw_data/LINUX_TERMINAL_COMMANDS.jsonl"
RAW_REVERSESHELL_PLAYLOADS_DATASET = "Raw_data/Reverseshell_payloads_dataset.jsonl"
ATOMIC_LINUX_PLAYLOADS = "Data/atomic_linux_payloads.jsonl"
RSHELL_LINUX_ONLY = "Data/rshell_linux_only.jsonl"
TERMINAL_COMMANDS = "Data/terminal_cmds.jsonl"
EXPLOITDB_DIR = "Raw_data/exploitdb"
CSV_FILES = ["files_exploits.csv", "files_shellcodes.csv"]
EXPLOITDB_SHELL_ONLY = "Data/exploitdb_shell_only.jsonl"
LOGS_SSH = 'Logs/session.json'

#Mapping Category

CATEGORY_TO_TACTIC = {
    'Navigation': 'Discovery',
    'Viewing': 'Discovery',
    'System Info': 'Discovery',
    'Networking': 'Discovery',
    'File Management': 'Collection',
    'Editor': 'Execution',
    'Package Management': 'Execution',
    'Process': 'Execution',
    'Permissions': 'Defense Evasion',
    'User Management': 'Persistence',
}

#Mapping Tactics

TECHNIQUE_TO_TACTIC = {
    'T1001': ['Command and Control'],'T1001.002': ['Command and Control'],'T1003': ['Credential Access'],
    'T1003.001': ['Credential Access'],'T1003.007': ['Credential Access'],'T1003.008': ['Credential Access'],
    'T1005': ['Collection'],'T1007': ['Discovery'],'T1014': ['Defense Evasion'],'T1016': ['Discovery'],
    'T1016.001': ['Discovery'],'T1018': ['Discovery'],'T1027': ['Defense Evasion'],'T1027.001': ['Defense Evasion'],
    'T1027.002': ['Defense Evasion'],'T1027.004': ['Defense Evasion'],'T1027.013': ['Defense Evasion'],
    'T1030': ['Command and Control'],'T1033': ['Discovery'],'T1036.003': ['Defense Evasion'],'T1036.004': ['Defense Evasion'],
    'T1036.005': ['Defense Evasion'],'T1036.006': ['Defense Evasion'],'T1037.004': ['Persistence', 'Privilege Escalation'],
    'T1040': ['Discovery'],'T1046': ['Discovery'],'T1048': ['Exfiltration'],'T1048.002': ['Exfiltration'],'T1048.003': ['Exfiltration'],
    'T1049': ['Discovery'],'T1053.002': ['Persistence', 'Privilege Escalation'],'T1053.003': ['Persistence', 'Privilege Escalation'],'T1053.006': ['Persistence', 'Privilege Escalation'],
    'T1056.001': ['Collection'],'T1057': ['Discovery'],'T1059.004': ['Execution'],'T1059.006': ['Execution'],
    'T1069.001': ['Discovery'],'T1069.002': ['Discovery'],'T1070.003': ['Defense Evasion'],'T1070.004': ['Defense Evasion'],
    'T1070.006': ['Defense Evasion'],'T1070.008': ['Defense Evasion'],'T1071.001': ['Command and Control'],'T1074.001': ['Collection'],
    'T1078': ['Initial Access', 'Defense Evasion', 'Persistence', 'Privilege Escalation'],'T1078.003': ['Initial Access', 'Defense Evasion', 'Persistence', 'Privilege Escalation'],
    'T1082': ['Discovery'],'T1083': ['Discovery'],'T1087.001': ['Discovery'],'T1087.002': ['Discovery'],'T1090.001': ['Command and Control'],
    'T1090.003': ['Command and Control'],'T1098.004': ['Persistence'],'T1105': ['Command and Control'],'T1110.001': ['Credential Access'],
    'T1110.004': ['Credential Access'],'T1113': ['Collection'],'T1115': ['Collection'],'T1124': ['Discovery'],
    'T1132.001': ['Command and Control'],'T1135': ['Discovery'],'T1136.001': ['Persistence'],'T1136.002': ['Persistence'],
    'T1140': ['Defense Evasion'],'T1195.002': ['Initial Access'],'T1201': ['Discovery'],'T1217': ['Discovery'],
    'T1222.002': ['Defense Evasion'],'T1485': ['Impact'],'T1486': ['Impact'],'T1489': ['Impact'],'T1496': ['Impact'],
    'T1497.001': ['Defense Evasion'],'T1497.003': ['Defense Evasion'],'T1518.001': ['Discovery'],'T1529': ['Impact'],
    'T1531': ['Impact'],'T1543.002': ['Persistence', 'Privilege Escalation'],'T1546.004': ['Privilege Escalation', 'Persistence'],
    'T1546.005': ['Privilege Escalation', 'Persistence'],'T1546.018': ['Privilege Escalation', 'Persistence'],
    'T1547.006': ['Privilege Escalation', 'Persistence'],'T1548.001': ['Privilege Escalation', 'Defense Evasion'],
    'T1548.003': ['Privilege Escalation', 'Defense Evasion'],'T1552': ['Credential Access'],'T1552.001': ['Credential Access'],
    'T1552.003': ['Credential Access'],'T1552.004': ['Credential Access'],'T1552.007': ['Credential Access'],
    'T1553.004': ['Defense Evasion'],'T1555.003': ['Credential Access'],'T1556.003': ['Defense Evasion'],
    'T1560.001': ['Collection'],'T1560.002': ['Collection'],'T1564.001': ['Defense Evasion'],
    'T1568.002': ['Command and Control'],'T1569.002': ['Execution'],'T1569.003': ['Execution'],'T1571': ['Command and Control'],
    'T1572': ['Exfiltration'],'T1574.006': ['Persistence', 'Privilege Escalation', 'Defense Evasion'],'T1580': ['Discovery'],
    'T1614': ['Discovery'],'T1614.001': ['Discovery'],'T1652': ['Discovery'],'T1659': ['Command and Control'],
    'T1685': ['Impact'],'T1685.002': ['Impact'],'T1685.004': ['Impact'],'T1685.006': ['Impact'],
    'T1686': ['Impact'],'T1690': ['Impact'],
}

DESCRIPTION_TO_TACTIC = {
        'Privilege Escalation': [
            'privilege escalation', 'local root', 'suid', 'sudo', 'privesc',
            'privilege', 'elevation', 'root shell', 'root exploit',
            'setuid', 'setgid', 'cap_sys_admin', 'local exploit'
        ],
        'Execution': [
            'remote code execution', 'rce', 'command execution',
            'code injection', 'arbitrary code', 'buffer overflow',
            'format string', 'remote exploit', 'remote root',
            'remote command', 'command injection', 'shell',
        ],
        'Impact': [
            'denial of service', 'dos', 'ddos', 'crash', 'etrn',
            'flood', 'memory leak', 'resource exhaustion',
            'hang', 'freeze', 'reboot', 'shutdown',
        ],
        'Command and Control': [
            'reverse shell', 'bind shell', 'backdoor', 'connect back',
            'reverse_tcp', 'bind_tcp',
        ],
        'Discovery': [
            'scanner', 'enumeration', 'discovery', 'scan',
            'information', 'file read', 'directory traversal',
            'path traversal', 'read file', 'disclose',
        ],
        'Credential Access': [
            'password', 'credential', 'hash', 'brute force',
            'authentication bypass', 'login bypass', 'passwd',
            'shadow', 'hash dump',
        ],
        'Persistence': [
            'persistence', 'backdoor', 'rootkit', 'boot',
            'cron', 'rc.local', 'init.d', 'startup',
        ],
        'Defense Evasion': [
            'bypass', 'evasion', 'hide', 'obfuscation', 'clear log',
            'symlink', 'race condition', 'insecure', 'predictable',
            'temporary file', 'file creation', 'file overwrite',
        ],
        'Initial Access': [
            'remote exploit', 'remote root', 'remote attack',
            'remote code', 'unauth', 'unauthenticated',
        ],
        'Lateral Movement': [
            'ssh', 'lateral', 'pivoting', 'pass-the',
        ],
        'Exfiltration': [
            'exfiltration', 'data leak', 'steal', 'transfer',
        ],
    }