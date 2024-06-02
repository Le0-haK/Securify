import ast
from db import connection_1

# Function to establish database connection and fetch OS command injection vulnerability data
def fetch_command_injection_vulnerabilities():
    collection = connection_1()  # Establish connection to the MongoDB collection
    return list(collection.find({}, {"_id": 0, "pattern": 1, "description": 1, "severity": 1}))

# Function to check if an AST node matches a given pattern for OS command injection vulnerability
def node_matches_command_injection_pattern(node, pattern):
    # Check if the node matches the command injection pattern
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == pattern
    return False

# Function to analyze the AST for OS command injection vulnerabilities
def analyze_ast_for_command_injection_vulnerabilities(node):
    vulnerabilities = []
    command_injection_vulnerability_db = fetch_command_injection_vulnerabilities()  # Fetch command injection vulnerability data from the database

    for entry in command_injection_vulnerability_db:
        pattern, description, severity = entry.get('pattern', ''), entry.get('description', ''), entry.get('severity', '')
        if not all((pattern, description, severity)):
            continue

        for match in ast.walk(node):
            if node_matches_command_injection_pattern(match, pattern):
                vulnerabilities.append({
                    'pattern': pattern,
                    'description': description,
                    'severity': severity,
                    'location': f"{match.lineno}:{match.col_offset}" if hasattr(match, 'lineno') else 'unknown'
                })

    return vulnerabilities    

