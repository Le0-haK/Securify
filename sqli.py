import ast
from db import connection


# Function to establish database connection and fetch vulnerability data
def fetch_vulnerabilities():
    collection = connection()  # Establish connection to the MongoDB collection
    return list(collection.find({}, {"_id": 0, "pattern": 1, "description": 1, "severity": 1}))

# Function to check if an AST node matches a given pattern
def node_matches_pattern(node, pattern):
    # Check if the node matches the pattern
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id == pattern
    return False

# Function to analyze the AST for vulnerabilities
def analyze_ast_for_SQL_injection_vulnerabilities(node):
    vulnerabilities = []
    vulnerability_db = fetch_vulnerabilities()  # Fetch vulnerability data from the database

    for entry in vulnerability_db:
        pattern, description, severity = entry.get('pattern', ''), entry.get('description', ''), entry.get('severity', '')
        if not all((pattern, description, severity)):
            continue

        for match in ast.walk(node):
            if node_matches_pattern(match, pattern):
                vulnerabilities.append({
                    'pattern': pattern,
                    'description': description,
                    'severity': severity,
                    'location': f"{match.lineno}:{match.col_offset}" if hasattr(match, 'lineno') else 'unknown'
                })

    return vulnerabilities    
