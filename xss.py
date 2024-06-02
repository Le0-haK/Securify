import ast
from db import connection_2

# Function to establish database connection and fetch XSS vulnerability data
def fetch_xss_vulnerabilities():
    collection = connection_2()  # Establish connection to the MongoDB collection
    return list(collection.find({}, {"_id": 0, "pattern": 1, "description": 1, "severity": 1}))

# Function to check if an AST node matches a given pattern for XSS vulnerability
def node_matches_xss_pattern(node, pattern):
    # Check if the node matches the XSS pattern
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == pattern:
        return True
    return False

# Function to analyze the AST for XSS vulnerabilities
def analyze_ast_for_xss_vulnerabilities(node):
    vulnerabilities = []
    xss_vulnerability_db = fetch_xss_vulnerabilities()  # Fetch XSS vulnerability data from the database

    for entry in xss_vulnerability_db:
        pattern, description, severity = entry.get('pattern', ''), entry.get('description', ''), entry.get('severity', '')
        if not all((pattern, description, severity)):
            continue

        for match in ast.walk(node):
            if node_matches_xss_pattern(match, pattern):
                vulnerabilities.append({
                    'pattern': pattern,
                    'description': description,
                    'severity': severity,
                    'location': f"{match.lineno}:{match.col_offset}" if hasattr(match, 'lineno') else 'unknown'
                })

    return vulnerabilities
