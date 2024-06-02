import ast
from sqli import analyze_ast_for_SQL_injection_vulnerabilities
from ci import analyze_ast_for_command_injection_vulnerabilities
from xss import analyze_ast_for_xss_vulnerabilities

# Function to create AST and analyze uploaded file
def analyze_uploaded_file(content, selected_test=None):
    try:
        parsed_ast = ast.parse(content)
        if selected_test:
            if selected_test == 'xss':
                # Perform XSS vulnerability test
                result = analyze_ast_for_xss_vulnerabilities(parsed_ast)
            elif selected_test == 'sqli':
                # Perform SQL Injection vulnerability test
                result = analyze_ast_for_SQL_injection_vulnerabilities(parsed_ast)
            elif selected_test == 'cmd_injection':
                # Perform Command Injection vulnerability test
                result = analyze_ast_for_command_injection_vulnerabilities(parsed_ast)                          
            
        else:
            # If no specific test selected, analyze for all vulnerabilities
            result = analyze_ast_for_All_vulnerabilities(parsed_ast)
            
        return result
    except SyntaxError as e:
        print(f"SyntaxError in the provided Python code: {e}")
        return [{'error': 'SyntaxError', 'message': str(e)}]