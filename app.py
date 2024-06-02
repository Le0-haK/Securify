import os
from flask import Flask, request, Request, render_template, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_users_collection, connection, connection_1, connection_2
from file_extcheck import allowed_file
from file_analysis import analyze_uploaded_file
from datetime import datetime
from notification_push import *

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def dashboard():
    # Check if user is logged in
    if 'username' in session:        
        username = session['username']
        return render_template('dashboard.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users_collection = get_users_collection()
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirmPassword'] 

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('register'))  # Redirect to registration page if password is too short       

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('register'))  # Redirect to registration page if passwords don't match

        if users_collection.find_one({'username': username}):
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))  # Redirect to registration page if username already exists

        # Hash the password before storing
        hashed_password = generate_password_hash(password)

        # Store the user in the database
        users_collection.insert_one({'username': username, 'password': hashed_password})
                
        flash('Registration successful. You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('registration.html')

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Get the users collection
        users_collection = get_users_collection()

        # Find user in the database
        user = users_collection.find_one({'username': username})

        # Check if user exists and password is correct
        if user and check_password_hash(user['password'], password):
            session['username'] = username  # Set session variable for logged-in user
            
            # Check if the notification is not already set in the session
            if 'notification' not in session:
                # Get current time and format it
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                session['notification'] = f'Successful login at {current_time}'     

                total = fetch_total_vulnerabilities()
                total_1 = fetch_total_vulnerabilities_1()
                session['vulnerability_count'] = total     
                session['vulnerability_count_1'] = total_1
            
            return redirect(url_for('dashboard'))

        else:
            return render_template('login.html', message='Invalid credentials. Please try again.')
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear session variable
    return redirect(url_for('login'))

@app.route('/notification')
def notification():
    # This function will render the about page template
    if 'username' in session:
        return render_template('notifications.html')
    else:
        return redirect(url_for('login'))


@app.route('/user')
def user():
    # This function will render the about page template
    if 'username' in session:
        username = session['username']
        return render_template('user.html', username=username)
    else:
        return redirect(url_for('login'))
    

@app.route('/vulnerabilities')
def valurnabilities():    
    # Fetch the vulnerability count
    count = fetch_total_vulnerabilities()
    count1 = fetch_total_vulnerabilities_1()
    count2 = fetch_total_vulnerabilities_2()

    # Render the user.html template with the vulnerability count
    return render_template('valurnabilities.html', sqli_count=count, ci_count=count1, xss_count=count2)    


@app.route('/list_vulnerabilities')
def list_vulnerabilities():
    # Fetch vulnerabilities data from the backend, for example:
    vulnerabilities = list_vulnerabilities_data()

    # Render the Jinja2 template with the vulnerabilities data
    return render_template('vulnerability_listing.html', vulnerabilities=vulnerabilities)


@app.route('/add_vulnerabilities')
def add_vulnerabilities():
    return render_template('vulnerability_adding.html')

@app.route('/vulnerability_delete')
def vulnerability_delete():
    return render_template('vulnerability_deleting.html')


@app.route('/delete_vulnerabilities', methods=['POST'])
def delete_vulnerabilities():
    if request.method == 'POST':
        # Get form data
        pattern = request.form.get('vulnName')     
        vuln_type = request.form.get('vulnType')
 
        # Determine the collection based on the vulnerability type
        if vuln_type == 'sqli':
            collection = connection()            
        elif vuln_type == 'xss':
            collection = connection_2()            
        elif vuln_type == 'ci':
            collection = connection_1()            
        else:
            # Handle other types of vulnerabilities if needed
            return "Invalid vulnerability type"

        # Perform the deletion
        result = collection.delete_one({'pattern': pattern})
        success = result.deleted_count == 1

        if success:
            # If the vulnerability is deleted successfully, redirect to the vulnerability listing page
            return redirect(url_for('valurnabilities'))
        else:
            return "Failed to delete the vulnerability", 404                        



@app.route('/upload_vulnerability', methods=['POST'])
def upload_vulnerability():
    if request.method == 'POST':
        # Get form data
        pattern = request.form.get('vulnName')
        description = request.form.get('description')
        severity = request.form.get('severity')
        vuln_type = request.form.get('vulnType')

        # Insert data into the appropriate collection
        vulnerability_data = {
            'pattern': pattern,
            'description': description,
            'severity': severity            
        }

        
        # Determine the collection based on the vulnerability type
        if vuln_type == 'sqli':
            collection = connection()
            collection.insert_one(vulnerability_data)
        elif vuln_type == 'xss':
            collection = connection_2()
            collection.insert_one(vulnerability_data)
        elif vuln_type == 'ci':
            collection = connection_1()
            collection.insert_one(vulnerability_data)
        else:
            # Handle other types of vulnerabilities if needed
            return "Invalid vulnerability type"
                

        # Redirect to a success page or any other route
        return redirect(url_for('valurnabilities'))    



@app.route('/typography')
def typography():
    # This function will render the about page template
    return render_template('typography.html')


@app.route('/upload', methods=['GET', 'POST'])
def handle_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('typography.html', message='No file part')

        file = request.files['file']

        if file.filename == '':
            return render_template('typography.html', message='No selected file')

        if file and allowed_file(file.filename):
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()

            # Get the selected vulnerability test
            selected_test = request.form.get('vulnerability_test')
            if not selected_test:
                return render_template('typography.html', message='No vulnerability test selected')

            # Analyze the uploaded file based on the selected test
            vulnerabilities = analyze_uploaded_file(file_content, selected_test)                    
            return render_template('result.html', filename=filename, vulnerabilities=vulnerabilities)
        
        else:
            return render_template('typography.html', message='Invalid file extension. Please upload a .py file.')

    return render_template('typography.html')


@app.route('/download_result', methods=['POST'])
def download_result():
    if request.method == 'POST':
        filename = request.form['filename']
        vulnerabilities = request.form['vulnerabilities']

        # Convert vulnerabilities string to a list of dictionaries
        vulnerabilities_list = eval(vulnerabilities)

        # Create a HTML file with the result
        with open('Scan-Report.html', 'w') as f:
            f.write("<!DOCTYPE html>\n<html>\n<head>\n<title>Analysis Result</title>\n</head>\n<body>\n")
            f.write(f"<h1>Analysis Result for {filename}</h1>\n")
            f.write('<div class="table-responsive">\n<table class="table tablesorter" id="vulnerabilities-table">\n')
            f.write('<thead class="text-primary">\n<tr>\n<th>Pattern</th>\n<th>Description</th>\n<th>Severity</th>\n<th>Location</th>\n</tr>\n</thead>\n')
            f.write('<tbody>\n')
            for vuln in vulnerabilities_list:
                f.write('<tr>\n')
                f.write(f"<td>{vuln.get('pattern', 'N/A')}</td>\n")
                f.write(f"<td>{vuln.get('description', 'N/A')}</td>\n")
                f.write(f"<td>{vuln.get('severity', 'N/A')}</td>\n")
                f.write(f"<td>{vuln.get('location', 'N/A')}</td>\n")
                f.write('</tr>\n')
            f.write("</tbody>\n</table>\n</div>\n</body>\n</html>")

        # Serve the HTML file for download
        return send_file('Scan-Report.html', as_attachment=True)


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if request.method == 'POST':
        # Get the users collection
        users_collection = get_users_collection()
        
        # Get the username or user ID to identify the account to delete
        username = request.form.get('username')
       
        # Perform deletion logic here, for example:
        result = users_collection.delete_one({'username': username})
        if result.deleted_count == 1:
            # If account deleted successfully, redirect to login page
            return redirect(url_for('login'))


app.run(debug=True)
