from pymongo import MongoClient

def connection():
    # Replace the connection string and database name with your actual MongoDB details
    client = MongoClient("mongodb://localhost:27017/")  # Connection string
    db = client["vuln-db"]  # Database name
    collection = db["sqli"]  # Collection name
    return collection

def connection_1():
    # Replace the connection string and database name with your actual MongoDB details
    client = MongoClient("mongodb://localhost:27017/")  # Connection string
    db = client["vuln-db"]  # Database name
    collection = db["ci"]  # Collection name
    return collection

def connection_2():
    # Replace the connection string and database name with your actual MongoDB details
    client = MongoClient("mongodb://localhost:27017/")  # Connection string
    db = client["vuln-db"]  # Database name
    collection = db["xss"]  # Collection name
    return collection   

def get_users_collection():
    # Establish connection to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client["securify"]  
    users_collection = db["creds"] 
    return users_collection
