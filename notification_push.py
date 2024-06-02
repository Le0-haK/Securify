from db import connection, connection_1, connection_2

# Function to establish database connection and fetch vulnerability data
def fetch_total_vulnerabilities():
    collection = connection()  # Establish connection to the MongoDB collection
    return collection.count_documents({})

# Function to establish database connection and fetch vulnerability data
def fetch_total_vulnerabilities_1():
    collection = connection_1()  # Establish connection to the MongoDB collection
    return collection.count_documents({})

# Function to establish database connection and fetch vulnerability data
def fetch_total_vulnerabilities_2():
    collection = connection_2()  # Establish connection to the MongoDB collection
    return collection.count_documents({})    

# Function to establish database connection and fetch vulnerability data
def list_vulnerabilities_data():
    # Establish connection to the MongoDB collections
    collection_0 = connection()
    collection_1 = connection_1()
    collection_2 = connection_2()
    # Fetch vulnerability data from different collections
    data_0 = list(collection_0.find({}, {"_id": 0, "pattern": 1, "description": 1, "severity": 1}))
    data_1 = list(collection_1.find({}, {"_id": 0, "pattern": 1, "description": 1, "severity": 1}))
    data_2 = list(collection_2.find({}, {"_id": 0, "pattern": 1, "description": 1, "severity": 1}))
    # Concatenate the data from different collections
    all_data = data_0 + data_1 + data_2
    return all_data  