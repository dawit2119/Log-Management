from pymongo import MongoClient,ASCENDING,TEXT

# MongoDB configuration
client = MongoClient("mongodb://localhost:27017/")
db = client["logmanagementdb"]  # Use your database name
users_collection = db["users"]
logs_collection = db["logs_collection"]
print("Hello")
def main():
   print("World")
   # Create indexes
   logs_collection.create_index([("date", ASCENDING)])
   logs_collection.create_index([("message", TEXT)])
   logs_collection.create_index([("severity", ASCENDING)])
   for index in logs_collection.list_indexes():
    print("Created index",index)
   #do some preprocessing task
   pass

if __name__ == "__main__":
    main()
