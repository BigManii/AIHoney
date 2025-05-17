from pymongo import MongoClient

uri = "mongodb+srv://emmanuelogbogu94:BarryAllen24@cluster0.d2muxlq.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(uri, serverSelectionTimeoutMS=5000)

try:
    print(client.server_info())
except Exception as e:
    print("ERROR:", e)
