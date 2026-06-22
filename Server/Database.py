import bcrypt
import json
import os

class DataBase:
    
    # Entry format for JSONs:
    # "username": {"password": "hash_in_formato_stringa", "available": 10, "used": 0}

    def __init__(self):
        self.internalState = {}
        self.default_available = 10
        
        # 1. Absolute path
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        
        # Path combining
        self.file = os.path.join(BASE_DIR, "DB", "status.json")
        
        # Create file if does not exist
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        
        # Load file if it exists
        if os.path.exists(self.file):
            self.loadState()
        else:
            self.storeState()

    def loadState(self):
        with open(self.file, 'r') as f:
            self.internalState = json.load(f)

    def storeState(self):
        with open(self.file, 'w') as f:
            json.dump(self.internalState, f, indent=4)

    def insertNewUser(self, username, password):
        self.loadState()

        # Presence check
        if self.internalState.get(username) is not None:
            print("[-] Errore: Utente già registrato!")
            return False

        # Bcrypt needs bytes
        password_bytes = password.encode('utf-8')
        
        # Hash generation (salt included within)
        hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12))
        
        # JSON needs readable strings
        hashed_string = hashed_bytes.decode('utf-8')

        new_entry = {
            "password": hashed_string,
            "available": self.default_available,
            "used": 0
        }
        
        self.internalState[username] = new_entry
        self.storeState()
        return True

    def login(self, username, password):
        self.loadState() 
        entry = self.internalState.get(username)
        
        if entry is None:
            return False
        
        # Hash to bytes for bcrypt
        stored_hash_bytes = entry["password"].encode('utf-8')
        password_bytes = password.encode('utf-8')
        
        # checkpw check
        if bcrypt.checkpw(password_bytes, stored_hash_bytes):
            return True
        return False
    
    def timeStamp(self, username):
        available = self.internalState[username]["available"]
        if available <= 0:
            return False
        return True
    
    def timeStamped(self, username):
        self.internalState[username]["available"] -= 1
        self.internalState[username]["used"] += 1
        self.storeState()
    
    def getData(self, username):
        return self.internalState.get(username)
    
    def printDB(self):
        self.loadState()
        for entry in self.internalState:
            print(f"{entry}: {self.getData(entry)}")
            
# New user insertion script
if __name__ == "__main__":
    b = DataBase()

    print("Inserisci username:")
    username = input()
    print(f"Hi, {username}! Insert your password!")
    while True:
        password = input()
        print("One more time!")
        password1 = input()
        if password == password1:
            if b.insertNewUser(username, password):
                print("[+] Utente registrato con successo nel file JSON!")
            break
        else:
            print("Ops, passwords do not coincide, please retry!")

    print("Current Database state:")
    b.printDB()