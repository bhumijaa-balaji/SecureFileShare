import socket
import json
import sqlite3
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pandas as pd
from sabac import PDP, PAP, DenyBiasedPEP, deny_unless_permit
import hashlib

class CustomLabelEncoder:
    def __init__(self, unknown_value=-1):
        self.label_encoder = LabelEncoder()
        self.unknown_value = unknown_value
        self.classes_ = None

    def fit(self, y):
        self.label_encoder.fit(y)
        self.classes_ = self.label_encoder.classes_
        return self

    def transform(self, y):
        return [self.label_encoder.transform([val])[0] if val in self.classes_ 
                else self.unknown_value for val in y]

    def fit_transform(self, y):
        return self.fit(y).transform(y)

class Server:
    def __init__(self, server_cfg_file):
        with open(server_cfg_file, 'r') as f:
            self.server_cfg_file = json.load(f)
        self.host = self.server_cfg_file['host']
        self.port = self.server_cfg_file['port']
        self.server_key = self.generate_key(self.server_cfg_file['server_secret'])
        self.database_path = self.server_cfg_file['database_path']
        self.default_expiration = self.server_cfg_file['default_expiration']
        self.init_database()
        self.create_sabac_policy()
        self.train_ml_model(self.load_historical_data())
        self.peks_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    def peks_test(self, encrypted_keyword, trapdoor):
        public_key = self.peks_key.public_key()
        try:
            public_key.verify(
                trapdoor,
                encrypted_keyword,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def generate_key(self, password):
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def init_database(self):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS files
            (file_id TEXT PRIMARY KEY UNIQUE NOT NULL,
            expire_time REAL,
            max_download INTEGER DEFAULT 0,
            curr_download_cnt INTEGER,
            file_size INTEGER,
            location TEXT,
            file_name TEXT,
            uploader TEXT,
            sensitivity_level TEXT,
            keywords TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
            (username TEXT PRIMARY KEY UNIQUE NOT NULL,
            password TEXT,
            role TEXT,
            department TEXT,
            clearance_level TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS shared_files
            (file_id TEXT,
            receiver TEXT,
            FOREIGN KEY (file_id) REFERENCES files(file_id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS policy_rules
            (rule_id INTEGER PRIMARY KEY,
            subject_condition TEXT,
            object_condition TEXT,
            action TEXT,
            effect TEXT)''')
        conn.commit()
        conn.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f'Server listening on {self.host}:{self.port}')
        while True:
            client_socket, client_addr = server_socket.accept()
            print('Connection established with', client_addr)
            self.perform_operations(client_socket)
        
    def create_sabac_policy(self):
        self.pap = PAP(deny_unless_permit)
        self.pap.add_item({
            "description": "ABAC permissions",
            "target": {},
            "algorithm": "DENY_UNLESS_PERMIT",
            "rules": [
                {
                    "effect": "PERMIT",
                    "description": "Allow access based on attributes",
                    "target": {
                        "department": {"@in": ["Engineering", "HR"]},
                        "clearance_level": {"@in": ["confidential", "secret", "top_secret"]},
                        "file_type": {"@in": ["source_code", "personnel", "system_log"]}
                    }
                }
            ]
        })
        self.pdp = PDP(pap_instance=self.pap)
        self.pep = DenyBiasedPEP(self.pdp)

    def train_ml_model(self, dataset):
        X = dataset.drop('access_decision', axis=1)
        y = dataset['access_decision']
        
        self.label_encoders = {}
        for column in X.select_dtypes(include=['object']).columns:
            le = CustomLabelEncoder()
            X[column] = le.fit_transform(X[column])
            self.label_encoders[column] = le
        
        self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.ml_model.fit(X, y)

    def evaluate_access(self, request):
        sabac_context = {
            'department': request.get('department'),
            'role': request.get('role'),
            'clearance_level': request.get('clearance_level'),
            'file_type': request.get('file_type'),
            'action': request.get('action')
        }
        sabac_result = self.pep.evaluate(sabac_context)
        print(f"SABAC Result {sabac_result}")

        if sabac_result:
            # Add specific rules
            if request['role'] in ['Salesperson', 'Contractor', 'Analyst'] and request['file_type'] == 'Top Secret' and request['action'] == 'write':
                return "Deny"
            if request['role'] in ['Salesperson', 'Contractor', 'Analyst'] and request['file_type'] == 'Confidential' and request['action'] == 'read':
                return "Deny"
            return "Allow"

        # Use ML model for other cases
        encoded_request = {}
        for column, le in self.label_encoders.items():
            if column in request:
                if request[column] not in le.classes_:
                    print(f"Warning: Unseen label '{request[column]}' for attribute '{column}'")
                    encoded_request[column] = -1
                else:
                    encoded_request[column] = le.transform([request[column]])[0]
            else:
                encoded_request[column] = -1

        ml_decision = self.ml_model.predict([list(encoded_request.values())])[0]
        return "Allow" if ml_decision == 1 else "Deny"
    
    def perform_operations(self, conn):
        try:
            is_authenticated, username, user_attributes = self.authenticate_user(conn)
            print(f"Authentication status: {is_authenticated}")
            if is_authenticated:
                cmd = conn.recv(1024).decode()
                print(f"Received command: '{cmd}'")
                conn.send("Command received".encode())
                if cmd == 'upload':
                    self.upload_file(conn, username, user_attributes)
                elif cmd.startswith('download'):
                    cmd = cmd.split()
                    file_id = cmd[1]
                    self.download_file(conn, file_id, user_attributes)
                elif cmd.startswith('list-uploaded'):
                    self.list_uploaded(conn, username)
                elif cmd.startswith('list-available'):
                    self.list_available(conn, username)
                elif cmd.startswith('send-to'):
                    _, receiver, file_id = cmd.split()
                    self.send_to(conn, username, receiver, file_id, user_attributes)
                elif cmd.startswith('search'):
                    cmd = cmd.split()
                    trapdoor = json.loads(conn.recv(1024).decode())
                    self.search_files(conn, trapdoor)
                elif cmd == 'exit':
                    print("Client requested to exit")
                else:
                    print('Invalid command')
                    conn.send("Invalid command".encode())
        except Exception as e:
            print(f"An error occurred during operations: {e}")
        finally:
            conn.close()
            print("Connection closed")

    def authenticate_user(self, client_socket):
        credential = client_socket.recv(1024).decode()
        username, password, role, department, clearance_level = credential.split(':')
        role = role if role else ""
        department = department if department else ""
        clearance_level = clearance_level if clearance_level else ""
        print(role, department, clearance_level)
        print(f"Authentication attempt for user: {username}")
        send_auth_response = 'Authentication successful'
        if username == 'anonymous':
            client_socket.send(send_auth_response.encode())
            return True, username, {'role': 'anonymous', 'department': 'none', 'clearance_level': 'none'}
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result is None:
            hashed_password = self.hash_password(password)
            cursor.execute('INSERT INTO users (username, password, role, department, clearance_level) VALUES (?, ?, ?, ?, ?)', 
                            (username, hashed_password, role, department, clearance_level))
            conn.commit()
            client_socket.send(send_auth_response.encode())
            conn.close()
            return True, username, {'role': role, 'department': department, 'clearance_level': clearance_level}
        else:
            if self.verify_password(password, result[1]):
                client_socket.send(send_auth_response.encode())
                conn.close()
                return True, username, {'role': result[2], 'department': result[3], 'clearance_level': result[4]}
            else:
                fail_response = 'Authentication unsuccessful'
                client_socket.send(fail_response.encode())
                conn.close()
                return False, username, None

    def hash_password(self, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return f"{salt.hex()}:{key.decode()}"

    def verify_password(self, password, hashed_password):
        salt, key = hashed_password.split(':')
        salt = bytes.fromhex(salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_to_check = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key == key_to_check.decode()

    def recv_all(self, sock, length):
        data = b''
        while len(data) < length:
            more = sock.recv(length - len(data))
            if not more:
                raise EOFError('Socket closed with %d bytes left in this message' % (length - len(data)))
            data += more
        return data

    def deterministic_encrypt(self, data):
        key = self.server_key[:32]  # Use the first 32 bytes of the server key
        iv = b'\x00' * 16  # Use a fixed IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = self.pad(data)
        return encryptor.update(padded_data) + encryptor.finalize()

    def pad(self, data):
        block_size = 16
        padding_size = block_size - (len(data) % block_size)
        padding = bytes([padding_size] * padding_size)
        return data + padding

    def deterministic_decrypt(self, encrypted_data):
        key = self.server_key[:32]  # Use the first 32 bytes of the server key
        iv = b'\x00' * 16  # Use a fixed IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return self.unpad(decrypted_data)

    def unpad(self, data):
        padding_size = data[-1]
        return data[:-padding_size]
     
    def upload_file(self, client_socket, username, user_attributes):
        metadata_length = int.from_bytes(self.recv_all(client_socket, 4), byteorder='big')
        metadata = json.loads(self.recv_all(client_socket, metadata_length).decode())
        file_name = metadata['file_name']
        file_path = metadata['filepath']
        expiration_time = metadata['expiration_minutes']
        max_download_cnt = metadata['max_downloads']
        dest_path = os.path.join(file_path, file_name)
        if metadata['keywords']:
            print(metadata['keywords'])
            keywords = metadata['keywords']
        else:
            keywords = None  # Set keywords to None if not prov
        # Receive file data

        request = {
            "user_id": username,
            "department": user_attributes["department"],
            "role": user_attributes["role"],
            "clearance_level": user_attributes["clearance_level"],
            "file_type": metadata.get("file_type", "unknown"),
            "action": "write"
        }
        decision = self.evaluate_access(request)
        print(decision)
        if decision != "Allow":
            client_socket.send("Access denied".encode())
            return

        file_data = b''
        file_size = 0
        max_file_size = 100 * 1024 * 1024
        chunk_size = 4096
        try:
            while True:
                chunk = client_socket.recv(chunk_size)
                if not chunk:
                    break
                file_data += chunk
                file_size = len(file_data)
                print(f"Received {file_size} bytes")
                if file_size > max_file_size:
                    raise ValueError("File size exceeds maximum allowed size.")
        except ConnectionResetError:
            print("Connection reset by client")
            return
        except ValueError as e:
            error_message = f"Error: {str(e)}"
            client_socket.send(error_message.encode())
            print(error_message)
            return

        if file_size == 0:
            error_message = "Error: File size is 0 bytes. Upload cancelled."
            client_socket.send(error_message.encode())
            print(error_message)
            return

        print(f"File upload complete. Total size: {file_size} bytes")

        file_identifier = os.urandom(24).hex()
        fernet = Fernet(self.server_key)
        # encrypted_file = fernet.encrypt(file_data)
        encrypted_file= self.deterministic_encrypt(file_data)

        dest_path = os.path.join(file_path, file_name)
        if os.path.isfile(dest_path):
            # Compare file contents
            with open(dest_path, 'rb') as existing_file:
                existing_encrypted_data = existing_file.read()
            
            if existing_encrypted_data == encrypted_file:
                error_message = "Error: Duplicate file. Upload cancelled."
                client_socket.send(error_message.encode())
                print(error_message)
                return

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, 'wb') as f:
            f.write(encrypted_file)

        success_message = f"File uploaded successfully. Identifier: {file_identifier}"
        client_socket.send(success_message.encode())
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        if keywords:
            cursor.execute('''
        INSERT INTO files (file_id, expire_time, max_download, curr_download_cnt, file_size, location, file_name, uploader, sensitivity_level, keywords)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (file_identifier, time.time() + expiration_time * 60, max_download_cnt, 0, file_size, file_path, file_name, username, metadata.get("sensitivity_level", "unknown"), keywords))
        else:
            cursor.execute('''
        INSERT INTO files (file_id, expire_time, max_download, curr_download_cnt, file_size, location, file_name, uploader, sensitivity_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (file_identifier, time.time() + expiration_time * 60, max_download_cnt, 0, file_size, file_path, file_name, username, metadata.get("sensitivity_level", "unknown")))
        conn.commit()
        conn.close()

    def download_file(self, client_socket, file_id, user_attributes):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        print("Checking download..")
        cursor.execute("SELECT * FROM files WHERE file_id = ?", (file_id,))
        file_info = cursor.fetchone()
        if file_info:
            request = {
                "department": user_attributes["department"],
                "role": user_attributes["role"],
                "clearance_level": user_attributes["clearance_level"],
                "file_type": file_info[8], 
                "action": "read"
            }
            decision = self.evaluate_access(request)
            if decision != "Allow":
                client_socket.send("Access denied".encode())
                return

            if time.time() < file_info[1] and file_info[3] < file_info[2]:
                file_location = file_info[5]
                print(file_location)
                file_name = file_info[6]
                print(file_name)
                file_path = os.path.join(file_location, file_name)
                try:
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    decrypted_data=self.deterministic_decrypt(encrypted_data)
                    print("Decrypted Data", decrypted_data)
                    client_socket.sendall(decrypted_data)
                    cursor.execute("UPDATE files SET curr_download_cnt = curr_download_cnt + 1 WHERE file_id = ?", (file_id,))
                    conn.commit()
                except Exception as e:
                    error_message = f"Error processing file: {str(e)}"
                    client_socket.send(error_message.encode())
                    print(error_message)
            else:
                client_socket.send(b'File expired or max downloads reached')
                cursor.execute('DELETE FROM files WHERE file_id = ?', (file_id,))
                conn.commit()
        else:
            client_socket.send(b"File not found")
        conn.close()

    def list_uploaded(self, client_socket, username):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT file_id, file_name, expire_time, max_download, curr_download_cnt
        FROM files WHERE uploader = ?
        ''', (username,))
        uploaded_files = [
            {
                'fid': file_info[0],
                'filename': file_info[1],
                'expiration': file_info[2],
                'downloads_left': file_info[3] - file_info[4]
            }
            for file_info in cursor.fetchall()
        ]
        print(uploaded_files)
        conn.close()
        client_socket.send(json.dumps(uploaded_files).encode())

    def list_available(self, client_socket, username):
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            cursor.execute('''
            SELECT file_id, file_name, expire_time, max_download, curr_download_cnt
            FROM files WHERE uploader = ?
            ''', (username,))
            uploaded_files = [
                {
                    'fid': file_info[0],
                    'filename': file_info[1],
                    'sender': 'You',
                    'type': 'uploaded'
                }
                for file_info in cursor.fetchall()
            ]
            print("Uploaded Files:", uploaded_files)
            cursor.execute('''
            SELECT f.file_id, f.file_name, f.uploader
            FROM files f
            JOIN shared_files sf ON f.file_id = sf.file_id
            WHERE sf.receiver = ? AND f.expire_time > ? AND f.curr_download_cnt < f.max_download
            ''', (username, time.time()))
            shared_files = [
                {
                    'fid': row[0],
                    'filename': row[1],
                    'sender': row[2],
                    'type': 'shared'
                }
                for row in cursor.fetchall()
            ]
            print("Shared Files:", shared_files)
            available_files = uploaded_files + shared_files
            print("Available Files:", available_files)
            client_socket.send(json.dumps(available_files).encode())
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            client_socket.send(json.dumps({"error": "Database error occurred"}).encode())
        finally:
            if conn:
                conn.close()

    def send_to(self, client_socket, sender, receiver, file_id):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM files WHERE file_id = ? AND uploader = ? AND expire_time > ? AND curr_download_cnt < max_download",
                        (file_id, sender, time.time()))
            file_info = cursor.fetchone()
            if file_info:
                cursor.execute("SELECT * FROM shared_files WHERE file_id = ? AND receiver = ?", (file_id, receiver))
                if cursor.fetchone():
                    response = f"File {file_id} has already been shared with {receiver}"
                else:
                    cursor.execute("INSERT INTO shared_files (file_id, receiver) VALUES (?, ?)", (file_id, receiver))
                    conn.commit()
                    response = f"File {file_id} has been shared with {receiver}"
            else:
                response = f"File {file_id} not found, expired, reached max downloads, or you don't have permission to share it"
        except sqlite3.Error as e:
            conn.rollback()
            response = f"An error occurred while sharing the file: {str(e)}"
        finally:
            conn.close()
            client_socket.send(response.encode())
    
    def load_historical_data(self):
        data = {
            'role': ['Manager', 'HR Specialist', 'Salesperson', 'Contractor', 'Developer', 'Administrator', 'Manager'],
            'clearance_level': ['Top Secret', 'Secret', 'Public', 'Secret', 'Secret', 'Secret', 'Confidential'],
            'access_decision': [1, 1, 0, 1, 1, 1, 1]
        }
        
        # Add cases where access is denied
        data['role'].extend(['HR Specialist', 'Salesperson', 'Contractor', 'Developer', 'Administrator'])
        data['clearance_level'].extend(['Top Secret', 'Top Secret', 'Top Secret', 'Top Secret', 'Top Secret'])
        data['access_decision'].extend([0, 0, 0, 0, 0])

        return pd.DataFrame(data)

    def search_files(self, client_socket, trapdoors):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT file_id, file_name FROM files WHERE "
        conditions = []
        for trapdoor in trapdoors:
            conditions.append(f"keywords LIKE '%{trapdoor}%'")
        
        query += " OR ".join(conditions)
        
        cursor.execute(query)
        matching_files = cursor.fetchall()
        
        if matching_files:
            response = "Matching files:\n"
            for file_id, file_name in matching_files:
                response += f"File ID: {file_id}, File Name: {file_name}\n"
        else:
            response = "No matching files found."
        
        print(response)
        client_socket.send(response.encode())
        conn.close()

if __name__ == '__main__':
        server = Server('server-cfg.json')
        server.start()