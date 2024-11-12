import socket
import json
import sqlite3
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Server:
    def __init__(self, server_cfg_file):
        with open(server_cfg_file, 'r') as f:
            self.server_cfg_file = json.load(f)
        self.host = self.server_cfg_file['host']
        self.port = self.server_cfg_file['port']
        self.server_key = self.generate_key(self.server_cfg_file['server_secret'])
        self.file_db_path = self.server_cfg_file['file_db_path']
        self.users_db_path = self.server_cfg_file['users_db_path']
        self.default_expiration = self.server_cfg_file['default_expiration']
        self.init_database()

    def generate_key(self, password):
        salt = b'salt_'  # In practice, use a random salt and store it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def init_database(self):
        conn = sqlite3.connect(self.file_db_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS files
                          (file_id TEXT PRIMARY KEY UNIQUE NOT NULL,
                           expire_time REAL,
                           max_download INTEGER DEFAULT 0,
                           curr_download_cnt INTEGER,
                           file_size INTEGER,
                           location TEXT)''')
        conn.commit()
        conn.close()

        file_conn = sqlite3.connect(self.users_db_path)
        file_cursor = file_conn.cursor()
        file_cursor.execute('''CREATE TABLE IF NOT EXISTS users
                               (username TEXT PRIMARY KEY UNIQUE NOT NULL,
                                password TEXT)''')
        file_conn.commit()
        file_conn.close()

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

    def perform_operations(self, conn):
        try:
            is_authenticated = self.authenticate_user(conn)
            print(f"Authentication status: {is_authenticated}")
            if is_authenticated:
                while True:
                    cmd = conn.recv(1024).decode()
                    print(f"Received command: '{cmd}'")
                    conn.send("Command received".encode())
                    if cmd == 'upload':
                        self.upload_file(conn)
                    elif cmd == 'download':
                        self.download_file(conn)
                    elif cmd == 'list-uploaded':
                        self.list_uploaded(conn)
                    elif cmd == 'list-available':
                        self.list_available(conn)
                    elif cmd == 'exit':
                        print("Client requested to exit")
                        break
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
        username, password = credential.split(':')
        print(f"Authentication attempt for user: {username}")
        send_auth_response = 'Authentication successful'
        if username == 'anonymous':
            client_socket.send(send_auth_response.encode())
            return True
        file_conn = sqlite3.connect(self.users_db_path)
        file_cursor = file_conn.cursor()
        file_cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        result = file_cursor.fetchone()
        if result is None:
            hashed_password = self.hash_password(password)
            file_cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            file_conn.commit()
            client_socket.send(send_auth_response.encode())
            file_conn.close()
            return True
        else:
            if self.verify_password(password, result[1]):
                client_socket.send(send_auth_response.encode())
                file_conn.close()
                return True
            else:
                fail_response = 'Authentication unsuccessful'
                client_socket.send(fail_response.encode())
                file_conn.close()
                return False

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

    def upload_file(self, client_socket):
        metadata_length = int.from_bytes(self.recv_all(client_socket, 4), byteorder='big')
        metadata = json.loads(self.recv_all(client_socket, metadata_length).decode())
        file_name = metadata['file_name']
        file_path = metadata['filepath']
        expiration_time = metadata['expiration_minutes']
        max_download_cnt = metadata['max_downloads']
        # Receive file data
        file_data = b''
        file_size = 0
        max_file_size = 100 * 1024 * 1024  # 100 MB limit
        chunk_size = 4096  # 4 KB chunks
        try:
            while True:
                chunk = client_socket.recv(chunk_size)
                if not chunk:
                    break  # Connection closed by client
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

        print(f"File upload complete. Total size: {file_size} bytes")        # while True:
        file_identifier = os.urandom(24).hex()
        fernet = Fernet(self.server_key)
        encrypted_file = fernet.encrypt(file_data)
        db_conn = sqlite3.connect(self.file_db_path)
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT INTO files (file_id, expire_time, max_download, curr_download_cnt, file_size, location)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (file_identifier, time.time() + expiration_time * 60, max_download_cnt, 0, file_size, file_path))
        db_conn.commit()
        db_conn.close()
        dest_path = os.path.join(file_path, file_name)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, 'wb') as f:
            f.write(encrypted_file)
        client_socket.send(file_identifier.encode())
        print(f"File uploaded successfully. Identifier: {file_identifier}")

    def download_file(self, client_socket):
        # Implement download logic here
        pass

    def list_uploaded(self, client_socket):
        # Implement list uploaded files logic here
        pass

    def list_available(self, client_socket):
        # Implement list available files logic here
        pass

if __name__ == '__main__':
    server = Server('server-cfg.json')
    server.start()
