import socket
import json
import os
import base64
import struct
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import argparse
import getpass

class Role(Enum):
    DEVELOPER = "Developer"
    MANAGER = "Manager"
    ANALYST = "Analyst"
    ADMINISTRATOR = "Administrator"
    HR_SPECIALIST = "HR Specialist"
    CONTRACTOR = "Contractor"
    SALESPERSON = "Sales Person"

class Department(Enum):
    ENGINEERING = "Engineering"
    HUMAN_RESOURCES = "HR"
    FINANCE = "Finance"
    MARKETING = "Marketing"
    OPERATIONS = "Operations"
    IT = "IT"

class ClearanceLevel(Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    SECRET = "Secret"
    TOP_SECRET = "Top Secret"


class DeterministicFernet(Fernet):
    def __init__(self, key):
        super().__init__(key)
        self._padding = padding.PKCS7(128)

    def encrypt_at_time(self, data, current_time, iv=None):
        if iv is None:
            iv = os.urandom(16)
        else:
            iv = base64.urlsafe_b64decode(iv)
        
        padder = self._padding.padder()
        padded_data = padder.update(data) + padder.finalize()

        encryptor = Cipher(
            algorithms.AES(self._encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return base64.urlsafe_b64encode(
            b'\x80' + struct.pack('>Q', current_time) + iv + ciphertext
        )
    
    def decrypt(self, token):
        data = super().decrypt(token)
        unpadder = self._padding.unpadder()
        return unpadder.update(data) + unpadder.finalize()

class SecureFileClient:
    def __init__(self, config_file, username, password, role, department, clearance_level):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.server_address = (self.config['server_ip'], self.config['server_port'])
        self.username = username
        self.password = password
        self.role = role
        self.department = department
        self.clearance_level = clearance_level
        self.auth_key = self.derive_key(self.password, b'auth_salt_')
        self.encryption_key = self.derive_key(self.password, b'enc_salt_')
        self.uploaded_files = []
        self.available_files = []
        self.fernet = Fernet(self.encryption_key)

    def peks_encrypt(self, keyword):
        hmac = HMAC(self.encryption_key, hashes.SHA256())
        hmac.update(keyword.encode())  # We hash the keyword itself
        encrypted_keyword = hmac.finalize()  # Returns a fixed-size result (32 bytes)
        return encrypted_keyword.hex()

    def peks_trapdoor(self, keyword):
        print(f"Original keyword: {keyword}")
        encrypted_keyword = self.peks_encrypt(keyword)
        print(f"Encrypted keyword (trapdoor): {encrypted_keyword}")
        return encrypted_keyword

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_file(self, file_data):
        f = DeterministicFernet(self.encryption_key)
        fixed_iv = base64.urlsafe_b64encode(b'\x00' * 16)  # 16 bytes of zeros, base64 encoded
        encrypted_data = f.encrypt_at_time(file_data, current_time=0, iv=fixed_iv)
        mac = HMAC(self.auth_key, hashes.SHA256())
        mac.update(encrypted_data)
        return encrypted_data + mac.finalize()
    
    def decrypt_file(self, encrypted_data):
        f = DeterministicFernet(self.encryption_key)
        return f.decrypt(encrypted_data)

    def authenticate(self, socket):
        socket.sendall(f"{self.username}:{self.password}:{self.role.value}:{self.department.value}:{self.clearance_level.value}".encode())
        response = socket.recv(1024).decode()
        if response != "Authentication successful":
            print("Authentication failed")
            return False
        return True

    def send_command(self, command, *args):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.server_address)
                if not self.authenticate(s):
                    return
                if command == "upload":
                    filename = args[0]
                    file_path = args[1]
                    expiration_minutes = args[2] if len(args) > 2 else None
                    max_downloads = args[3] if len(args) > 3 else None
                    sensitivity_level = args[4] if len(args) > 4 else "confidential"
                    keywords = args[5] if len(args) > 5 else []
                    encrypted_keywords = None
                    if keywords:
                        if isinstance(keywords, list):
                            encrypted_keywords = [self.peks_encrypt(keyword) for keyword in keywords]
                        else:
                            encrypted_keywords = self.peks_encrypt(keywords)
                        print("Encrypted keywords:", encrypted_keywords)


                    src_file_path = os.path.abspath(filename)
                    if not os.path.isfile(src_file_path):
                        print(f"Error: File {src_file_path} does not exist.")
                        return

                    with open(src_file_path, 'rb') as file:
                        file_data = file.read()

                    if not file_data:
                        print("File is empty. Skipping encryption.")
                        encrypted_data = None
                    else:
                        encrypted_data = self.encrypt_file(file_data)

                    metadata = {
                        "file_name": filename,
                        "filepath": file_path,
                        "expiration_minutes": int(expiration_minutes) if expiration_minutes else None,
                        "max_downloads": int(max_downloads) if max_downloads else None,
                        "sensitivity_level": sensitivity_level,
                        "keywords": str(encrypted_keywords) if encrypted_keywords else []
                    }

                    s.sendall("upload".encode())
                    response = s.recv(1024).decode()
                    if response == "Access denied":
                        print("File upload failed: Access denied")
                        return
                    metadata_json = json.dumps(metadata)
                    s.sendall(len(metadata_json).to_bytes(4, byteorder='big'))
                    s.sendall(metadata_json.encode())

                    chunk_size = 4096
                    for i in range(0, len(encrypted_data), chunk_size):
                        chunk = encrypted_data[i:i+chunk_size]
                        s.sendall(chunk)

                    s.shutdown(socket.SHUT_WR)
                    file_identifier = s.recv(1024).decode()
                    if file_identifier == "Access denied":
                        print("File upload failed: Access denied")
                    elif file_identifier == "Error: Duplicate file. Upload cancelled.":
                        print("File upload failed: Duplicate file")
                    else:
                        print(f"File uploaded successfully. Identifier: {file_identifier}")
                else:
                    if command == "search":
                        keywords = args
                        full_command = f"{command} {' '.join(map(str, keywords))}".encode()
                        trapdoor = [self.peks_trapdoor(keyword) for keyword in keywords]
                        s.sendall(full_command)
                        s.sendall(json.dumps(trapdoor).encode())
                        response = b""
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            response += chunk

                        response = response.decode()
                        print(f"Search results:\n{response}")
                    full_command = f"{command} {' '.join(map(str, args))}".encode()
                    s.sendall(full_command)
                    response = s.recv(1024).decode()
                    print(f"Server response: {response}")
                    if command in ["list-uploaded", "list-available", "send-to"]:
                        response = response + ' '
                        while True:
                            chunk = s.recv(1024).decode()
                            if not chunk:
                                break
                            response += chunk
                    if command == "download":
                        file_id = args[0]
                        s.sendall("download".encode())
                        s.sendall(file_id.encode())
                        encrypted_data = s.recv(4096)
                        decrypted_data = self.decrypt_file(encrypted_data)
                        with open(f"downloaded_{file_id}", 'wb') as f:
                            f.write(decrypted_data)
                        print(f"File saved as downloaded_{file_id}")

                return response
        except socket.error as e:
            print(f"Socket error: {e}")
    
    def list_uploaded(self):
        response = self.send_command("list-uploaded")
        if response:
            try:
                uploaded_files = json.loads(response)
                if uploaded_files:
                    print("Uploaded Files:")
                    for file in uploaded_files:
                        print(f"FID: {file['fid']}, Filename: {file['filename']}, Expiration: {file['expiration']}, Downloads left: {file['downloads_left']}")
                else:
                    print("No files uploaded.")
            except json.JSONDecodeError:
                print("Server response:", response)
        else:
            print("No response received from the server.")

    def list_available(self):
        response = self.send_command("list-available")
        if response:
            try:
                _, json_data = response.split('[', 1)
                json_data = '[' + json_data
                available_files = json.loads(json_data)
                if available_files:
                    print("Available Files:")
                    for file in available_files:
                        print(f"FID: {file['fid']}, Filename: {file['filename']}, Sender: {file['sender']}")
            except json.JSONDecodeError:
                print("No files available or unable to parse the server response.")
        else:
            print("No response received from the server.")
 
def main():
    parser = argparse.ArgumentParser(description="Secure File Sharing Client")
    parser.add_argument("config_file", help="Path to the client configuration file")
    parser.add_argument("command", choices=["upload", "download", "list-uploaded", "list-available", "send-to", "search"],
                        help="Command to execute")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Command arguments")
    parser.add_argument("-u", "--username", help="Username for authentication")
    args = parser.parse_args()
    username = args.username if args.username else input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    print("Select your role:")
    for role in Role:
        print(f"{role.value}")
    role = Role(input("Enter role: "))

    print("Select your department:")
    for dept in Department:
        print(f"{dept.value}")
    department = Department(input("Enter department: "))

    print("Select your clearance level:")
    for level in ClearanceLevel:
        print(f"{level.value}")
    clearance_level = ClearanceLevel(input("Enter clearance level: "))
    client = SecureFileClient(args.config_file, username, password, role, department, clearance_level)

    if args.command == "upload":
        if len(args.args) < 2:
            print("Usage: upload <filename> <file_path> [expiration_minutes] [max_downloads] [<keywords>]")
            return
        filename = args.args[0]
        file_path = args.args[1]
        expiration_minutes = args.args[2] if len(args.args) > 2 else None
        max_downloads = args.args[3] if len(args.args) > 3 else None
        print("Select file clearance level:")
        for level in ClearanceLevel:
            print(f"{level.value}")
        file_clearance = ClearanceLevel(input("Enter file clearance level: ")).value
        keywords_input = input("Enter keywords for easy search (separate multiple keywords with commas): ")
        keywords = [keyword.strip() for keyword in keywords_input.split(',')] if keywords_input else None

        client.send_command(args.command, filename, file_path, expiration_minutes, max_downloads, file_clearance, keywords)

    elif args.command == "download":
        if len(args.args) < 1:
            print("Usage: download <file_id>")
            return
        client.send_command(args.command, args.args[0])

    elif args.command == "list-uploaded":
        client.list_uploaded()

    elif args.command == "list-available":
        client.list_available()

    elif args.command == "send-to":
        if len(args.args) < 2:
            print("Usage: send-to <recipient> <file_id>")
            return
        response = client.send_command(args.command, *args.args)
        print(response)

    elif args.command == "search":
        if len(args.args) < 1:
            print("Usage: search <keyword>")
            return
        client.send_command(args.command, *args.args)
    else:
        print(f"Unknown command: {args.command}")

if __name__ == "__main__":
    main()