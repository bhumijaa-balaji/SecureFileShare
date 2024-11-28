import json
import socket
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidSignature
import base64
import argparse
import getpass

class SecureFileClient:
    def __init__(self, config_file, username, password):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.server_address = (self.config['server_ip'], self.config['server_port'])
        self.username = username
        self.password = password
        self.auth_key = self.derive_key(self.password, b'auth_salt_')
        self.encryption_key = self.derive_key(self.password, b'enc_salt_')
        self.uploaded_files = []
        self.available_files = []

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file(self, file_data):
        f = Fernet(self.encryption_key)
        encrypted_data = f.encrypt(file_data)
        mac = HMAC(self.auth_key, hashes.SHA256())
        mac.update(encrypted_data)
        return encrypted_data + mac.finalize()
    
    def decrypt_file(self, encrypted_data):
        mac = encrypted_data[-32:]
        encrypted_data = encrypted_data[:-32]
        hmac = HMAC(self.auth_key, hashes.SHA256())
        hmac.update(encrypted_data)
        try:
            hmac.verify(mac)
        except InvalidSignature:
            print("Error: Signature verification failed. The file may have been tampered with.")
            return None
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_data)

    def authenticate(self, socket):
        socket.sendall(f"{self.username}:{self.password}".encode())
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
                    # File path is the first argument
                    filename = args[0]
                    file_path = args[1]
                    expiration_minutes = args[2] if len(args) > 2 else None
                    max_downloads = args[3] if len(args) > 3 else None

                    # Normalize file path and check if the file exists
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
                        "file_name" : filename,
                        "filepath": file_path,
                        "expiration_minutes": int(expiration_minutes) if expiration_minutes else None,
                        "max_downloads": int(max_downloads) if max_downloads else None
                    }
                
                    s.sendall("upload".encode())
                    response = s.recv(1024).decode()  # Wait for "Command received"

                    metadata_json = json.dumps(metadata)
                    s.sendall(len(metadata_json).to_bytes(4, byteorder='big'))
                    s.sendall(metadata_json.encode())
                        # Send file data in chunks
                    chunk_size = 4096  # 4KB chunks, adjust as needed
                    for i in range(0, len(encrypted_data), chunk_size):
                        chunk = encrypted_data[i:i+chunk_size]
                        s.sendall(chunk)
                    s.shutdown(socket.SHUT_WR)
                    file_identifier = s.recv(1024).decode()
                    print(f"File uploaded successfully. Identifier: {file_identifier}")
                else:
                    full_command = f"{command} {' '.join(map(str, args))}".encode()
                    print(full_command)
                    s.sendall(full_command)
                    response = s.recv(1024).decode()
                    print(f"Server response: {response}")

                    if command == "list-uploaded" or command == "list-available" or command == "send-to":
                        # For these commands, we expect a JSON response
                        response = response+' '
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
        except Exception as e:
            print(f"An error occurred: {e}")

    def list_uploaded(self):        
        response = self.send_command("list-uploaded")
        print('Response inside list-uploaded',response)
        if response:
            try:
                _, json_data = response.split('[', 1)
                json_data = '[' + json_data
                self.uploaded_files = json.loads(json_data)
                if self.uploaded_files:
                    print("Uploaded Files:")
                    for file in self.uploaded_files:
                        print(f"FID: {file['fid']}, Filename: {file['filename']}, Expiration: {file['expiration']}, Downloads left: {file['downloads_left']}")
            except json.JSONDecodeError:
                print("No files uploaded or unable to parse the server response.")
        else:
            print("No response received from the server.")

    def list_available(self):
        response = self.send_command("list-available")
        if response:
            try:
                _, json_data = response.split('[', 1)
                json_data = '[' + json_data
                self.available_files = json.loads(json_data)
                if self.available_files:
                    print("Available Files:")
                    for file in self.available_files:
                        print(f"FID: {file['fid']}, Filename: {file['filename']}, Sender: {file['sender']}")
            except json.JSONDecodeError:
                print("No files uploaded or unable to parse the server response.")
        else:
            print("No response received from the server.")

    def download_by_fid(self, fid):
        if fid:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(self.server_address)
                    if not self.authenticate(s):
                        return
                    s.sendall(f"download {fid}".encode())
                    response = s.recv(1024)
                    if response == b"Command received":
                        encrypted_data_with_mac = s.recv(4096)
                        if encrypted_data_with_mac:
                            try:
                                decrypted_data = self.decrypt_file(encrypted_data_with_mac)
                                print(decrypted_data)
                                if decrypted_data:
                                    with open(f"downloaded_{fid}", 'wb') as f:
                                        f.write(decrypted_data)
                                    print(f"File saved as downloaded_{fid}")
                                else:
                                    print("Failed to decrypt the file")
                            except Exception as e:
                                print(f"Error processing file: {e}")
                        else:
                            print("No file data received")
                    else:
                        print(f"Unexpected server response: {response.decode()}")
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
         print(f"No file found with FID: {fid}")

def main():
    parser = argparse.ArgumentParser(description="Secure File Sharing Client")
    parser.add_argument("config_file", help="Path to the client configuration file")
    parser.add_argument("command", choices=["upload", "download", "list-uploaded", "list-available", "send-to"],
                        help="Command to execute")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Command arguments")
    parser.add_argument("-u", "--username", help="Username for authentication")
    args = parser.parse_args()

    username = args.username if args.username else input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    client = SecureFileClient(args.config_file, username, password)

    if args.command == "upload":
        if len(args.args) < 1:
            print("Usage: upload <file_path> [<expiration_minutes>] [<max_downloads>]")
            sys.exit(1)
        # Now we handle file path and extra arguments correctly
        filename = args.args[0]
        file_path = args.args[1]
        expiration_minutes = args.args[2] if len(args.args) > 2 else None
        max_downloads = args.args[3] if len(args.args) > 3 else None
        client.send_command(args.command, filename, file_path, expiration_minutes, max_downloads)
    elif args.command == "download":
        if len(args.args) < 1:
            print("Usage: download <file_id>")
            sys.exit(1)
        client.download_by_fid(args.args[0])
    elif args.command == "list-uploaded":
        client.list_uploaded()
    elif args.command == "list-available":
        client.list_available()
    elif args.command == "send-to":
        if len(args.args) < 2:
            print("Usage: send-to <username> <file_id>")
            sys.exit(1)
        #client.send_command(args.command, *args.args)
        recipient, file_id = args.args
        response = client.send_command(args.command, recipient, file_id)
        print(response)  # This will print the server's response
    else:
        print(f"Unknown command: {args.command}")

if __name__ == "__main__":
    main()