## Problem Statement
Digital communication and data sharing are increasingly critical for organizations. Modern file-sharing systems face significant security and operational challenges and protecting sensitive information while enabling collaboration is a key requirement.

## Key Challenges
Files are often stored and transmitted without adequate encryption.
Redundant file storage increases costs and operational complexity.
Inefficient systems fail to optimize secure file handling.
Limited or non-existent search functionality reduces efficiency.
Existing systems lack robust access control techniques.

We aim to develop a secure file sharing system which provides semantic security ensures robust encryption for data storage and transmission, searchable encryption enables secure keyword searches on encrypted data, attribute-based access control provides fine-grained permissions based on roles and attributes, and deduplication avoidance prevents redundant file storage while maintaining security.

## Architecture
Server Component:
Handles client connections and requests
Implements file secure storage and retrieval mechanisms
Enforces access control policies

Client Component:
Provides user interface for file operations
Manages user authentication
Implements secure communication with the server

## Functionalities

### File Upload
- Allows authenticated users to upload files
- Checks if the required arguments (filename and file path) are provided and processes optional arguments:
	- Expiration time (in minutes)
	- Maximum number of downloads
	- File sensitivity level 
	- Keywords for efficient file search, encrypts keywords if provided
- Reads the file data and encrypts the file content, provides integrity
- Server authenticates users with their credential and attributes (role, department and clearance level of the user)
- Determines access to perform the upload operation for the user based on the attributes
- Server checks for deduplication, verifies the existence of the file at the specified destination path
- Uploads file successfully if the client has access to perform the upload operation
	- Prints success message and returns with a unique file identifier if upload is successful
	- Prints error message if access is denied or if the file is a duplicate
	- Handles potential socket errors during the process

### File Download
- Allows an authenticated user to download a file using the identifier generated during file upload.
- The server checks for the user’s permissions, checks if the file is available and ensures that the file has not expired or reached the download count.
- Upon finding the file, it retrieves the encrypted data from the filesystem, decrypts it and sends the decrypted file to the client and updates the download count.
- If the file has reached the maximum download count, the server deletes the file from the filesystem and its corresponding metadata from the database.
- The client receives the decrypted file which is stored in the filesystem with the file identifier.
- Additionally, the server sends an error message if the file has been tampered with and thus checks for the integrity of the data.

### List-uploaded
- Allows authenticated users to view the list of files uploaded by them.
- The server checks for the list of files uploaded by the user and returns file identifiers, file names, expiration time and the remaining downloads left for each file and sends these details to the client.
- The client displays the list of uploaded

### List-Available
- This functionality shows both uploaded and shared files available to the user
- Allows authenticated users to request for available files.
- The server retrieves files uploaded by the user and  files shared with the user that haven't expired and haven't reached download limits.
- For each file, the server collects file identifiers, file names, sender name and type of the file (either uploaded or shared) and sends the aggregated results to the client.
- The client displays the list of available files.

### Share File
- Client takes two arguments: receiver's username and file ID to be sent
- Server extracts the receiver's username and file ID from the request
- Checks if the file exists and belongs to the sender
- Verifies if the file has not expired and hasn't reached its download limit
- Checks if the file has already been shared with the receiver
- If all checks pass, adds an entry to the shared_files table

  Successful output:
  - Client: Displays a success message indicating the file has been shared
  - Server: Sends a confirmation message to the client

  Possible errors:
  - File not found
  - File expired or reached maximum downloads
  - Sender doesn't have permission to share the file
  - File already shared with the receiver
  - Database error during the sharing process

## Additional Functionalities

### Search
- Allows an authenticated user to find files based on keywords.
- The user enters the list of keywords to be searched for which trapdoors (encrypted keywords) are generated and sent to the server.
- The server searches for the files that match the given list of keywords and returns the file identifier and the file name for the matched files.

### Access Control  
- It takes a request dictionary containing user credentials and attributes as input
- The function uses a two-step process for access control:
- Attribute-Based Access Control (ABAC) using SABAC
- Machine Learning-based decision using RandomForestClassifier

ABAC evaluation:
- Creates a sabac_context dictionary with relevant attributes
- Uses a Policy Decision Point (PDP) to evaluate the context against predefined policies
- If SABAC allows access, it proceeds to specific rule checks
- Machine Learning-based decision:
- Encodes the request attributes using custom label encoders
- Handles unknown attribute values by assigning them a default value (-1)
- Uses the trained RandomForestClassifier to predict the access decision
- Returns "Allow" if the model predicts 1, otherwise "Deny"
- The function provides a layered approach to access control, combining rule-based and ML-based decisions

It handles edge cases and provides warnings for unseen attribute values
The implementation allows for fine-grained access control based on various user and file attributes, enhancing security and flexibility in the file sharing system










