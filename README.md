# MES1 - Mocca Encryption System

MES1 is a secure cryptographic protocol for file encryption with security features, including two-factor authentication, integrity verification, and support for binary files.

## Features

- **Secure Encryption**: AES-CBC encryption with 256-bit keys
- **Two-Factor Security**: Requires both password and UUID for encryption/decryption
- **File Type Support**: Handles both text and binary files (images, audio, video, etc.)
- **Compression**: Optional pre-encryption compression to reduce file size
- **Integrity Verification**: HMAC validation ensures files haven't been tampered with
- **Batch Processing**: Encrypt/decrypt multiple files or entire directories (not tested)
- **Line-by-Line Integrity Check**: Compare files to detect specific line modifications

## Installation

### Prerequisites
- Python 3.6 or higher
- Required packages: pycryptodome

### Setup
1. Clone the repository:
    ```bash
    git clone https://github.com/TanukiSoftware/MES1
    cd MES1
    ```
2. Install dependencies:
    ```bash
    pip install pycryptodome
    ```

## Quick Start

### Encrypting a file
```python
import MES1

# Generate or use an existing UUID
uuid = MES1.generate_uuid()

# Encrypt a file
MES1.encrypt_file("myfile.txt", "your_password", uuid, compression_level=5)
```

### Decrypting a file
```python
import MES1

# Use the same UUID from encryption
MES1.decrypt_file("myfile.txt.mes1", "your_password", uuid)
```

### Integrity checking
```python
import MES1

# Check if a file matches the original encrypted version
results = MES1.check_file_integrity("original_hash.mes1", "your_password", "your-uuid", "file_to_check.txt")

# Results include:
if results["status"] == "success":
    print(f"Modified lines: {len(results['modified_lines'])}")
    print(f"Added lines: {len(results['added_lines'])}")
    print(f"Deleted lines: {len(results['deleted_lines'])}")
```
 - After running, if an inconsistency is found, the console will report which lines have been modified, added, removed or moved but won't reveal the content to protect the content, this however can be modified to specify what has been deleted if you know how to implement it. 

## CLI Usage

The MES1_cli.py provides an interactive interface for all MES1 features:

- Generate UUID: Create a unique identifier for encryption
- Test Key Derivation: Explore how keys are derived from passwords
- Encrypt/Decrypt String: Process individual strings
- Encrypt File: Encrypt any file with optional compression
- Decrypt File: Restore encrypted files using password and UUID
- Batch Process: Encrypt/decrypt multiple files or directories
- Check File Integrity: Compare files to detect modifications
- Run Built-in Test: Verify system functionality

### Example: Encrypting a File with CLI
1. Launch the CLI: `python MES1_cli.py`
2. Select option 4 (Encrypt File)
3. Enter the file path, password, and encryption options
4. **IMPORTANT**: Save the UUID provided - you'll need it for decryption
5. Choose where to save the encrypted hash file

## Protocol Details

MES1 uses a structured format for encrypted data:
```
[HEADER][ENCRYPTED BODY][FOOTER]
```

- **Header**: Contains file metadata (encryption settings, salt, compression)
- **Body**: Contains the encrypted file content
- **Footer**: Contains HMAC for integrity verification

## Security Features

- **Two-Factor Security**:
  - Password: Something you know
  - UUID: Something you have
  
- **Key Derivation**:
  - PBKDF2 with 100,000 iterations (modifiable)
  - Unique salt for each encryption (automatically generated)
  - Keys derived from both password and UUID
  
- **Data Integrity**:
  - HMAC verification using SHA-256
  - Detects any tampering with the encrypted data
  
- **Memory Protection**:
  - Secure deletion of sensitive variables 
  - Minimizes exposure of keys in memory
  
  - Note: Due to how python works, the secure deletion is no guarantee of the deletion of sensitive info although we try to do it as best as we can. 

## Security Considerations
- Keep Your UUID Safe: Without it, decryption is impossible
- Use Strong Passwords: Complexity and length improve security. Weak passwords will almost always be the weakest points in the chain
- Backup Your Data: No recovery mechanism if credentials are lost
- Protect UUID Files: Store them separately from encrypted files

## Compression Options

Compression is enabled by default with level 5. You can adjust the compression level (0-9) where:
- 0: No compression
- 9: Maximum compression

Note that this feature is not tested. Files might not be compressed. Tests has shown that file sizes might increase after encryption


## Terms of Use

This encryption protocol is provided "as is" without any warranties. This encryption protocol is open source and publicly accessible, any commercial use must credit the author: [Krono159](https://github.com/Krono159) and/or [TanukiCompany](https://github.com/TanukiCompany/).

The project is maintained by TanukiSoftware. This protocol is intended for lawful purposes only. TanukiSoftware and Krono159 are not responsible for any misuse, damage, or data loss.

TanukiSoftware supports the use of AI for coding and development, but we do not endorse the use of AI for generation of audiovisual content. If you need art content, please pay a human artist.

Thanks for using MES1!
