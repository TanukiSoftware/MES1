"""
MES1 
Mocca Encryption System 1
encryption and integrity check Protocol

A secure cryptographic protocol for file encryption with the following features:
- Reversible hashing of file content with line-by-line encryption
- Two-factor security requiring both password and UUID to encrypt/decrypt and validate integrity
- Data integrity verification
- Structured format with markers for parsing reliability

Terms of use:
This encryption protocol is provided "as is" without any warranties or guarantees.
This encryption protocol is open source and publicly accessible, any commercial use must credit the author by linking his github profile:  https://github.com/Krono159 
The author of this encryption protocol is Krono159, and the project is maintained by TanukiSoftware.
This encryption protocol is not intended for use in any illegal activities or to circumvent any laws or regulations.
TanukiSoftware and Krono159 are not responsible of the misuse of this encryption protocol. 
This must be used only for lawful purposes and to protect your data.
The misuse of this encryption protocol for unlawful purposes is sole responsibility of the user. 
TanukiSoftware and Krono159 are not responsible for any damage or loss of data caused by the use of this protocol nor for the unlawful use of this protocol.

Part of this code is based on the work of other developers and with github copilot. AI might have made mistakes that i have 
not corrected. Please let me know if you find any mistakes or bugs in the protocol and i will look into it. 


TanukiSoftware supports use of AI for coding and development, but we do not endorse the use of AI for generation of audiovisual content, including but not limited to video, audio or images.  If you consider to get any kind of art content, please pay a human artist. Art is human, and AI is not and will never replace a human.

Thanks for using MES1! 
"""
import os
import uuid
import hashlib
import base64
import json
import time
import gc 
import hmac 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import zlib

PROTOCOL_VERSION = "0.1.1" 

"""
Changelog
0.0.1 - Initial version, basic functionality implemented.
0.0.2 - Added support for binary files.
0.0.3 - Added hash verification and integrity check.
0.1.0 - Added other methods of encryption and batch encryption/decryption. NOT TESTED.
0.1.1 - Removed AES-GCM mode, defaulted to AES-CBC mode. Ready to publish first version to github. 

"""


"""
    This constants can be changed to modify how the protocol works. 
    The strings resulting will have separators to separate each line of the data, the end of the header and the end of the file.
    If you intend to use this, i don't recommend to use the default ones, as they are easy to guess and are publicly listed on the github repo.
    The default ones are only for testing purposes, and should not be used in production.
    The default ones are:
    LINE_SEPARATOR = "0xab1"  
    FILE_END_MARKER = "0xaf6"
    HEADER_SEPARATOR = "0xac2"

"""
LINE_SEPARATOR = "0xab1"  
FILE_END_MARKER = "0xaf6"
HEADER_SEPARATOR = "0xac2"

# Compression settings: still on the work. Not fully implemented yet.
# Target is, for example, if the Wolf of Withervale epub file is 10.6 MB, and the encrypted file without compression # 
# is 14.1 MB, Then the compressed file should be equal or less than 10.6 MB. Max. size of this would be 12 MB.
DEFAULT_COMPRESSION_LEVEL = 5  # Range is 0-9, where 9 is highest compression

# Encryption settings
SALT_SIZE = 32
IV_SIZE = 16 
KEY_SIZE = 32 
PBKDF2_ITERATIONS = 100000 # Number of iterations for PBKDF2 key derivation, higher is more secure

# AES encryption modes. This can be changed to use different modes of AES encryption but not supported yet... 
# Most of the modes are not supported yet, but the CBC mode is.
# If you want to implement other modes, you can do it by changing the code in the encrypt and decrypt functions.

ENCRYPTION_MODE_CBC = "CBC"
DEFAULT_ENCRYPTION_MODE = ENCRYPTION_MODE_CBC

# Custom Exceptions. If you want to add more exceptions, you can do it here or modify the  behaviour of current exceptions

class MES1Error(Exception):
    print("Exception for MES1 protocol. Unknown error.")
    pass

class EncryptionError(MES1Error):
    print("""Error during encryption process""")
    pass

class DecryptionError(MES1Error):
    print("""Error during decryption process""")
    pass

class HeaderError(MES1Error):
    print("""header format or decryption error""")
    pass

class IntegrityError(MES1Error):
    print("""data integrity verification error""")
    pass

class ParameterError(MES1Error):
    print("""invalid parameters""")
    pass

def secure_delete(variable):
    """
        Attempt to delete sensitive info from memory. Take in mind that due to python shit, memory stored 
        stuff might not be fully deleted. This might not be fully reliable. 
    """
    if variable is None:
        return
    
    
    if isinstance(variable, str):
        length = len(variable)
        for i in range(5):  
            variable = 'x' * length
            variable = '0' * length
    elif isinstance(variable, bytes):
        length = len(variable)
        for i in range(5):  
            variable = b'x' * length
            variable = b'0' * length
    elif isinstance(variable, list):
        for i in range(len(variable)):
            secure_delete(variable[i])
            variable[i] = None
    elif isinstance(variable, dict):
        for key in list(variable.keys()):
            secure_delete(variable[key])
            variable[key] = None
            
    # Force garbage collection
    gc.collect()

def generate_uuid():
    
    """
        Generate a random UUID string. 
        This is used with the password to generate a unique key to encrypt the data. 
        The uuid might be used to identify the user, so it is important to keep it safe.
    """
    return uuid.uuid4().hex

def derive_key(password, salt=None, uuid_str=None):
    
    
    """
    Derive a secure key from a password and  a UUID.
    
    Args:
        password (str): The user's password
        uuid_str (str): UUID to incorporate into key
        salt(bytes): Generated automatically. Salt wont be provided by user but by randomized bits
        
    Returns:
        tuple: (derived_key, salt)
        
    Raises:
        ParameterError: If parameters are invalid
    """
    try:
        if not password:
            raise ParameterError("Password cannot be empty")
            
        if not salt:
            salt = get_random_bytes(SALT_SIZE)
        
        # Convert password to bytes if it's a string
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # If UUID is provided, incorporate it into the key material
        if uuid_str:
            if isinstance(uuid_str, str):
                uuid_str = uuid_str.encode('utf-8')
            password = password + uuid_str
            
        # Use PBKDF2 to derive a secure key. 
        key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
        return key, salt
    except ParameterError:
        raise
    except Exception as e:
        raise EncryptionError(f"Key derivation failed: {str(e)}")

def encrypt(plaintext, key):
    
    """
    Encrypt data using AES-CBC mode.
    
    Args:
        plaintext (str or bytes): data to encrypt, can be a string, or a file. Might be a binary file or a text file, or maybe a single string
        key (bytes): Encryption key. provided in last function
        
    Returns:
        dict: Contains iv and ciphertext
    """
    try:
        # Parameter validation
        if not plaintext:
            raise ParameterError("Plaintext cannot be empty")
        if not key or len(key) != KEY_SIZE:
            raise ParameterError(f"Key must be {KEY_SIZE} bytes") # this error should NOT occur. If this exception is raised, check the key generation function
        
        # Generate a random initialization vector
        iv = get_random_bytes(IV_SIZE)
        
        # Convert plaintext to bytes if it's a string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Create an AES cipher object with CBC mode, then pad and encrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
        # Return as base64 encoded strings
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    except ParameterError:
        # Re-raise parameter errors
        raise
    except Exception as e:
        # Convert other exceptions to EncryptionError
        raise EncryptionError(f"Encryption failed: {str(e)}") #idk why this would happen... only happened once. Check the messages and see if it is a bug or an 8th layer error // aka. user error.

def decrypt(encrypted_data, key):
    
    """
    Decrypt data using AES-CBC mode.
    
    Args:
        encrypted_data (dict): Contains iv and ciphertext
        key (bytes): Decryption key
        
    Returns:
        str: Decrypted plaintext
        
    Raises:
        DecryptionError: If decryption fails
        ParameterError: If parameters are invalid
    """
    try:
        # Parameter validation
        if not encrypted_data or 'iv' not in encrypted_data or 'ciphertext' not in encrypted_data:
            raise ParameterError("Invalid encrypted data format")
        if not key or len(key) != KEY_SIZE:
            raise ParameterError(f"Key must be {KEY_SIZE} bytes")
        
        # Get the IV and ciphertext
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Create an AES cipher object with CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad the data
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        # Return as string
        return plaintext.decode('utf-8')
    except ParameterError:
        # Re-raise parameter errors
        raise
    except ValueError as e:
        # Handle padding errors separately
        raise DecryptionError(f"Padding error during decryption: {str(e)}")
    except Exception as e:
        # Convert other exceptions to DecryptionError
        raise DecryptionError(f"Decryption failed: {str(e)}")

def serialize_encrypted_data(encrypted_data):
    
    """
    Convert encrypted data dictionary to string format.
    
    Args:
        encrypted_data (dict): The encrypted data dictionary
        
    Returns:
        str: Serialized string representation
    """
    return f"{encrypted_data['iv']}:{encrypted_data['ciphertext']}"

def deserialize_encrypted_data(serialized_data):
    """
    Parse serialized encrypted data.
    
    Args:
        serialized_data (str): Serialized encrypted data
        
    Returns:
        dict: Encrypted data dictionary
    """
    parts = serialized_data.split(':')
    if len(parts) != 2:
        raise ParameterError("Invalid serialized data format")
        
    iv, ciphertext = parts
    return {
        'iv': iv,
        'ciphertext': ciphertext
    }

def create_file_hash(file_path, password, user_uuid=None, compress=True, 
                    compression_level=DEFAULT_COMPRESSION_LEVEL):
    """
    Generate a secure hash of the file that can be validated and restored.
    
    Args:
        file_path (str): Path to the file
        password (str): Password for encryption
        user_uuid (str, optional): User's UUID, generated if None
        compress (bool): Whether to compress the data before encryption
        compression_level (int): Compression level (0-9), where 9 is max compression
        
    Returns:
        tuple: (file_hash, uuid) - The encrypted hash string and the UUID
    """
    header_key = None
    content_key = None
    content_salt = None
    
    try:
        # Parameter validation
        if not os.path.exists(file_path):
            raise ParameterError(f"File not found: {file_path}")
        if not password:
            raise ParameterError("Password cannot be empty")
        if compression_level not in range(0, 10):
            raise ParameterError("Compression level must be between 0 and 9")
            
        # Generate or use provided UUID
        if user_uuid is None:
            user_uuid = generate_uuid()
            print(f"New UUID generated: {user_uuid}")
            print("IMPORTANT: Keep this UUID safe. You will need it to decrypt your file.")
        
        # Generate content salt (will be stored in header)
        content_salt = get_random_bytes(SALT_SIZE)
        
        # For header encryption, derive a deterministic salt from password and UUID
        header_salt = hashlib.sha256((password + user_uuid).encode()).digest()[:SALT_SIZE]
        header_key, _ = derive_key(password, header_salt, user_uuid)
        
        is_binary = False
        with open(file_path, 'rb') as check_file:
            chunk = check_file.read(1024)
            is_binary = b'\x00' in chunk or sum(1 for b in chunk if b > 127) > len(chunk) / 3
        
        if is_binary:
            with open(file_path, 'rb') as file:
                file_content = file.read()
                
            if compress:
                original_size = len(file_content)
                file_content = zlib.compress(file_content, compression_level)
                compressed_size = len(file_content)
                compression_ratio = round((1 - compressed_size / original_size) * 100, 2) if original_size > 0 else 0
                print(f"Compressed binary data: {original_size} bytes → {compressed_size} bytes ({compression_ratio}% reduction)")
            
            data_size = len(file_content)
            
            header = {
                'data_size': data_size,
                'content_salt': base64.b64encode(content_salt).decode('utf-8'),
                'version': PROTOCOL_VERSION,
                'timestamp': int(time.time()),
                'is_binary': True,
                'compressed': compress,
                'orig_size': original_size if compress else data_size
            }
            
            encrypted_header = encrypt(json.dumps(header), header_key)
            
            content_key, _ = derive_key(password, content_salt, user_uuid)
            
            encrypted_data = encrypt(file_content, content_key)
            
            mac = hmac.new(content_key, file_content, hashlib.sha256).hexdigest()
            
            header_part = f"{encrypted_header['iv']}:{encrypted_header['ciphertext']}"
            body_part = f"{encrypted_data['iv']}:{encrypted_data['ciphertext']}"
            footer_part = f"{mac}{FILE_END_MARKER}"
            
            full_hash = f"{header_part}{HEADER_SEPARATOR}{body_part}{HEADER_SEPARATOR}{footer_part}"
            
        else:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = [line.strip() for line in file.readlines()]
            
            content_str = '\n'.join(lines)
            content_bytes = content_str.encode('utf-8')
            
            if compress:
                original_size = len(content_bytes)
                compressed_bytes = zlib.compress(content_bytes, compression_level)
                compressed_size = len(compressed_bytes)
                compression_ratio = round((1 - compressed_size / original_size) * 100, 2) if original_size > 0 else 0
                print(f"Compressed text data: {original_size} bytes → {compressed_size} bytes ({compression_ratio}% reduction)")
                
                is_binary = True
                file_content = compressed_bytes
                data_size = len(file_content)
                
                header = {
                    'data_size': data_size,
                    'content_salt': base64.b64encode(content_salt).decode('utf-8'),
                    'version': PROTOCOL_VERSION,
                    'timestamp': int(time.time()),
                    'is_binary': True,
                    'compressed': True,
                    'orig_size': original_size,
                    'is_text': True
                }
                
                encrypted_header = encrypt(json.dumps(header), header_key)
                
                content_key, _ = derive_key(password, content_salt, user_uuid)
                
                encrypted_data = encrypt(file_content, content_key)
                
                mac = hmac.new(content_key, file_content, hashlib.sha256).hexdigest()
                
                header_part = f"{encrypted_header['iv']}:{encrypted_header['ciphertext']}"
                body_part = f"{encrypted_data['iv']}:{encrypted_data['ciphertext']}"
                footer_part = f"{mac}{FILE_END_MARKER}"
                
                full_hash = f"{header_part}{HEADER_SEPARATOR}{body_part}{HEADER_SEPARATOR}{footer_part}"
            else:
                data_size = sum(len(line) for line in lines)
                
                header = {
                    'data_size': data_size,
                    'content_salt': base64.b64encode(content_salt).decode('utf-8'),
                    'version': PROTOCOL_VERSION,
                    'timestamp': int(time.time()),
                    'is_binary': False,
                    'compressed': False,
                    'is_text': True
                }
                
                encrypted_header = encrypt(json.dumps(header), header_key)
                
                content_key, _ = derive_key(password, content_salt, user_uuid)
                
                encrypted_lines = []
                for line in lines:
                    line_data = encrypt(line, content_key)
                    encrypted_lines.append(f"{line_data['iv']}:{line_data['ciphertext']}{LINE_SEPARATOR}")
                
                file_content = ''.join(lines).encode('utf-8')
                mac = hmac.new(content_key, file_content, hashlib.sha256).hexdigest()
                
                header_part = f"{encrypted_header['iv']}:{encrypted_header['ciphertext']}"
                body_part = ''.join(encrypted_lines)
                footer_part = f"{mac}{FILE_END_MARKER}"
                
                full_hash = f"{header_part}{HEADER_SEPARATOR}{body_part}{HEADER_SEPARATOR}{footer_part}"
        
        return full_hash, user_uuid
        
    except ParameterError:
        raise
    except Exception as e:
        raise EncryptionError(f"File hash creation failed: {str(e)}")
    finally:
        secure_delete(header_key)
        secure_delete(content_key)
        secure_delete(content_salt)

def validate_and_restore(full_hash, password, user_uuid):
    """
    Validate the hash and restore the original file content.
    
    Args:
        full_hash (str): The encrypted hash string
        password (str): The password for decryption
        user_uuid (str): The UUID originally used for encryption
        
    Returns:
        list: The decrypted lines of the file, or None if validation fails
    """
    header_key = None
    content_key = None
    content_salt = None
    
    try:
        if not full_hash:
            raise ParameterError("Hash string cannot be empty")
        if not password:
            raise ParameterError("Password cannot be empty")
        if not user_uuid:
            raise ParameterError("UUID cannot be empty")
            
        parts = full_hash.split(HEADER_SEPARATOR)
        if len(parts) != 3:
            raise HeaderError("Invalid hash format: missing separators")
            
        header_part, body_part, footer_part = parts
        
        hmac_parts = footer_part.split(FILE_END_MARKER)
        if len(hmac_parts) != 2:
            raise HeaderError("Invalid hash format: missing file end marker")
            
        hmac_val = hmac_parts[0]
        
        header_parts = header_part.split(':', 1)
        if len(header_parts) != 2:
            raise HeaderError("Invalid header format: missing separator")
            
        header_iv, header_ciphertext = header_parts
        
        encrypted_header = {
            'iv': header_iv,
            'ciphertext': header_ciphertext
        }
        
        header_salt = hashlib.sha256((password + user_uuid).encode()).digest()[:SALT_SIZE]
        header_key, _ = derive_key(password, header_salt, user_uuid)
        
        try:
            header_str = decrypt(encrypted_header, header_key)
            header = json.loads(header_str)
        except json.JSONDecodeError as e:
            raise HeaderError(f"Invalid header format: {str(e)}")
        except DecryptionError:
            raise HeaderError("Failed to decrypt header: Invalid password or UUID.")
            
        is_binary = header.get('is_binary', False)
        is_compressed = header.get('compressed', False)
        is_text = header.get('is_text', False)
        
        if 'content_salt' not in header:
            raise HeaderError("Header missing required content_salt field")
            
        content_salt = base64.b64decode(header['content_salt'])
        content_key, _ = derive_key(password, content_salt, user_uuid)
        
        if is_binary:
            body_parts = body_part.split(':', 1)
            if len(body_parts) != 2:
                raise HeaderError("Invalid body format for binary file")
                
            iv, ciphertext = body_parts
            
            encrypted_data = {
                'iv': iv,
                'ciphertext': ciphertext
            }
            
            try:
                iv = base64.b64decode(encrypted_data['iv'])
                ciphertext = base64.b64decode(encrypted_data['ciphertext'])
                
                cipher = AES.new(content_key, AES.MODE_CBC, iv)
                
                binary_content = unpad(cipher.decrypt(ciphertext), AES.block_size)
                
                calculated_mac = hmac.new(content_key, binary_content, hashlib.sha256).hexdigest()
                if calculated_mac != hmac_val:
                    raise IntegrityError("HMAC verification failed: binary data may have been tampered with")
                
                if is_compressed:
                    try:
                        binary_content = zlib.decompress(binary_content)
                        print(f"Decompressed data: {len(binary_content)} bytes")
                    except zlib.error as e:
                        raise DecryptionError(f"Failed to decompress data: {str(e)}")
                
                if len(binary_content) != header.get('orig_size', header['data_size']):
                    print(f"Warning: Size mismatch. Expected {header.get('orig_size', header['data_size'])}, got {len(binary_content)}.")
                
                if is_text and is_compressed:
                    try:
                        text_content = binary_content.decode('utf-8')
                        return text_content.split('\n')
                    except UnicodeDecodeError:
                        print("Warning: Failed to decode as text; returning as binary")
                        return [binary_content]
                
                return [binary_content]
                
            except Exception as e:
                raise DecryptionError(f"Failed to decrypt binary content: {str(e)}")
        else:
            lines = []
            for encrypted_line in body_part.split(LINE_SEPARATOR):
                if not encrypted_line:
                    continue
                    
                line_parts = encrypted_line.split(':', 1)
                if len(line_parts) != 2:
                    continue
                    
                line_iv, line_ciphertext = line_parts
                
                encrypted_line_data = {
                    'iv': line_iv,
                    'ciphertext': line_ciphertext
                }
                
                try:
                    decrypted_line = decrypt(encrypted_line_data, content_key)
                    lines.append(decrypted_line)
                except DecryptionError as e:
                    print(f"Warning: Failed to decrypt a line: {str(e)}")
                    continue
            
            if 'data_size' in header and sum(len(line) for line in lines) != header['data_size']:
                print(f"Warning: Size mismatch. Expected {header['data_size']}, got {sum(len(line) for line in lines)}.")
            
            file_content = ''.join(lines).encode('utf-8')
            calculated_mac = hmac.new(content_key, file_content, hashlib.sha256).hexdigest()
            
            if calculated_mac != hmac_val:
                raise IntegrityError("HMAC verification failed: data may have been tampered with")
                
            return lines
            
    except MES1Error as e:
        print(f"Validation failed: {e.__class__.__name__}: {str(e)}")
        return None
    except Exception as e:
        print(f"Validation failed: Unexpected error: {str(e)}")
        return None
    finally:
        secure_delete(header_key)
        secure_delete(content_key)
        secure_delete(content_salt)

def save_to_file(lines, output_file):
    """
    Save decrypted content to a file.
    
    Args:
        lines (list): List of decrypted lines or binary content
        output_file (str): Path to the output file
    """
    try:
        if not lines:
            raise ParameterError("No content to save")
            
        if len(lines) == 1 and isinstance(lines[0], bytes):
            with open(output_file, 'wb') as f:
                f.write(lines[0])
        else:
            with open(output_file, 'w', encoding='utf-8') as f:
                for line in lines:
                    f.write(f"{line}\n")
                    
    except Exception as e:
        raise MES1Error(f"Failed to save file: {str(e)}")

def check_file_integrity(original_hash, password, user_uuid, compare_file_path):
    """
    Compare the integrity of a file against a previously encrypted hash.
    
    Args:
        original_hash (str): Original encrypted hash from previous encryption
        password (str): Password used for encryption
        user_uuid (str): UUID used for encryption
        compare_file_path (str): Path to the file to compare
        
    Returns:
        dict: Report containing integrity check results
        
    Raises:
        Various MES1Error subclasses for specific error conditions
    """
    try:
        if not original_hash:
            raise ParameterError("Original hash cannot be empty")
        if not os.path.exists(compare_file_path):
            raise ParameterError(f"Compare file not found: {compare_file_path}")
            
        original_lines = validate_and_restore(original_hash, password, user_uuid)
        if not original_lines:
            return {
                "status": "failed", 
                "message": "Failed to decrypt original hash",
                "modified_lines": [],
                "deleted_lines": [],
                "added_lines": []
            }
            
        with open(compare_file_path, 'r', encoding='utf-8') as f:
            compare_lines = [line.strip() for line in f.readlines()]
            
        changes = analyze_file_changes(original_lines, compare_lines)
        
        return {
            "status": "completed",
            "total_lines_original": len(original_lines),
            "total_lines_compare": len(compare_lines),
            "modified_lines": changes["modified"],
            "deleted_lines": changes["deleted"],
            "added_lines": changes["added"],
            "summary": (f"Found {len(changes['modified'])} modified, "
                      f"{len(changes['deleted'])} deleted, and "
                      f"{len(changes['added'])} added lines")
        }
        
    except MES1Error as e:
        return {
            "status": "error",
            "message": f"{e.__class__.__name__}: {str(e)}",
            "modified_lines": [],
            "deleted_lines": [],
            "added_lines": []
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error during integrity check: {str(e)}",
            "modified_lines": [],
            "deleted_lines": [],
            "added_lines": []
        }

def analyze_file_changes(original_lines, compare_lines):
    """
    Uses sequence matching to identify exactly which lines were modified, added, or deleted.
    
    Args:
        original_lines (list): List of lines from the original file
        compare_lines (list): List of lines from the file being compared
        
    Returns:
        dict: Dictionary with lists of modified, added, and deleted lines
    """
    import difflib
    
    matcher = difflib.SequenceMatcher(None, original_lines, compare_lines)
    
    modified = []
    deleted = []
    added = []
    
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == 'equal':
            continue
            
        elif op == 'replace':
            for line_num in range(i1, i2):
                modified.append({
                    "line_number": line_num + 1,
                    "status": "modified",
                    "original_line_num": line_num + 1,
                    "compare_line_num": j1 + (line_num - i1) + 1
                })
                
        elif op == 'delete':
            for line_num in range(i1, i2):
                deleted.append({
                    "line_number": line_num + 1,
                    "status": "deleted"
                })
                
        elif op == 'insert':
            for line_num in range(j1, j2):
                added.append({
                    "line_number": line_num + 1,
                    "status": "added"
                })
    
    return {
        "modified": modified,
        "deleted": deleted,
        "added": added
    }

def batch_process_files(base_path, password, user_uuid=None, operation="encrypt", 
                        output_dir=None, include_pattern="*", compress=True, 
                        recursive=False):
    """
    Process multiple files or directories.
    
    Args:
        base_path (str): Path to file or directory to process
        password (str): Password for encryption/decryption
        user_uuid (str, optional): UUID to use (generated if None for encryption)
        operation (str): "encrypt" or "decrypt"
        output_dir (str, optional): Directory for output files
        include_pattern (str): File pattern to include (e.g., "*.txt")
        compress (bool): Whether to compress files during encryption
        recursive (bool): Whether to recursively process subdirectories
        
    Returns:
        dict: Report on processed files
    """
    import glob
    from pathlib import Path
    
    if not os.path.exists(base_path):
        raise ParameterError(f"Path not found: {base_path}")
    
    if operation not in ["encrypt", "decrypt"]:
        raise ParameterError("Operation must be 'encrypt' or 'decrypt'")
    
    if operation == "encrypt" and not user_uuid:
        user_uuid = generate_uuid()
        print(f"Generated UUID for batch operation: {user_uuid}")
        print("IMPORTANT: Keep this UUID safe. You will need it for decryption.")
    
    if operation == "decrypt" and not user_uuid:
        raise ParameterError("UUID is required for decryption")
        
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    results = {
        "successful": [],
        "failed": [],
        "total_processed": 0,
        "uuid": user_uuid
    }
    
    def process_file(file_path):
        try:
            relative_path = os.path.relpath(file_path, base_path)
            
            if operation == "encrypt":
                if output_dir:
                    out_path = os.path.join(output_dir, f"{relative_path}.mes1")
                else:
                    out_path = f"{file_path}.mes1"
                    
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                
                file_hash, _ = create_file_hash(file_path, password, user_uuid, compress)
                
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(file_hash)
                    
                print(f"Encrypted: {file_path} → {out_path}")
                results["successful"].append({"source": file_path, "destination": out_path})
                
            else:
                if output_dir:
                    out_path = os.path.join(output_dir, relative_path)
                    if out_path.endswith('.mes1'):
                        out_path = out_path[:-5]
                else:
                    out_path = file_path
                    if out_path.endswith('.mes1'):
                        out_path = out_path[:-5]
                    out_path = f"{out_path}.decrypted"
                    
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_hash = f.read().strip()
                
                content = validate_and_restore(file_hash, password, user_uuid)
                
                if content:
                    save_to_file(content, out_path)
                    print(f"Decrypted: {file_path} → {out_path}")
                    results["successful"].append({"source": file_path, "destination": out_path})
                else:
                    raise DecryptionError(f"Failed to decrypt {file_path}")
                    
        except Exception as e:
            print(f"Failed to process {file_path}: {str(e)}")
            results["failed"].append({"source": file_path, "error": str(e)})
            return False
            
        return True
    
    if os.path.isfile(base_path):
        process_file(base_path)
        results["total_processed"] = 1
        
    else:
        processed_count = 0
        
        if recursive:
            pattern = os.path.join(base_path, "**", include_pattern)
            files = glob.glob(pattern, recursive=True)
        else:
            pattern = os.path.join(base_path, include_pattern)
            files = glob.glob(pattern)
            
        files = [f for f in files if os.path.isfile(f)]
            
        for file_path in files:
            if process_file(file_path):
                processed_count += 1
                
            if processed_count % 10 == 0:
                print(f"Progress: {processed_count}/{len(files)} files processed")
                
        results["total_processed"] = processed_count
    
    print("\nBatch processing complete:")
    print(f"Total files processed: {results['total_processed']}")
    print(f"Successful: {len(results['successful'])}")
    print(f"Failed: {len(results['failed'])}")
    
    if operation == "encrypt":
        print(f"\nUUID used: {user_uuid}")
        print("IMPORTANT: Save this UUID for decryption.")
        
    return results

def main():
    """Example usage of the cryptographic protocol."""
    import argparse
    
    parser = argparse.ArgumentParser(description="MES1 Cryptography Protocol")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("file", help="File to encrypt")
    encrypt_parser.add_argument("--password", required=True, help="Encryption password")
    encrypt_parser.add_argument("--uuid", help="Optional UUID for encryption")
    encrypt_parser.add_argument("--output", help="Output file to store the hash")
    
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("hash_file", help="File containing the hash")
    decrypt_parser.add_argument("--password", required=True, help="Decryption password")
    decrypt_parser.add_argument("--uuid", required=True, help="UUID used for encryption")
    decrypt_parser.add_argument("--output", required=True, help="Output file to store decrypted content")
    
    test_parser = subparsers.add_parser("test", help="Run a test")
    
    args = parser.parse_args()
    
    if args.command == "encrypt":
        file_hash, uuid_str = create_file_hash(args.file, args.password, args.uuid)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(file_hash)
            print(f"Hash written to {args.output}")
        else:
            print("\nGenerated hash:")
            print(f"{file_hash[:50]}...{file_hash[-50:]} (truncated)")
            
        print(f"\nUUID: {uuid_str}")
        print("KEEP THIS UUID SAFE. YOU WILL NEED IT FOR DECRYPTION.")
            
    elif args.command == "decrypt":
        with open(args.hash_file, 'r', encoding='utf-8') as f:
            file_hash = f.read().strip()
            
        lines = validate_and_restore(file_hash, args.password, args.uuid)
        
        if lines:
            save_to_file(lines, args.output)
            print(f"File successfully decrypted to {args.output}")
        else:
            print("Decryption failed")
            
    elif args.command == "test":
        test_file = "test_file.txt"
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write("This is line 1\n")
            f.write("This is line 2 with special chars: !@#$%^\n")
            f.write("This is line 3 - final line")
        
        password = "TestPassword123"
        
        print("\nEncrypting test file...")
        file_hash, uuid_str = create_file_hash(test_file, password)
        
        print(f"\nGenerated hash (truncated): {file_hash[:50]}...{file_hash[-50:]}")
        print(f"UUID: {uuid_str}")
        
        print("\nDecrypting with correct credentials...")
        decrypted_lines = validate_and_restore(file_hash, password, uuid_str)
        
        if decrypted_lines:
            print("Decryption successful!")
            print("\nDecrypted content:")
            for i, line in enumerate(decrypted_lines, 1):
                print(f"Line {i}: {line}")
        
        print("\nTesting with incorrect password...")
        wrong_result = validate_and_restore(file_hash, "WrongPassword", uuid_str)
        if not wrong_result:
            print("Correctly rejected invalid password")
        
        print("\nTesting with incorrect UUID...")
        wrong_result = validate_and_restore(file_hash, password, generate_uuid())
        if not wrong_result:
            print("Correctly rejected invalid UUID")
        
        print("\nTest completed!")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()