"""
MES1 CLI
Mocca Encryption System 1 - Command Line Interface

A command-line interface for the MES1 cryptographic protocol with the following features:
- Interactive menus for encryption, decryption, and integrity checking
- UUID generation and management
- File and string encryption/decryption
- Batch processing of multiple files and directories
- Compression support with configurable levels
- Integrity checking with detailed reports

Terms of use:
This command-line interface is provided "as is" without any warranties or guarantees.
This CLI is open source and publicly accessible, any commercial use must credit the author by linking 
his github profile: https://github.com/Krono159
The author of this CLI is Krono159, and the project is maintained by TanukiSoftware.
This CLI is not intended for use in any illegal activities or to circumvent any laws or regulations.
TanukiSoftware and Krono159 are not responsible of the misuse of this tool.
This must be used only for lawful purposes and to protect your data.
The misuse of this tool for unlawful purposes is sole responsibility of the user.
TanukiSoftware and Krono159 are not responsible for any damage or loss of data caused by the use of this tool
nor for the unlawful use of this tool.

TanukiSoftware supports use of AI for coding and development, but we do not endorse the use of AI for generation
of audiovisual content, including but not limited to video, audio or images. If you consider to get any kind of
art content, please pay a human artist. Art is human, and AI is not and will never replace a human.

Thanks for using MES1 CLI!
"""

import os
import json
from MES1 import (
    generate_uuid,
    derive_key,
    encrypt,
    decrypt,
    create_file_hash,
    validate_and_restore,
    save_to_file,
    check_file_integrity  
)

MENU_WIDTH = 70
MENU_PADDING = 2

def print_header(title):
    print("\n" + "=" * MENU_WIDTH)
    print(f"{title:^{MENU_WIDTH}}")
    print("=" * MENU_WIDTH)

def print_menu_item(key, description):
    padding = " " * MENU_PADDING
    print(f"{padding}{key}. {description}")

def get_input(prompt):
    """Get info with proper padding"""
    padding = " " * MENU_PADDING
    return input(f"{padding}>> {prompt}: ")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input("\nPress Enter to continue...")

def test_generate_uuid():
    """Test the UUID generation function"""
    print_header("UUID Generation")
    new_uuid = generate_uuid()
    print(f"\nGenerated UUID: {new_uuid}")
    print("\nThis UUID can be used for encryption with the MES1 protocol.")
    print("Keep it safe - you'll need it to decrypt your files later!")
    
    save_to_file = get_input("Save UUID to file? (y/n)").lower() == 'y'
    if save_to_file:
        filename = get_input("Enter filename (default: uuid.txt)") or "uuid.txt"
        save_uuid_to_file(new_uuid, filename)
    
    pause()

def test_derive_key():
    """Test the key derivation function"""
    print_header("Key Derivation Test")
    password = get_input("Enter a password")
    use_uuid = get_input("Include UUID? (y/n)").lower() == 'y'
    
    uuid_str = None
    if use_uuid:
        uuid_str = get_input("Enter UUID (or press Enter to generate one)")
        if not uuid_str:
            uuid_str = generate_uuid()
            print(f"\nGenerated UUID: {uuid_str}")
    
    key, salt = derive_key(password, None, uuid_str)
    
    print(f"\nPassword: {password}")
    if uuid_str:
        print(f"UUID: {uuid_str}")
    print(f"Salt (hex): {salt.hex()}")
    print(f"Derived Key (hex): {key.hex()}")
    print(f"\nKey Length: {len(key) * 8} bits")
    pause()

def test_string_encryption():
    """Test encrypting and decrypting a string"""
    print_header("String Encryption/Decryption Test")
    
    plaintext = get_input("Enter text to encrypt")
    password = get_input("Enter a password")
    use_uuid = get_input("Include UUID? (y/n)").lower() == 'y'
    
    uuid_str = None
    if use_uuid:
        uuid_str = get_input("Enter UUID (or press Enter to generate one)")
        if not uuid_str:
            uuid_str = generate_uuid()
            print(f"\nGenerated UUID: {uuid_str}")
    
    key, salt = derive_key(password, None, uuid_str)
    
    encrypted_data = encrypt(plaintext, key)
    
    print("\n--- Encryption Output ---")
    print(f"IV: {encrypted_data['iv']}")
    print(f"Ciphertext: {encrypted_data['ciphertext']}")
    
    print("\n--- Decryption Test ---")
    decrypted_text = decrypt(encrypted_data, key)
    print(f"Decrypted text: {decrypted_text}")
    print(f"\nOriginal text: {plaintext}")
    print(f"Successful decryption: {'Yes' if decrypted_text == plaintext else 'No'}")
    
    pause()

def test_file_encryption():
    """Test encrypting and decrypting a file"""
    print_header("File Encryption Test")
    
    file_path = get_input("Enter path to file to encrypt")
    if not os.path.exists(file_path):
        print(f"File {file_path} not found!")
        pause()
        return
    
    password = get_input("Enter a password")
    
    use_existing_uuid = get_input("Use existing UUID? (y/n)").lower() == 'y'
    uuid_str = None
    if use_existing_uuid:
        uuid_str = get_input("Enter your UUID")
    
    print("\nAdvanced options:")
    use_compression = get_input("Use compression? (y/n)").lower() == 'y'
    compression_level = 6
    if use_compression:
        try:
            level_str = get_input("Compression level (0-9, where 9 is highest compression)")
            compression_level = int(level_str)
            if compression_level < 0 or compression_level > 9:
                compression_level = 6
                print("Invalid compression level. Using default level 6.")
        except ValueError:
            compression_level = 6
            print("Invalid input. Using default compression level 6.")
    
    print("\nEncrypting file...")
    file_hash, uuid_val = create_file_hash(file_path, password, uuid_str, 
                                          compress=use_compression, 
                                          compression_level=compression_level)
    
    print("\n--- Encryption Output ---")
    print(f"UUID: {uuid_val}")
    print(f"Hash (truncated): {file_hash[:50]}...{file_hash[-50:]}")
    print("\nIMPORTANT: Keep your UUID safe. You will need it to decrypt this file.")
    
    save_uuid = get_input("Save UUID to file? (y/n)").lower() == 'y'
    if save_uuid:
        uuid_file = get_input("Enter UUID filename (default: uuid.txt)") or "uuid.txt"
        save_uuid_to_file(uuid_val, uuid_file)
    
    save_hash = get_input("Save hash to file? (y/n)").lower() == 'y'
    if save_hash:
        hash_file = get_input("Enter output file name")
        with open(hash_file, 'w', encoding='utf-8') as f:
            f.write(file_hash)
        print(f"Hash saved to {hash_file}")
    
    decrypt_now = get_input("Decrypt the file now? (y/n)").lower() == 'y'
    if decrypt_now:
        print("\nDecrypting file...")
        decrypted_lines = validate_and_restore(file_hash, password, uuid_val)
        
        if decrypted_lines:
            print("Decryption successful!")
            
            print("\nFirst few lines of decrypted content:")
            for i, line in enumerate(decrypted_lines[:3], 1):
                if i <= 3:
                    print(f"Line {i}: {line[:50]}{'...' if len(line) > 50 else ''}")
            
            save_content = get_input("Save decrypted content to file? (y/n)").lower() == 'y'
            if save_content:
                output_file = get_input("Enter output file name")
                save_to_file(decrypted_lines, output_file)
                print(f"Decrypted content saved to {output_file}")
        else:
            print("Decryption failed!")
    
    pause()

def test_file_decryption():
    """Test decrypting a file hash"""
    print_header("File Decryption Test")
    
    use_hash_file = get_input("Load hash from file? (y/n)").lower() == 'y'
    file_hash = ""
    
    if use_hash_file:
        hash_file = get_input("Enter hash file name")
        if not os.path.exists(hash_file):
            print(f"File {hash_file} not found!")
            pause()
            return
        
        with open(hash_file, 'r', encoding='utf-8') as f:
            file_hash = f.read().strip()
    else:
        print("Enter the hash string:")
        file_hash = get_input("Hash")
    
    password = get_input("Enter password")
    
    load_from_file = get_input("Load UUID from file? (y/n)").lower() == 'y'
    
    if load_from_file:
        uuid_file = get_input("Enter UUID filename (default: uuid.txt)") or "uuid.txt"
        uuid_val = load_uuid_from_file(uuid_file)
        if not uuid_val:
            uuid_val = get_input("UUID file not found. Please enter UUID manually")
    else:
        uuid_val = get_input("Enter UUID")
    
    print("\nDecrypting...")
    decrypted_lines = validate_and_restore(file_hash, password, uuid_val)
    
    if decrypted_lines:
        print("Decryption successful!")
        
        print("\nFirst few lines of decrypted content:")
        for i, line in enumerate(decrypted_lines[:3], 1):
            if i <= 3:
                print(f"Line {i}: {line[:50]}{'...' if len(line) > 50 else ''}")
        
        save_content = get_input("Save decrypted content to file? (y/n)").lower() == 'y'
        if save_content:
            output_file = get_input("Enter output file name")
            save_to_file(decrypted_lines, output_file)
            print(f"Decrypted content saved to {output_file}")
    else:
        print("Decryption failed!")
    
    pause()

def test_file_integrity_check():
    """Compare two files for integrity (detect modified lines)"""
    print_header("File Integrity Check")
    
    use_hash_file = get_input("Load original hash from file? (y/n)").lower() == 'y'
    original_hash = ""
    
    if use_hash_file:
        hash_file = get_input("Enter hash file name")
        if not os.path.exists(hash_file):
            print(f"File {hash_file} not found!")
            pause()
            return
        
        with open(hash_file, 'r', encoding='utf-8') as f:
            original_hash = f.read().strip()
    else:
        print("Enter the original hash string:")
        original_hash = get_input("Hash")
    
    password = get_input("Enter password used for original encryption")
    
    load_from_file = get_input("Load UUID from file? (y/n)").lower() == 'y'
    
    if load_from_file:
        uuid_file = get_input("Enter UUID filename (default: uuid.txt)") or "uuid.txt"
        uuid_val = load_uuid_from_file(uuid_file)
        if not uuid_val:
            uuid_val = get_input("UUID file not found. Please enter UUID manually")
    else:
        uuid_val = get_input("Enter UUID used for original encryption")
    
    compare_file = get_input("Enter path to the file to check for modifications")
    if not os.path.exists(compare_file):
        print(f"File {compare_file} not found!")
        pause()
        return
    
    print("\nPerforming integrity check, comparing files...")
    results = check_file_integrity(original_hash, password, uuid_val, compare_file)
    
    if results["status"] == "error":
        print(f"\nError: {results['message']}")
    elif results["status"] == "failed":
        print(f"\nFailed: {results['message']}")
    else:
        print("\n--- Integrity Check Results ---")
        print(f"Original file: {results['total_lines_original']} lines")
        print(f"Compare file: {results['total_lines_compare']} lines")
        
        total_changes = len(results['modified_lines']) + len(results['deleted_lines']) + len(results['added_lines'])
        
        if total_changes == 0:
            print("\nFiles match! No differences detected.")
        else:
            print(f"\nChanges detected:")
            
            if results['modified_lines']:
                print(f"\nModified lines ({len(results['modified_lines'])}):")
                for mod in results['modified_lines']:
                    print(f"  Line {mod['original_line_num']} (original) → Line {mod['compare_line_num']} (new): Content modified")
            
            if results['deleted_lines']:
                print(f"\nDeleted lines ({len(results['deleted_lines'])}):")
                for del_line in results['deleted_lines']:
                    print(f"  Line {del_line['line_number']} from original file was deleted")
            
            if results['added_lines']:
                print(f"\nAdded lines ({len(results['added_lines'])}):")
                for add_line in results['added_lines']:
                    print(f"  Line {add_line['line_number']} was added in the new file")
            
            save_report = get_input("Save integrity report to file? (y/n)").lower() == 'y'
            if save_report:
                report_file = get_input("Enter report filename") or "integrity_report.txt"
                with open(report_file, 'w') as f:
                    f.write(f"Integrity Check Report\n")
                    f.write(f"=====================\n\n")
                    f.write(f"Original file: {results['total_lines_original']} lines\n")
                    f.write(f"Compare file: {results['total_lines_compare']} lines\n\n")
                    
                    if results['modified_lines']:
                        f.write(f"Modified lines ({len(results['modified_lines'])}):\n")
                        for mod in results['modified_lines']:
                            f.write(f"  Line {mod['original_line_num']} (original) → Line {mod['compare_line_num']} (new): Content modified\n")
                    
                    if results['deleted_lines']:
                        f.write(f"\nDeleted lines ({len(results['deleted_lines'])}):\n")
                        for del_line in results['deleted_lines']:
                            f.write(f"  Line {del_line['line_number']} from original file was deleted\n")
                    
                    if results['added_lines']:
                        f.write(f"\nAdded lines ({len(results['added_lines'])}):\n")
                        for add_line in results['added_lines']:
                            f.write(f"  Line {add_line['line_number']} was added in the new file\n")
                
                print(f"\nReport saved to {report_file}")
    
    pause()

def run_built_in_test():
    """Run the built-in test from MES1.py"""
    print_header("Running Built-in Test")
    
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
    pause()

def save_uuid_to_file(uuid_str, filename="uuid.txt"):
    """Save UUID to a file for later use
    
    Args:
        uuid_str (str): The UUID to save
        filename (str): The filename to save to (default: uuid.txt)
    """
    try:
        with open(filename, 'w') as f:
            f.write(uuid_str)
        print(f"UUID saved to {filename}")
        return True
    except Exception as e:
        print(f"Error saving UUID: {str(e)}")
        return False

def load_uuid_from_file(filename="uuid.txt"):
    """Load UUID from a file
    
    Args:
        filename (str): The filename to load from (default: uuid.txt)
        
    Returns:
        str: The loaded UUID or None if file not found
    """
    try:
        if not os.path.exists(filename):
            print(f"UUID file {filename} not found!")
            return None
            
        with open(filename, 'r') as f:
            uuid_str = f.read().strip()
        print(f"UUID loaded from {filename}")
        return uuid_str
    except Exception as e:
        print(f"Error loading UUID: {str(e)}")
        return None

def secure_delete(variable):
    """
    Attempt to securely delete a variable from memory.
    
    Args:
        variable: The variable to securely delete
        
    Note:
        This is a best-effort function and may not fully remove all traces due to
        Python's memory management, but it helps reduce the exposure window.
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
            
    import gc
    gc.collect()

def batch_process_files(base_path, password, user_uuid=None, operation="encrypt", 
                       output_dir=None, include_pattern="*", compress=False, 
                       compression_level=6, recursive=False):
    """Process multiple files with the MES1 protocol
    
    Args:
        base_path (str): Path to file or directory to process
        password (str): Password for encryption/decryption
        user_uuid (str, optional): UUID for encryption/decryption
        operation (str): Either "encrypt" or "decrypt"
        output_dir (str, optional): Directory for output files
        include_pattern (str): File pattern to include (e.g., "*.txt")
        compress (bool): Whether to use compression
        compression_level (int): Compression level (0-9)
        recursive (bool): Whether to process subdirectories
        
    Returns:
        dict: Results of batch processing
    """
    import os
    import fnmatch
    
    results = {
        "total_processed": 0,
        "successful": [],
        "failed": [],
        "uuid": user_uuid or generate_uuid()
    }
    
    def process_file(file_path):
        try:
            out_path = None
            if output_dir:
                rel_path = os.path.relpath(file_path, base_path)
                out_path = os.path.join(output_dir, rel_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
            
            if operation == "encrypt":
                file_hash, _ = create_file_hash(
                    file_path, password, results["uuid"], 
                    compress=compress, 
                    compression_level=compression_level
                )
                
                if out_path:
                    with open(out_path + ".mes1", 'w', encoding='utf-8') as f:
                        f.write(file_hash)
                
                results["successful"].append({
                    "source": file_path,
                    "output": out_path + ".mes1" if out_path else None
                })
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_hash = f.read().strip()
                
                decrypted_lines = validate_and_restore(file_hash, password, results["uuid"])
                
                if decrypted_lines:
                    if out_path:
                        save_to_file(decrypted_lines, out_path)
                    else:
                        save_to_file(decrypted_lines, file_path + ".decrypted")
                    
                    results["successful"].append({
                        "source": file_path,
                        "output": out_path if out_path else file_path + ".decrypted"
                    })
                else:
                    raise Exception("Decryption failed")
            
            return True
        except Exception as e:
            results["failed"].append({
                "source": file_path,
                "error": str(e)
            })
            return False
    
    if os.path.isfile(base_path):
        process_file(base_path)
        results["total_processed"] = 1
    else:
        for root, dirs, files in os.walk(base_path):
            if not recursive and root != base_path:
                continue
                
            for filename in fnmatch.filter(files, include_pattern):
                file_path = os.path.join(root, filename)
                process_file(file_path)
                results["total_processed"] += 1
    
    return results

def test_batch_processing():
    """Test batch processing of multiple files or directories"""
    print_header("Batch Processing")
    
    operation = get_input("Operation (1=Encrypt, 2=Decrypt)").strip()
    if operation == "2":
        operation = "decrypt"
        print("Operation: Decrypt multiple files")
    else:
        operation = "encrypt"
        print("Operation: Encrypt multiple files")
    
    base_path = get_input("Enter path to file or directory")
    if not os.path.exists(base_path):
        print(f"Path {base_path} not found!")
        pause()
        return
    
    password = get_input("Enter a password")
    
    uuid_str = None
    if operation == "encrypt":
        use_existing_uuid = get_input("Use existing UUID? (y/n)").lower() == 'y'
        if use_existing_uuid:
            uuid_str = get_input("Enter your UUID")
    else:
        uuid_str = get_input("Enter UUID used for encryption")
        if not uuid_str:
            print("UUID is required for decryption!")
            pause()
            return
    
    use_output_dir = get_input("Specify output directory? (y/n)").lower() == 'y'
    output_dir = None
    if use_output_dir:
        output_dir = get_input("Enter output directory path")
    
    use_pattern = get_input("Specify file pattern? (y/n)").lower() == 'y'
    include_pattern = "*"
    if use_pattern:
        include_pattern = get_input("Enter file pattern (e.g., *.txt)") or "*"
    
    print("\nAdvanced options:")
    use_compression = False
    compression_level = 6
    if operation == "encrypt":
        use_compression = get_input("Use compression? (y/n)").lower() == 'y'
        if use_compression:
            try:
                level_str = get_input("Compression level (0-9, where 9 is highest)")
                compression_level = int(level_str)
                if compression_level < 0 or compression_level > 9:
                    compression_level = 6
                    print("Invalid compression level. Using default level 6.")
            except ValueError:
                compression_level = 6
                print("Invalid input. Using default compression level 6.")
    
    recursive = get_input("Process subdirectories recursively? (y/n)").lower() == 'y'
    
    if os.path.isdir(base_path):
        print(f"\nAbout to {operation} files in directory: {base_path}")
        if recursive:
            print("Including all subdirectories")
        print(f"Matching pattern: {include_pattern}")
    else:
        print(f"\nAbout to {operation} file: {base_path}")
        
    if not get_input("Proceed? (y/n)").lower() == 'y':
        print("Operation cancelled.")
        pause()
        return
    
    print(f"\nStarting batch {operation} operation...")
    results = batch_process_files(
        base_path, 
        password, 
        user_uuid=uuid_str, 
        operation=operation,
        output_dir=output_dir, 
        include_pattern=include_pattern, 
        compress=use_compression, 
        recursive=recursive
    )
    
    print("\nBatch processing complete:")
    print(f"Total files processed: {results['total_processed']}")
    print(f"Successful: {len(results['successful'])}")
    print(f"Failed: {len(results['failed'])}")
    
    if results['failed']:
        show_failures = get_input("Show failed operations? (y/n)").lower() == 'y'
        if show_failures:
            print("\nFailed operations:")
            for failure in results['failed']:
                print(f"  {failure['source']}: {failure['error']}")
                
    if operation == "encrypt":
        print(f"\nUUID used: {results['uuid']}")
        print("IMPORTANT: Save this UUID for decryption.")
        
        save_uuid = get_input("Save UUID to file? (y/n)").lower() == 'y'
        if save_uuid:
            uuid_file = get_input("Enter UUID filename (default: uuid.txt)") or "uuid.txt"
            save_uuid_to_file(results['uuid'], uuid_file)
    
    pause()

def main_menu():
    """Display the main menu and handle user input"""
    while True:
        clear_screen()
        print_header("MES1 Cryptographic Protocol - CLI Menu")
        
        print_menu_item("1", "Generate UUID")
        print_menu_item("2", "Test Key Derivation")
        print_menu_item("3", "Encrypt/Decrypt String")
        print_menu_item("4", "Encrypt File")
        print_menu_item("5", "Decrypt File")
        print_menu_item("6", "Batch Process Files/Directories")
        print_menu_item("7", "Check File Integrity (Line-by-Line Comparison)")
        print_menu_item("8", "Run Built-in Test")
        print_menu_item("0", "Exit")
        
        choice = get_input("Enter your choice")
        
        if choice == "1":
            test_generate_uuid()
        elif choice == "2":
            test_derive_key()
        elif choice == "3":
            test_string_encryption()
        elif choice == "4":
            test_file_encryption()
        elif choice == "5":
            test_file_decryption()
        elif choice == "6":
            test_batch_processing()
        elif choice == "7":
            test_file_integrity_check()
        elif choice == "8":
            run_built_in_test()
        elif choice == "0":
            print("\nExiting the application. Goodbye!")
            break
        else:
            print("\nInvalid choice! Please try again.")
            pause()


if __name__ == "__main__":
    try:
        main_menu()
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        input("\nPress Enter to exit...")