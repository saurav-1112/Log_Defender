import hashlib
import os

def hash_file(file_path):
    """Generate MD5 hash of a single file."""
    hash_md5 = hashlib.md5()  # Create an MD5 hash object
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def hash_directory(directory_path):
    """Generate MD5 hash for all files in a directory (recursively)."""
    all_hashes = []

    for root, dirs, files in os.walk(directory_path):
        for file in sorted(files):  # Sorting files to get consistent hash order
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path)
            if file_hash:
                all_hashes.append(file_hash)

    # Combine all file hashes into a final hash
    final_hash = hashlib.md5()
    for file_hash in all_hashes:
        final_hash.update(file_hash.encode('utf-8'))  # Update with each file hash

    return final_hash.hexdigest()

# Example usage:
folder_path = input("Enter the folder path to hash: ")
folder_hash = hash_directory(folder_path)
print(f"MD5 hash of the folder: {folder_hash}")
