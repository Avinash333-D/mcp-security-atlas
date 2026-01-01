import os

def secure_wipe_file(filepath):
    """
    Securely wipes a file by overwriting it with random data multiple times,
    then deletes it from the disk.
    """
    if not os.path.exists(filepath):
        return

    # Get file size
    size = os.path.getsize(filepath)

    # Overwrite with random data 3 times for security
    for _ in range(3):
        with open(filepath, 'wb') as f:
            f.write(os.urandom(size))

    # Delete the file
    os.remove(filepath)