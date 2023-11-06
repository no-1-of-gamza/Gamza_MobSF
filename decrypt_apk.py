import os
import zipfile
import fnmatch
import shutil
import glob
from Cryptodome.Cipher import AES, DES, Blowfish
from Cryptodome.Util.Padding import unpad

class APKDecryptor:
    def __init__(self, apk_path, encryption_method, key):
        self.original_apk = apk_path
        self.encryption_method = encryption_method
        self.key = key
        self.backup_apk = ''
        self.extract_to_path = ''
        self.decrypt_extract_to_path = ''
        self.encrypted_dex = []

    """"""""""""""""""""""""""""""""""""
    """""""""APK----------Unzip"""""""""
    """"""""""""""""""""""""""""""""""""

    def backup_apk_file(self):
        self.backup_apk = os.path.join(os.path.dirname(self.original_apk), 'original_' + os.path.basename(self.original_apk))
        shutil.copy2(self.original_apk, self.backup_apk)
        print(f"Original APK file has been backed up: {self.backup_apk}")

    def unzip_apk(self):
        new_zip = self.original_apk.replace('.apk', '.zip')
        os.rename(self.original_apk, new_zip)
        print(f"File extension has been changed from .apk to .zip: {new_zip}")

        self.extract_to_path = os.path.join(os.path.dirname(new_zip), 'original_apk')
        os.makedirs(self.extract_to_path, exist_ok=True)

        with zipfile.ZipFile(new_zip, 'r') as zip_ref:
            zip_ref.extractall(self.extract_to_path)

        print(f"Decompression complete: {self.extract_to_path}")

        self.decrypt_extract_to_path = os.path.join(os.path.dirname(new_zip), 'decrypt_apk')
        os.makedirs(self.decrypt_extract_to_path, exist_ok=True)
        shutil.copytree(self.extract_to_path, self.decrypt_extract_to_path, dirs_exist_ok=True)

    def classify_dex_files(self):
        return self._classify_dex_files(self.extract_to_path)

    def decrypt_files(self):
        true_dex, self.encrypted_dex = self.classify_dex_files()

        print("True dex files:", true_dex)
        print("Encrypted dex files:", self.encrypted_dex)

        successful_decryption_count = 0
        for encrypted_dex_path in self.encrypted_dex:
            decrypted_data = self.decrypt_file(encrypted_dex_path, self.key, self.encryption_method)
            if decrypted_data:
                self.save_decrypted_data(decrypted_data, encrypted_dex_path)
                successful_decryption_count += 1
            else:
                print(f"Failed to decrypt file: {encrypted_dex_path}")

        # Check if all files have been successfully decrypted
        if successful_decryption_count == len(self.encrypted_dex):
            print(f"All decrypted .dex files have been successfully saved to 'decrypt_apk' folder.")
        else:
            print(f"Some files failed to decrypt. There may be files not saved to 'decrypt_apk' folder.")


    def _classify_dex_files(self, directory):
        true_dex_files = []
        encrypt_dex_files = []
        pattern = '*.dex'

        files_found = []
        for root, dirs, files in os.walk(directory):
            for filename in fnmatch.filter(files, pattern):
                files_found.append(os.path.join(root, filename))
        
        if len(files_found) == 1:
            print("Single dex")
        elif len(files_found) > 1:
            print("Multi Dex")
        
        # Classifying Encrypted Dex files
        for file_path in files_found:
            with open(file_path, 'rb') as file:
                magic = file.read(4)
            
            magic_string = magic.decode(errors='ignore')
            if magic_string == 'dex\n':
                true_dex_files.append(file_path)
            else:
                encrypt_dex_files.append(file_path)

        return true_dex_files, encrypt_dex_files
    


    """"""""""""""""""""""""""""""""""""
    """""""""Decrypt-------File"""""""""
    """"""""""""""""""""""""""""""""""""

    def decrypt_file(self, file_path, key, encryption_method):
        # Extract encryption type and key length (if applicable)
        method, key_length, mode = encryption_method.split('-')
        key_length = int(key_length)
        
        # Initialize encryption cipher
        if method == 'AES':
            if key_length not in [128, 192, 256]:
                raise ValueError("Invalid AES key length. Must be 128, 192, or 256.")
            if len(key) * 8 != key_length:
                raise ValueError(f"Incorrect key length for AES-{key_length}: {len(key)} bytes.")
            cipher = AES.new(key, AES.MODE_ECB)
        elif method == 'DES':
            # DES key is always 8 bytes
            if len(key) != 8:
                raise ValueError("Incorrect key length for DES: should be 8 bytes.")
            cipher = DES.new(key, DES.MODE_ECB)
        elif method == 'Blowfish':
            # Blowfish key length is between 4 and 56 bytes
            if not (4 <= len(key) <= 56):
                raise ValueError("Incorrect key length for Blowfish.")
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            raise ValueError(f"Unsupported encryption method: {encryption_method}")
        
        with open(file_path, 'rb') as encrypted_file:
            ciphertext = encrypted_file.read()
            try:
                # ECB mode does not use IV
                decrypted_data = cipher.decrypt(ciphertext)
                # If padding was used during encryption, remove it from the decrypted data
                if mode in ['CBC', 'ECB']:
                    decrypted_data = unpad(decrypted_data, cipher.block_size)
                return decrypted_data
            except ValueError as e:
                print(f"Decryption failed: {e}")
                return None

    def save_decrypted_data(self, decrypted_data, encrypted_dex_path):
        # Create a new path for the decrypted .dex file
        decrypted_dex_filename = os.path.basename(encrypted_dex_path).replace('.dex', '_decrypted.dex')
        decrypted_dex_path = os.path.join(self.decrypt_extract_to_path, decrypted_dex_filename)
        
        with open(decrypted_dex_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
            print(f"Decrypted dex file saved as: {decrypted_dex_path}")

if __name__ == "__main__":
    # The path to your APK and other parameters can be set here.
    apk_path = 'C:\\Users\\EJ\\Desktop\\sample.apk'
    encryption_method = 'AES-128-ECB'
    key = b'dbcdcfghijklmaop'
    
    decryptor = APKDecryptor(apk_path, encryption_method, key)
    decryptor.backup_apk_file()
    decryptor.unzip_apk()
    decryptor.decrypt_files()