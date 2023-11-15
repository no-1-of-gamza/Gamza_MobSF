import os
import zipfile
import fnmatch
import shutil
import glob
from Cryptodome.Cipher import AES, DES, Blowfish
from Cryptodome.Util.Padding import unpad
import subprocess
import datetime
import time
import re
from elftools.elf.elffile import ELFFile

class APKDecryptor:
    def __init__(self, apk_path, encryption_method):
        self.output_directory_path = ''
        self.original_apk = apk_path
        self.encryption_method = encryption_method
        self.extract_to_path = ''
        self.decrypt_extract_to_path = ''
        self.encrypted_dex = []

    """"""""""""""""""""""""""""""""""""
    """""""""APK----------Unzip"""""""""
    """"""""""""""""""""""""""""""""""""
    def make_output_directory(self):
        date_time_folder_name = 'decrypt_apk_' + datetime.datetime.now().strftime("%Y%m%d_%H%M")
        output_directory_path = os.path.join(os.path.dirname(__file__), date_time_folder_name)
        os.makedirs(output_directory_path, exist_ok=True)  
        return output_directory_path

    def backup_apk_file(self):
        try:
            self.output_directory_path = self.make_output_directory()
            backup_apk_path = os.path.join(self.output_directory_path, 'original_' + os.path.basename(self.original_apk))
            shutil.copy2(self.original_apk, backup_apk_path)
            print(f"Original APK file has been backed up: {self.output_directory_path}")
            print("---------------------------------------------------------------")
        except Exception as e:
            print(f"Failed to backup APK file: {e}")
        return backup_apk_path

    def unzip_apk(self):
        try:
            self.output_directory_path = self.make_output_directory()
            copied_apk_path = os.path.join(self.output_directory_path, os.path.basename(self.original_apk))
            
            try:
                shutil.copy2(self.original_apk, copied_apk_path)
            except IOError as e:
                print(f"Failed to copy the file: {e}")
                return  
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                return  
            
            new_zip = copied_apk_path.replace('.apk', '.zip')
            os.rename(copied_apk_path, new_zip)
            print(f"File extension has been changed from .apk to .zip: {new_zip}")
            print("---------------------------------------------------------------")

            self.extract_to_path = os.path.join(os.path.dirname(new_zip), 'original_apk')
            os.makedirs(self.extract_to_path, exist_ok=True)
            
            with zipfile.ZipFile(new_zip, 'r') as zip_ref:
                zip_ref.extractall(self.extract_to_path)

            print(f"Decompression complete: {self.extract_to_path}")
            print("---------------------------------------------------------------")

            self.decrypt_extract_to_path = os.path.join(os.path.dirname(new_zip), 'decrypt_apk')
            os.makedirs(self.decrypt_extract_to_path, exist_ok=True)
            shutil.copytree(self.extract_to_path, self.decrypt_extract_to_path, dirs_exist_ok=True)

        except zipfile.BadZipFile:
            print("The file is not a zip file or it is corrupted.")
        except OSError as e:
            print(f"An OS error occurred: {e.strerror}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def find_nested_apk_files(self):
        apk_files = []
        for root, dirs, files in os.walk(self.extract_to_path):
            for filename in fnmatch.filter(files, '*.apk'):
                apk_files.append(os.path.join(root, filename))
        return apk_files

    def _classify_dex_files(self):
        true_dex_files = []
        encrypt_dex_files = []
        pattern = '*.dex'

        try:
            files_found = []
            for root, dirs, files in os.walk(self.extract_to_path):
                for filename in fnmatch.filter(files, pattern):
                    files_found.append(os.path.join(root, filename))
                    
            if len(files_found) == 1:
                print("Single dex")
            elif len(files_found) > 1:
                print("Multi Dex")
            print("---------------------------------------------------------------")   

            # Classifying Encrypted Dex files
            for file_path in files_found:
                try:
                    with open(file_path, 'rb') as file:
                        magic = file.read(4)
                except IOError as e:
                    print(f"Error reading file {file_path}: {e.strerror}")
                    continue  # Skip to the next file
                
                try:
                    magic_string = magic.decode(errors='ignore')
                except UnicodeDecodeError as e:
                    print(f"Error decoding file {file_path}: {e}")
                    continue  # Skip to the next file

                if magic_string == 'dex\n':
                    true_dex_files.append(file_path)
                else:
                    encrypt_dex_files.append(file_path)

        except Exception as e:
            print(f"An unexpected error occurred while classifying dex files: {e}")

        return true_dex_files, encrypt_dex_files

    """"""""""""""""""""""""""""""""""""
    """""""""Decrypt-------File"""""""""
    """"""""""""""""""""""""""""""""""""
    def decrypt_files(self, keys_str, encryption_method=None):
        keys = [key.encode() for key in keys_str]  # 키 문자열을 바이트로 변환

        if not keys:
            print("Error: 'keys' is empty, decryption cannot proceed.")
            return

        try:
            true_dex, self.encrypted_dex = self._classify_dex_files()
            if not self.encrypted_dex:
                print("No files to decrypt.")
                return

            successful_decryption_count = 0
            failed_decryption_count = 0

            for encrypted_dex_path in self.encrypted_dex:
                file_decrypted = False

                for key in keys:
                    methods_to_try = [encryption_method] if encryption_method else ['AES', 'DES', 'Blowfish']
                    for method in methods_to_try:
                        if method == 'Blowfish':
                            key_lengths = list(range(32, 449, 8))
                        else:
                            key_lengths = [128, 192, 256]

                        for key_length in key_lengths:
                            modes_to_try = [encryption_method.split('-')[2]] if encryption_method else ['ECB']
                            for mode in modes_to_try:
                                try:
                                    encryption_spec = f"{method}-{key_length}-{mode}"
                                    decrypted_data = self.decrypt_file(encrypted_dex_path, key, encryption_spec)
                                    if decrypted_data and decrypted_data[:3] == b'dex':
                                        file_decrypted = True
                                        print(f"Success: {encrypted_dex_path} decrypted with key: {key.decode()}")
                                        print(f"Decryption completed with {successful_decryption_count} successes and {failed_decryption_count} failures.")
                                        print("---------------------------------------------------------------")
                                        return decrypted_data
                        
                                except ValueError as e:
                                    print(f"ValueError with key: {key.decode()} | {e}")
                                    continue
                                except FileNotFoundError:
                                    continue
                                except Exception as e:
                                    print(f"Unexpected exception with key: {key.decode()} | {e}")
                                    continue    
                            if file_decrypted:
                                print(f"Decryption completed with {successful_decryption_count} successes and {failed_decryption_count} failures.")
                                print("---------------------------------------------------------------")
                                return decrypted_data
                        if file_decrypted:
                            print(f"Decryption completed with {successful_decryption_count} successes and {failed_decryption_count} failures.")
                            print("---------------------------------------------------------------")
                            return decrypted_data

                if not file_decrypted:
                    failed_decryption_count += 1
                    print(f"Failure: No valid key or method found to decrypt {encrypted_dex_path}")

            print(f"Decryption completed with {successful_decryption_count} successes and {failed_decryption_count} failures.")
            print("---------------------------------------------------------------")
            return decrypted_data
        except Exception as e:
            print(f"An error occurred during the decryption process: {e}")  

    def decrypt_file(self, file_path, key, encryption_spec):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file {file_path} does not exist.")

        method, key_length_str, mode = encryption_spec.split('-')
        key_length = int(key_length_str) // 8 

        cipher = None
        if method == 'AES' and len(key) == key_length:
            cipher = AES.new(key, AES.MODE_ECB)
        elif method == 'DES' and len(key) == 8:
            cipher = DES.new(key, DES.MODE_ECB)
        elif method == 'Blowfish' and (4 <= len(key) <= 56):
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            raise ValueError(f"Unsupported encryption method or incorrect key length for {method}.")

        with open(file_path, 'rb') as encrypted_file:
            ciphertext = encrypted_file.read()

        decrypted_data = cipher.decrypt(ciphertext)
        try:
            decrypted_data = unpad(decrypted_data, cipher.block_size)
        except ValueError:
            raise ValueError("Incorrect padding.")

        return decrypted_data

    def save_decrypted_data(self, decrypted_data):
        try:
            number_of_dex_files = 0

            for root, dirs, files in os.walk(self.decrypt_extract_to_path):
                for file in files:
                    if fnmatch.fnmatch(file, '*.dex'):
                        number_of_dex_files += 1

            if number_of_dex_files == 0:
                decrypted_dex_filename = "classes.dex"
            else:
                decrypted_dex_filename = f"classes{number_of_dex_files}.dex"

            decrypted_dex_path = os.path.join(self.decrypt_extract_to_path, decrypted_dex_filename)
            
            # Ensure the parent directory exists
            os.makedirs(os.path.dirname(decrypted_dex_path), exist_ok=True)

            with open(decrypted_dex_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
                print(f"Decrypted dex file saved as: {decrypted_dex_path}")
        
        except IOError as e:
            print(f"Failed to save decrypted data: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while saving decrypted data: {e}")

    """"""""""""""""""""""""""""""""""""
    """"apk tool Repackaging APK"""""""""
    """"""""""""""""""""""""""""""""""""

    def decompile_apk(self, apk_backup_path):
        try:
            current_script_dir = os.path.dirname(os.path.realpath(__file__))
            apktool_path = os.path.join(current_script_dir, "apktool.bat")
            output_dir = os.path.join(os.path.dirname(apk_backup_path),"apk_tool_orginal_decrypt" ,os.path.splitext(os.path.basename(self.original_apk))[0])
            
            command = [apktool_path, "d", self.original_apk, "-o", output_dir]
            
            result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

            if result.returncode == None:
                print(f"APK successfully decompiled to {output_dir}.")
                print(result.stdout)
                print("---------------------------------------------------------------")   
                return output_dir
            else:
                print("APK decompilation failed.")
                print(result.stderr)
                print("---------------------------------------------------------------") 
                return None
                
        except FileNotFoundError:
            print("apktool was not found. Please ensure that it is installed and added to your PATH.")
            return None
        except OSError as e:
            print(f"An OS error occurred: {e.strerror}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred while decompiling the APK: {e}")
            return None
    print("---------------------------------------------------------------")   

    def repackaging_apk(self, output_dir):
        time.sleep(5)
        try:
            current_script_dir = os.path.dirname(os.path.realpath(__file__))
            apktool_path = os.path.join(current_script_dir, "apktool.bat")
            
            yml_file_path = os.path.join(output_dir, "apktool.yml")
            destination_path = os.path.join(self.output_directory_path, "decrypt_apk")
            destination_file_path = os.path.join(destination_path, 'apktool.yml')

            shutil.copy2(yml_file_path, destination_file_path)

            time.sleep(5)

            with open(destination_file_path, 'r', encoding='utf-8') as file:
                content = file.readlines()

            with open(destination_file_path, 'w', encoding='utf-8') as file:
                for line in content:
                   
                    if line.strip().startswith('apkFileName:'):
                        
                        current_name_match = re.search(r'apkFileName: (.*)\.apk', line)
                        if current_name_match:
                            
                            current_name = current_name_match.group(1)
                            new_name = f'{current_name}_result.apk'
                            
                            file.write(f'apkFileName: {new_name}\n')
                        else:
                            
                            file.write(line)
                    else:
                        
                        file.write(line)

            command = [apktool_path, "b", destination_path]

            result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == None:
                print("APK successfully built.")
                #print(result.stdout)
                print("---------------------------------------------------------------") 
                result_apk = os.path.join(self.output_directory_path,"dist")
                time.sleep(10)
                try:
                    shutil.move(result_apk, self.output_directory_path)
                    print("Saeve decrypt APK to", self.output_directory_path)
                    print("---------------------------------------------------------------")
                    time.sleep(5)
                    
                    resign_apk_path = os.path.join(self.output_directory_path,"dist",os.path.splitext(os.path.basename(self.original_apk))[0]+"_result.apk" )
                    self.resign_apk(resign_apk_path)
                    return result_apk
                except Exception as e :
                    print(f"An unexpected error occurred while moving repackaged APK: {e}")
                    print("---------------------------------------------------------------")
            else:
                print("APK build failed.")
                print(result.stderr)
                print("---------------------------------------------------------------")
                 
        except FileNotFoundError as e:
            print("File was not found. Please ensure that it is installed and added to your PATH.")
            print("---------------------------------------------------------------")
        except OSError as e:
            print(f"An OS error occurred: {e}")
            print("---------------------------------------------------------------")
        except Exception as e:
            print(f"An unexpected error occurred while repackaging the APK: {e}")
            print("---------------------------------------------------------------")

    def find_lib(self):
        
        so_files = []
        
        for root, dirs, files in os.walk(self.decrypt_extract_to_path):
            for file in files:
                if file.endswith('.so'):
                    so_files.append(os.path.join(root, file))
        
        return so_files

    def print_java_native_functions_with_content(elffile):
        encryption_keywords = ['aes', 'des', 'encrypt', 'decrypt']
        print("Java Native Functions with Encryption Keywords and Content:")
        found_symbols = False

        for section in elffile.iter_sections():
            if hasattr(section, 'iter_symbols'):
                for symbol in section.iter_symbols():
                    if hasattr(symbol, 'entry') and 'st_info' in symbol.entry:
                        if symbol['st_info']['type'] == 'STT_FUNC':
                            symbol_name = symbol.name.lower()
                            if symbol_name.startswith("java_") and any(keyword in symbol_name for keyword in encryption_keywords):
                                found_symbols = True
                                print(f"{symbol.name} - Size: {symbol['st_size']}, Addr: {symbol['st_value']}")
                                symbol_address = symbol['st_value']
                                symbol_size = symbol['st_size']
                                code_section = elffile.get_section_by_name('.text') 
                                if code_section:
                                    offset = symbol_address - code_section['sh_addr']
                                    bytes_data = code_section.data()[offset:offset+symbol_size]
                                    #CODE = bytes_data
                                    #md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
                                    #for i in md.disasm(CODE, 0x1000):
                                    #    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                                    #print(f"Function Content: {bytes_data.hex()}")
                                        
                                else:
                                    print("Code section not found.")
        print("---------------------------------------------------------------")  
        
        if not found_symbols:
            print("No Java native functions with encryption keywords and content found.")

        if not found_symbols:
            print("No Java native functions with encryption keywords found.")

        if not found_symbols:
            print("No encryption related symbols found.")
        return symbol_name

    def find_strings_of_specific_lengths(self, data, lengths):
        strings = []
        result = ""

        for c in data:
            if 32 <= c < 127:
                result += chr(c)
            else:
                if len(result) in lengths:
                    strings.append(result)
                result = ""

        if len(result) in lengths:
            strings.append(result)

        return strings

    def keys_string(self, elffile):
        specific_lengths = {16, 24, 32}
        found_strings = []

        for section in elffile.iter_sections():
            print(f"Section Name: {section.name}")
            try:
                if section.data():
                    strings = self.find_strings_of_specific_lengths(section.data(), specific_lengths)
                    
                    if strings:
                        for string in strings:
                            print(f"Length: {len(string)}, String: {string}")
                            found_strings.append(string)
                    else:
                        print("<No strings of specified lengths found>")
            except Exception as e:
                print(f"<No data or cannot read section: {e}>")
            print("-" * 40)
        
        return found_strings

    def process_so_files(self,so_files_paths):
        all_keys = {}
        for so_file_path in so_files_paths:
            try:
                with open(so_file_path, 'rb') as f:
                    elffile = ELFFile(f)
                    all_keys = self.keys_string(elffile)
                    self.print_java_native_functions_with_content(elffile)
            except FileNotFoundError:
                print(f"The specified file does not exist: {so_file_path}")
            except IOError as e:
                print(f"An I/O error occurred while processing {so_file_path}: {e}")
            except Exception as e:
                print(f"An unexpected error occurred while processing {so_file_path}: {e}")

        return all_keys


    """"""""""""""""""""""""""""""""""""
    """"Resign              APK"""""""""
    """"""""""""""""""""""""""""""""""""

    def resign_apk(self, result_apk):

        keystore_file = os.path.splitext(os.path.basename(self.original_apk))[0]+".keystore"
        alias = os.path.splitext(os.path.basename(self.original_apk))[0]
        repackaged_app = result_apk
        
        # Create the command string.
        command = f"keytool -genkey -v -keystore {keystore_file} -alias {alias} -keyalg RSA -keysize 2048"

        # Run the command using subprocess and handle input
        try:
            process = subprocess.Popen(command, shell=True, text=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate(input="111111\n111111\n" + " \n" * 6+"yes\n")
            print(output)
            if process.returncode == 0:
                print("Key generation successfully. test sign password : 111111")

        except Exception as e:
            print(f"Unknown error occurred: {e}")

        time.sleep(3)

        try:
            command = f"jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore {keystore_file} {repackaged_app} {alias}"
            process = subprocess.Popen(command, shell=True, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate(input="111111\n")
            print(output)
            if process.returncode == 0:
                print("Signing completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error occurred: {e}")
        except Exception as e:
            print(f"Unknown error occurred: {e}")