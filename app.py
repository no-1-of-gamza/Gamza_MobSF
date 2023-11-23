import sys
import os
import configparser
from mobSF_rest_API import MobSF_API
import subprocess
import requests
import time
from decrypt_apk import APKDecryptor
import shutil
import zipfile
from datetime import datetime
import fnmatch

class Main:
    def __init__(self):
        self.load_config()

    def load_config(self):
        self.config = configparser.ConfigParser()
        config_file_path = os.path.join(os.path.dirname(__file__), 'config.ini')
        
        self.config.read(config_file_path)
        self.mobsf_path = os.path.join(os.path.dirname(__file__), self.config['MobSF']['MobSF'])
        self.server_ip = self.config['SERVER'].get('ServerIP', self.config['DEFAULT']['ServerIP'])
        self.api_key = self.config['API'].get('ApiKey', self.config['DEFAULT']['ApiKey'])
        self.file_path = self.config['FILE'].get('FilePath', self.config['DEFAULT']['FilePath']).split(',')
        self.avm_name = self.config['AVM'].get('AVM_Name', self.config['DEFAULT']['AVM_Name'])
        self.frida_script_path = self.config['Frida'].get('Frida_Script', self.config['DEFAULT']['Frida_Script'])
        self.encryption_method = self.config['Encryption_method'].get('encryption_method', self.config['DEFAULT']['Encryption_method'])   

    def save_config(self):
        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)

    def start(self):
        self.print_welcome()
        self.run_mobsf()
        time.sleep(0.1)
        while True:
            command = input(">>> ").split(" ")
            if command[0] == "":
                pass

            elif command[0] == "exit":
                option = input("Are you sure to exit program? ( XoX ) <yes(default)/no>: ")
                option = option.lower()
                if option == 'no' or option == 'n':
                    continue               
                sys.exit(0)

            elif command[0] == "help":
                self.help()
                
            elif command[0] == "status":
                self.get_status()
            
            elif command[0] == "analysis":
                self.static_analysis()
                self.dynamic_analysis()

            elif command[0] == "static" and len(command) > 1 and command[1] == "analysis":
                self.static_analysis()
            
            elif command[0] == "dynamic" and len(command) > 1 and command[1] == "analysis":
                self.dynamic_analysis()
            
            elif command[0] == "decrypt" and len(command) > 1 and command[1] == "apk":
                self.apk_decryptor()
            
            elif command[0] == "dynamic" and len(command) > 1 and command[1] == "stop":
                self.dynamic_analysis_stop()
            
            elif command[0] == "nested" and len(command) > 1 and command[1] == "check":
                self.add_nested_path()
                        
            else:
                print("\'{}\' is invalid command.\n".format(" ".join(command)))
                self.help()

    def print_welcome(self):
        welcome_message = r"""
            _____   ___  ___  ___ ______  ___
            |  __ \ / _ \ |  \/  ||___  / / _ \
            | |  \// /_\ \| .  . |   / / / /_\ \
            | | __ |  _  || |\/| |  / /  |  _  |
            | |_\ \| | | || |  | |./ /___| | | |
            \____/\_| |_/\_|  |_/\_____/\_| |_/

            ___  ___        _      _____ ______    ___  ______  _____
            |  \/  |       | |    /  ___||  ___|  / _ \ | ___ \|_   _|
            | .  . |  ___  | |__  \ `--. | |_    / /_\ \| |_/ /  | |
            | |\/| | / _ \ | '_ \  `--. \|  _|   |  _  ||  __/   | |
            | |  | || (_) || |_) |/\__/ /| |     | | | || |     _| |_
            \_|  |_/ \___/ |_.__/ \____/ \_|     \_| |_/\_|     \___/
        
                                                                                                                                                                         
        To know how to use, use 'help' command.
        Have a nice time ~ ( 'v' )♡ ~
        """
        print(welcome_message)       
        
    def help(self):
        help = {
            "status": "Show current Status Config",
            "analysis":"Static Analysis and Dynamic Analysis",
            "static analysis":"Static Analysis File and Report to Pdf",
            "dynamic analysis":"Dynamic Analysis, activity, exported activity, tls test",
            "decrypt apk":"Decrypt APK, Find Decrypt Key and Decrypt APK and Repackaging",
            "nested check":"Decompile APK and Find Nested APK",
            "exit": "Exit shell"
        }

        print("usage:", end="\n\n")
        for command in help.keys():
            print("{0:35s}\t{1:s}".format(command, help[command]))
        print()

    def run_mobsf(self):
        run_script_path = os.path.join(self.mobsf_path, 'run.bat')
        if not os.path.exists(run_script_path):
            print(f"Error: Invalid Path - {self.mobsf_path}")
            print("Please run MobSF Manually")
            return  
        process = subprocess.Popen(run_script_path, shell=True, cwd=self.mobsf_path)        
       
        print("MobSF is starting! you can now enter next commands:")

        return process  

    def get_status(self):
        print("---------------------------------------------------------------")      
        if hasattr(self, 'server_ip'):
            print("\nMobSF server IP: {}".format(self.server_ip))
        else:
            print("\nMobSF server IP is not set.")

        if hasattr(self, 'api_key'):
            print("MobSF API KEY: {}".format(self.api_key))
        else:
            print("MobSF API KEY is not set.")

        if hasattr(self, 'file_path'):
            if self.file_path:
                print("Target file path ({}): {}".format(len(self.file_path), ', '.join(self.file_path)))
            else:
                print("Target file path is not set.\n")
        else:
            print("Target file path is not set.\n")
        
        if hasattr(self, 'mobsf_path'):
            print("MobSF Path: {}\n".format(self.mobsf_path))
        else:
            print("MobSF Path: MobSF Path is not set.")

        print("---------------------------------------------------------------")

    def server_is_running(self):
        try:
            response = requests.get(self.server_ip)
            if response.status_code == 200:
                return True
            else:
                print("The server responded with status code:", response.status_code)
                return False
        except requests.ConnectionError:
            print("Failed to connect to the server. Please make sure the MobSF server is running and accessible.")
            return False

    def choose_file_path(self):
        while True:
            if len(self.file_path) > 1:
                print("Multiple files detected. Please select one for analysis:")
                print("---------------------------------------------------------------")
                for idx, path in enumerate(self.file_path):
                    clean_path = path.strip()
                    print(f"{idx + 1}. {clean_path}")
                print("---------------------------------------------------------------")
                selected_index = input(f"Enter the number (1-{len(self.file_path)}) or 'q' to quit: ")

                if selected_index.lower() == 'q':
                    return self.start()

                try:
                    selected_index = int(selected_index) - 1
                    if selected_index < 0 or selected_index >= len(self.file_path):
                        raise ValueError("Selected index is out of range.")

                    selected_file_path = self.file_path[selected_index].strip()

                    if not os.path.isfile(selected_file_path):
                        print(f"The file at {selected_file_path} does not exist. Please try again.")
                    else:
                        return selected_file_path

                except ValueError as e:
                    print(f"Invalid selection: {e}")

            elif self.file_path:
                single_path = self.file_path[0].strip()
                if os.path.isfile(single_path):
                    return single_path
                else:
                    print(f"The file at {single_path} does not exist. Please check your file path.")
                    return None
            else:
                print("No file paths are available.")
                return None
        
    def nested_check(self, selected_file_path):
        print("---------------------------------------------------------------")
        print("Checking nested apk...")
        
        if os.path.exists(selected_file_path) == False:
            print(f"Error: Invalid Path - {selected_file_path}")
            print("---------------------------------------------------------------")
            return
        current_dir_path = os.getcwd()

        zip_file_path = selected_file_path.split('/')[-1] + ".zip"
        shutil.copy(selected_file_path, zip_file_path)

        zip_dir_path = current_dir_path + "\\nested_apk\\analysis"
        if not os.path.exists(zip_dir_path):
            os.makedirs(zip_dir_path, exist_ok=True)
        else:
            print("Directory already exists")
    
        with zipfile.ZipFile(zip_file_path, 'r') as unzip:
            unzip.extractall(zip_dir_path)
    
        apk_files = []
        if os.path.exists(zip_dir_path):
            for root, dirs, files in os.walk(zip_dir_path):
                for file in files:
                    if file.endswith('.apk'):
                        file_path = os.path.join(root, file)
                        apk_files.append(file_path)
        else:
            print("Directory does not exist")
        
        if apk_files:
            print(len(apk_files), "nested apks were found.")
            print("---------------------------------------------------------------")
            return apk_files
        else:
            print("nested apk was not found.")
        print("---------------------------------------------------------------")
    
    def static_analysis(self):
        print("---------------------------------------------------------------")
        print("[Static analysis start...]")

        if not self.server_is_running():
            print("MobSF Server is not running. Please start the server before analysis.")
            print("---------------------------------------------------------------")
            return

        time.sleep(2)
        
        selected_file_path = self.choose_file_path()
        
        mobsf_api = MobSF_API(self.server_ip, self.api_key, selected_file_path)

        if self.server_is_running():
            print("MobSF Server is Working!")
            response_data = mobsf_api.upload()
            if response_data:
                mobsf_api.scan()
                mobsf_api.json_resp()
                mobsf_api.pdf()
        else:
            print("Server is not running. Please check the MobSF server settings and ensure it is running before trying again.")
            print("---current seting---")
            self.get_status(self)

        nested_check_result=self.nested_check(selected_file_path)
        print("---------------------------------------------------------------")

        if nested_check_result:
                for index, apk in enumerate(nested_check_result):
                    print(f'[{index+1}/{len(nested_check_result)}] - {apk}')
                    mobsf_api = MobSF_API(self.server_ip, self.api_key, apk)
                    print("[Nested APK Static analysis start...]")
                    print("Proceed Automatically Static Reporting nested apk file")
                    response_data = mobsf_api.upload()
                    if response_data:
                        mobsf_api.scan()
                        mobsf_api.json_resp()
                        mobsf_api.pdf()
                    else:
                        print("Server is not running. Please check the MobSF server settings and ensure it is running before trying again.")
                        print("---current seting---")
                        self.get_status(self)
                        print('Selected nested apk: ', apk)
                    print("---------------------------------------------------------------")

    def run_emulator(self):
        print("---------------------------------------------------------------")
        print("[Running emnulator start]")

        if self.server_is_running():
            print("MobSF Server Checking...")
            print("MobSF Server is Working!")
        else :
            print("Server is not running. Please check the MobSF server settings and ensure it is running before trying again.")
            print("---current setting---")
            self.get_status(self)

        command = f'emulator -avd {self.avm_name} -writable-system -no-snapshot'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        if process.returncode is not None and process.returncode != 0:
            print(f"Emulator failed to start with return code {process.returncode}.")
            print("---------------------------------------------------------------")
            return
        else:
            print("Emulator started successfully.")
            print("---------------------------------------------------------------")
            return 

    def dynamic_analysis_setting(self):

        selected_file_path = self.choose_file_path()
        
        self.run_emulator()
        print("[Dynamic analysis start...]")
        print("Please wait to set dynamic analysis")

        time.sleep(20)

        mobsf_api = MobSF_API(self.server_ip, self.api_key, selected_file_path)

        response_data = mobsf_api.upload()

        if response_data:
            max_retries = 3
            attempts = 0

            while attempts < max_retries:
                try:
                    print(f"Attempting dynamic analysis, try {attempts+1} of {max_retries}")
                    analysis_setting_result = mobsf_api.dynamic_analysis_setting()

                    if 'error' in analysis_setting_result and analysis_setting_result['error'] == "Dynamic Analysis Failed.":
                        print("Dynamic Analysis Failed, retrying...")
                        attempts += 1
                        time.sleep(10)          
                    else:
                        print("Dynamic Analysis Setting is Successful.")
                        break
                except Exception as e:
                    print("An exception occurred during dynamic analysis.")
                    print(e)
                    attempts += 1                
                    time.sleep(10)
                    print("---------------------------------------------------------------")
            
            if attempts == max_retries:
                print("Dynamic analysis failed after maximum retries.")
                print("Please check the Emulator settings and ensure it is running before trying again.") 
                print("---------------------------------------------------------------")     
                return
            
            print("---------------------------------------------------------------")
            return selected_file_path

    def dynamic_analysis_stop(self):
        mobsf_api = MobSF_API(self.server_ip, self.api_key, self.file_path)
        mobsf_api.dynamic_analysis_stop()
        print("Dynamic analysis is stop.")
        return

    def dynamic_analysis(self):
        print("---------------------------------------------------------------")
        selected_file_path = self.dynamic_analysis_setting()
        if not selected_file_path:
            print("invalid file path.")
            print("---------------------------------------------------------------")
            return
    
        mobsf_api = MobSF_API(self.server_ip, self.api_key, selected_file_path)
        mobsf_api.upload()
        
        try:
            with open(self.frida_script_path, 'r') as file:
                frida_code = file.read()
        except Exception as e:
            print(f"Error reading the Frida script: {e}")
            return
        try:
            mobsf_api.frida_instrument(default_hooks=True, frida_code=frida_code)
            print("Performing Frida Instrumentation")
        except Exception as e:
            print("Please check Frida Code")

        mobsf_api.frida_get_dependencies_api()

        mobsf_api.dynamic_analysis_activity_test("activity")
        mobsf_api.dynamic_analysis_activity_test("exported")
        mobsf_api.frida_api_monitor()

        mobsf_api.frida_instrument(default_hooks=True, frida_code=frida_code)
        mobsf_api.dynamic_ttl_ssl_test()
        mobsf_api.frida_view_logs()

        time.sleep(20)
        mobsf_api.dynamic_analysis_stop()
        mobsf_api.dynamic_jason_report()
        print("---------------------------------------------------------------")
        return

    def apk_decryptor(self):
        print("---------------------------------------------------------------")
        print("Decrypt APK")
        apk_path = self.choose_file_path()
        decryptor = APKDecryptor(apk_path, self.encryption_method)
        apk_backup_path=decryptor.backup_apk_file()
        decryptor.unzip_apk()
        so_files_paths = decryptor.find_lib()
        found_keys = decryptor.process_so_files(so_files_paths)
        print("so_files_path :",so_files_paths)
        print("found_keys :",found_keys)
        decrypted_data = decryptor.decrypt_files(found_keys)
        decryptor.save_decrypted_data(decrypted_data)
        time.sleep(5)
        print(apk_backup_path)
        output_dir = decryptor.decompile_apk(apk_backup_path)
        time.sleep(10)
        print("output_dir: ",output_dir)
        result_apk = decryptor.repackaging_apk(output_dir)
        time.sleep(5)
        if result_apk:
            self.file_path.append(result_apk)
            print("The result apk file path has been added. Please proceed with the analysis.")
    
    def add_nested_path(self):
        print("---------------------------------------------------------------")
        date_time_format = datetime.now().strftime("%Y%m%d_%H%M")
        
        selected_file_path = self.choose_file_path()
        print("---------------------------------------------------------------")
        
        if os.path.exists(selected_file_path) == False:
            print(f"Error: Invalid Path - {selected_file_path}")
            print("---------------------------------------------------------------")
            return
        current_dir_path = os.getcwd()

        zip_file_path = selected_file_path.split('/')[-1] + ".zip"
        shutil.copy(selected_file_path, zip_file_path)

        zip_dir_path = current_dir_path + "\\nested_apk"
        zip_dir_path = os.path.join(zip_dir_path, date_time_format)
        if not os.path.exists(zip_dir_path):
            os.makedirs(zip_dir_path, exist_ok=True)
        else:
            print("Directory already exists")
    
        with zipfile.ZipFile(zip_file_path, 'r') as unzip:
            unzip.extractall(zip_dir_path)
    
        apk_files = []
        if os.path.exists(zip_dir_path):
            for root, dirs, files in os.walk(zip_dir_path):
                for file in files:
                    if file.endswith('.apk'):
                        file_path = os.path.join(root, file)
                        apk_files.append(file_path)
        else:
            print("Directory does not exist")
        
        if apk_files:
            print(len(apk_files), "nested apks were found.")
            for apk in apk_files:
                self.file_path.append(apk)
            print("The nested apk file path has been added. Please proceed with the analysis.")
            print("---------------------------------------------------------------")
        else:
            print("nested apk was not found.")
            print("---------------------------------------------------------------")

        
if __name__ == "__main__":
    main = Main()
    main.start()
