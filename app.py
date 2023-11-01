import sys
import os
import configparser
from mobSF_rest_API import MobSF_API
import subprocess
import requests
import threading
import time

class Main:
    def __init__(self):
        self.load_config()

    def load_config(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.mobsf_path = self.config['MobSF'].get('MobSF', self.config['DEFAULT']['MobSF'])
        self.server_ip = self.config['SERVER'].get('ServerIP', self.config['DEFAULT']['ServerIP'])
        self.api_key = self.config['API'].get('ApiKey', self.config['DEFAULT']['ApiKey'])
        self.file_path = self.config['FILE'].get('FilePath', self.config['DEFAULT']['FilePath'])
        self.avm_name = self.config['AVM'].get('AVM_Name', self.config['DEFAULT']['AVM_Name'])


    def save_config(self):
        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)

    def start(self):

        self.print_welcome()
        self.run_mobsf()

        while True:
            command = input(">>> ").split(" ")
            if command[0] == "":
                pass

            elif command[0] == "exit":
                option = input("Are you sure to exit program? <yes(default)/no>: ")
                option = option.lower()
                if option == 'no' or option == 'n':
                    continue
                
                self.exit()

            elif command[0] == "help":
                self.help()
                
            elif command[0] == "status":
                self.get_status()
            
            elif command[0] == "static" and len(command) > 1 and command[1] == "analysis":
                self.static_analysis()
            
            elif command[0] == "dynamic" and len(command) > 1 and command[1] == "analysis":
                self.dynamic_analysis()

            else:
                print("\'{}\' is invalid command.\n".format(" ".join(command)))
                self.help()

    def print_welcome(self):
        welcome_message = """
        _____   ___  ___  ___ ______  ___  
        |  __ \ / _ \ |  \/  ||___  / / _ \ 
        | |  \// /_\ \| .  . |   / / / /_\ \\
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
        Have a nice time ~
        """
        
        print(welcome_message)

    def exit(self):
        sys.exit(0)        
        
    def help(self):
        help = {
            "status": "Show current target vm/malware",
            "static analysis":"Static Analysis File and Report to Pdf",
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
       
        print("MobSF is starting... you can now enter next commands:\n")
        return process  

    def get_status(self):       
        if hasattr(self, 'server_ip'):
            print("\nMobSF server IP: {}".format(self.server_ip))
        else:
            print("\nMobSF server IP is not set.")

        if hasattr(self, 'api_key'):
            print("MobSF API KEY: {}".format(self.api_key))
        else:
            print("MobSF API KEY is not set.")

        if hasattr(self, 'file_path'):
            if self.file_path is None:
                print("Target file path is not set.\n")
            elif isinstance(self.file_path, str):
                print("Target APK path: {}\n".format(self.file_path))
            else:
                print("Target file path is not set.\n")
        else:
            print("Target file path is not set.\n")
        
        if hasattr(self, 'mobsf_path'):
            print("\nMobSF Path: {}".format(self.mobsf_path))
        else:
            print("\nMobSF Path is not set.")

    def server_is_running(self):
        """Check if the MobSF server is running."""
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
        

    def static_analysis(self):
        print("Static analyze start...")
        mobsf_api = MobSF_API(self.server_ip, self.api_key, self.file_path)

        if self.server_is_running():
            print("MobSF Server is Working!")
            response_data = mobsf_api.upload()
            if response_data:
                mobsf_api.scan()
                mobsf_api.json_resp()
                mobsf_api.pdf()
                mobsf_api.delete()
        else:
            print("Server is not running. Please check the MobSF server settings and ensure it is running before trying again.")
            print("---current seting---")
            self.get_status(self)

    
    def wait_for_emulator_to_start(self, process):
        last_line = None
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                last_line = line.strip()
                print(last_line)
                if "INFO | Revoking microphone permissions for Google App." in last_line:
                    print("Emulator started successfully with the desired message.")

        if process.returncode and process.returncode != 0:
            print(f"Emulator failed to start with return code {process.returncode}.")

    def dynamic_analysis(self):
        print("Dynamic analysis start")
        if self.server_is_running():
            print("MobSF Server Checking...")
            print("MobSF Server is Working!")
        else :
            print("Server is not running. Please check the MobSF server settings and ensure it is running before trying again.")
            print("---current setting---")
            self.get_status(self)

        command = f'emulator -avd {self.avm_name} -writable-system -no-snapshot'
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=self.mobsf_path)
            thread = threading.Thread(target=self.wait_for_emulator_to_start, args=(process,))
            thread.start()
            print("Emulator is starting you can now enter next commands:\n")
        except Exception as e:
            print("Fail to Start Emulator. Run Emulator Manually or Check your option")
            print(e)
               
            
if __name__ == "__main__":
    main = Main()
    main.start()
