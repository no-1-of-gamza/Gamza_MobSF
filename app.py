import signal
import sys
import os
import time
import ipaddress
import requests
import configparser
from mobSF_rest_API import MobSF_API

class Main:
    def __init__(self):
        self.load_config()

    def load_config(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.server_ip = self.config['SERVER'].get('ServerIP', self.config['DEFAULT']['ServerIP'])
        self.api_key = self.config['API'].get('ApiKey', self.config['DEFAULT']['ApiKey'])
        self.file_path = self.config['FILE'].get('FilePath', self.config['DEFAULT']['FilePath'])

    def save_config(self):
        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)

    def start(self):

        self.print_welcome()
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

    def static_analysis(self):
        """Perform static analysis using MobSF REST API"""
        print("Static analysis start...")
        mobsf_api = MobSF_API(self.server_ip, self.api_key, self.file_path)

        response_data = mobsf_api.upload()
        if response_data:
            mobsf_api.scan(response_data)
            mobsf_api.json_resp(response_data)
            mobsf_api.pdf(response_data)
            mobsf_api.delete(response_data)

if __name__ == "__main__":
    main = Main()
    main.start()
