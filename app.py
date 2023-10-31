import signal
import sys
import os
import time

class Main:
    def __init__(self):

        print("\nInitializing sandbox...please wait......")

    def start(self):

        self.print_welcome()

        while True:
            command = input(">>> ").split(" ")
            if command[0] == "":
                pass

            elif command[0] == "exit":
                option = input("Are you sure to exit program? Your snapshots and logs will be deleted. <yes(default)/no>: ")
                option = option.lower()
                if option == 'no' or option == 'n':
                    continue
                
                self.exit()

            elif command[0] == "help":
                self.help()
                
            elif command[0] == "status":
                self.get_status()

            elif command[:2] == ["set", "vm"]:
                if len(command) < 3:
                    print("set vm: invalid command\n")
                    self.help()
                    continue
                
                vm_name = command[2]
                self.set_vm(vm_name)
                
            elif command[:2] == ["set", "malware"]:
                if len(command) < 3:
                    print("set malware: invalid command\n")
                    self.help()
                    continue
                
                malware_path = command[2]
                self.set_malware(malware_path)

            elif command[:2] == ["list", "vm"]:
                self.list_vm()
            
            elif command[:2] == ["list", "snapshot"]:
                if len(command) < 3:
                    print("list snapshot: invalid command\n")
                    self.help()
                    continue
                
                vm_name = command[2]
                self.list_snapshot(vm_name)
            
            elif command[:2] == ["take", "snapshot"]:
                if len(command) < 3:
                    print("take snapshot: invalid command\n")
                    self.help()
                    continue
                
                if command[2] == "init_snapshot":
                    print("take snapshot: cannot use the init snapshot name\n")
                    continue

                snapshot_name = command[2]
                self.take_snapshot(snapshot_name)

            elif command[0] == "rollback":
                if len(command) < 2:
                    print("rollback: invalid command\n")
                    self.help()
                    continue

                snapshot_name = command[1]
                self.rollback_snapshot(snapshot_name)
                
            elif command[:2] == ["start", "analyze"]:
                self.start_analyze()

            elif command[:2] == ["stop", "analyze"]:
                self.stop_analyze()

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
            "set vm [vm name]": "Set target Virtual Machine's name",
            "set malware [exe path]": "Set target malware execution file's path",
            "list vm": "List available Virtual Machine",
            "list snapshot [vm name]": "List saved snapshot",
            "take snapshot [new snapshot name]": "Take snapshot of current analyzing status",
            "rollback [snapshot name]": "Rollback current vm to specific snapshot",
            "start analyze": "Start analyze based on set information(vm, malware)",
            "stop analyze": "Stop analyze based on set information(vm, malware)",
            "exit": "Exit shell"
        }

        print("usage:", end="\n\n")
        for command in help.keys():
            print("{0:35s}\t{1:s}".format(command, help[command]))
        print()
            



if __name__ == "__main__":
    main = Main()
    main.start()
