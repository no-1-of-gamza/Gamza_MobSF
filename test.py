import subprocess

def resign_apk():

    keystore_file = "test3.keystore"
    alias = "test3"

    # Create the command string.
    command = f"keytool -genkey -v -keystore {keystore_file} -alias {alias} -keyalg RSA -keysize 2048"
    # keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048

    # Run the command using subprocess and handle input
    try:
        process = subprocess.Popen(command, shell=True, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate(input="111111\n111111\n" + " \n" * 6+"yes\n")
        print(output)
        if process.returncode == 0:
            print("Key generation completed successfully.")
        else:
            print()
            #print(f"Error occurred: {error.decode('utf-8')}")
    except Exception as e:
        print(f"Unknown error occurred: {e}")

    # Create the command string.
    #command = f"jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore {keystore_file} {repackaged_app} {alias}"

    # Run the command using subprocess.
    #try:
    #    subprocess.run(command, shell=True, check=True)
    #    print("Signing completed successfully.")
    #except subprocess.CalledProcessError as e:
    #    print(f"Error occurred: {e}")
    #except Exception as e:
    #    print(f"Unknown error occurred: {e}")

resign_apk()
