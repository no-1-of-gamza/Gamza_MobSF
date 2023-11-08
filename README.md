# Gamza_MobSF

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


You can use MobSF API in Python CLI

**Automatically Run Server, Analysis, Make Report**

## Usage
0. Download MobSF and Install

https://github.com/MobSF/Mobile-Security-Framework-MobSF

1. Set Config.ini Your Information
   
  ![image](https://github.com/no-1-of-gamza/Gamza_MobSF/assets/68416184/4a7c0169-2f0b-4b5d-b60c-d2dee73f3ff5)


2. Run Program

       app.py

### Static Analysis

Input CLI "static analysis", Wait few minutes.

       >> static analysis

You can get a report.pdf about your apk.
![image](https://github.com/no-1-of-gamza/Gamza_MobSF/assets/68416184/1a2c1c62-4959-488e-9101-4ae26a10bd15)

### Dynamic Analysis

Input CLK "dynamic analysis", Wait few minutes.
It takes more time than static analysis and Please check your AVD *(Android Studio, GenyMotion)

Analyze Activities, Exported Activities, TTL Test and Make Report.

       >> dynamic analysis
![image](https://github.com/no-1-of-gamza/Gamza_MobSF/assets/68416184/ca164902-e08e-4891-8adc-a3aaecedeb70)

You can get a report.jason about your apk.
![image](https://github.com/no-1-of-gamza/Gamza_MobSF/assets/68416184/6e032a2d-602c-41c4-b139-fea161f62883)

### Decrypt APK

Input CLK "decrypt apk", Wait few minutes.

       >> decrypt apk

Decrypt APK If .dex file encrypted and Repackaging to APK file

![image](https://github.com/no-1-of-gamza/Gamza_MobSF/assets/68416184/be562e86-98cb-465d-8253-74ccdc9e581b)
![image](https://github.com/no-1-of-gamza/Gamza_MobSF/assets/68416184/72be5b18-6e6b-485d-8c0f-c147348c61a3)

Decrypt APK : unzip APK include Decrypt dex file 

Original APK : unzip APK original

Original [APK Name].apk : original your apk, just copied

[APK Name] : Original Zip APK

### Demonstration video
https://youtu.be/c9Jxb_oO1Ac
