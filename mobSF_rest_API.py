"""
MOBSF REST API Python Requests
"""

import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import time


class MobSF_API:
    def __init__(self, server, api_key, file_path):
        self.server = server
        self.api_key = api_key
        self.file_path = file_path
        self.scan_hash = None  

    """"""""""""""""""""""""""""""""""""
    """""""""Static    Analysis"""""""""
    """"""""""""""""""""""""""""""""""""
    
    def upload(self):
        """Upload File"""
        print("Uploading file...")
        multipart_data = MultipartEncoder(
            fields={'file': (self.file_path, open(self.file_path, 'rb'), 'application/octet-stream')}
        )
        headers = {
            'Content-Type': multipart_data.content_type,
            'Authorization': self.api_key
        }
        response = requests.post(f'{self.server}/api/v1/upload', data=multipart_data, headers=headers)
        result = response.json() 
        if 'hash' in result:
            self.scan_hash = result['hash']  
        print(response.text)
        return result

    def scan(self):
        """Scan the file"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        print("Scanning file...")
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/scan', data=data, headers=headers)
        print(response.text)

    def pdf(self):
        """Generate PDF Report"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        print("Generating PDF report...")
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/download_pdf', data=data, headers=headers, stream=True)
        if response.status_code == 200:
            with open("report.pdf", 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            print("Report saved as report.pdf")
        else:
            print("Failed to download PDF report.")

    def json_resp(self):
        """Generate JSON Report"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        print("Generating JSON report...")
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/report_json', data=data, headers=headers)
        print(response.text)

    def delete(self):
        """Delete Scan Result"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        print("Deleting Scan...")
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/delete_scan', data=data, headers=headers)
        print(response.text)
        




    """"""""""""""""""""""""""""""""""""
    """""""""Dynamic Analysis"""""""""
    """"""""""""""""""""""""""""""""""""

    def dynamic_analysis_setting(self):
        """Dynamic analysis"""
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/dynamic/start_analysis', data=data, headers=headers)
        print(response.text)
        reponse_json=response.json()
        return reponse_json

    def dynamic_analysis_stop(self):
        """Dynamic analysis stop"""
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/dynamic/stop_analysis', data=data, headers=headers)
        print(response.text)


    def dynamic_analysis_activity_start(self,activity=''):
        """Dynamic analysis Activity Tester API"""
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash,
                'activity' : activity}
        response = requests.post(f'{self.server}/api/v1/android/start_activity', data=data, headers=headers)
        print(response.text)


    def dynamic_jason_report(self):
        """Dynamic Json report"""
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/dynamic/report_json', data=data, headers=headers)
        print(response.text)
        reponse_json=response.json()
        return reponse_json



    """"""""""""""""""""""""""""""""""""
    """""""""""""Frida"""""""""""""
    """"""""""""""""""""""""""""""""""""

    def frida_instrument(self, default_hooks=True, auxiliary_hooks='', frida_code='', class_name=None, class_search=None, class_trace=None):
        """Perform Frida Instrumentation"""
        if not self.scan_hash:
            print("No file uploaded or hash not found for Frida Instrumentation")
            return
        
        headers = {'Authorization': self.api_key }

        data = {
            'hash': self.scan_hash,
            'default_hooks': default_hooks,
            'auxiliary_hooks': auxiliary_hooks,
            'frida_code': frida_code
        }

        if class_name is not None:
            data['class_name'] = class_name
        if class_search is not None:
            data['class_search'] = class_search
        if class_trace is not None:
            data['class_trace'] = class_trace

        response = requests.post(f'{self.server}/api/v1/frida/instrument', headers=headers, data=data)

        print(response.text)


    




