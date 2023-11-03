"""
MOBSF REST API Python Requests
"""

import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import time
from datetime import datetime

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
        print("Uploading File : ",response.text)
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
        print("Scanning File : ",response.text)

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
            current_time = datetime.now()
            date_str = current_time.strftime("%Y-%m-%d")
            with open(f"static_report_{self.scan_hash}_{date_str}.pdf", 'wb') as f:
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
        #print(response.text)

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
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/dynamic/start_analysis', data=data, headers=headers)
        print("Dynamic Analysis Setting : ",response.text)
        reponse_json=response.json()
        return reponse_json

    def dynamic_analysis_stop(self):
        """Dynamic analysis stop"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/dynamic/stop_analysis', data=data, headers=headers)
        print("Dynamic Analysis Stop : ",response.text)


    def dynamic_analysis_activity_start(self,activity=''):
        """Dynamic analysis Activity Tester API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash,
                'activity' : activity}
        response = requests.post(f'{self.server}/api/v1/android/start_activity', data=data, headers=headers)
        print("Dynamic Analysis Activity Start : ",activity,response.text)

    def dynamic_ttl_ssl_test(self):
        """Dynamic analysis TLS/SSL Security Tester API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/android/tls_tests', data=data, headers=headers)
        print("Dynamic analysis TLS/SSL Security Tester : ",response.text)


    def dynamic_jason_report(self):
        """Dynamic Json report"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/dynamic/report_json', data=data, headers=headers)
        response_json = response.json()
        #print(json.dumps(response_json, indent=4))
        current_time = datetime.now()
        date_str = current_time.strftime("%Y-%m-%d")
        filename = f"dynamic_report_{self.scan_hash}_{date_str}.json"
        
        with open(filename, 'w') as json_file:
            json.dump(response_json, json_file, indent=4)
        
        print(f"JSON report saved to {filename}")
    
        return response_json
    
    def dynamic_view_source(self, type):
        """Dynamic Analysis View Source API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash,
                'file': self.file_path,
                'type':type}
        response = requests.post(f'{self.server}/api/v1/dynamic/view_source', data=data, headers=headers)
        response_json = response.json()
        #print(json.dumps(response_json, indent=4))

        filename = f"dynamic_report_{self.scan_hash}.json"
        
        with open(filename, 'w') as json_file:
            json.dump(response_json, json_file, indent=4)
        
        print(f"JSON report saved to {filename}")
    
        return response_json




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
        print("Perform Frida Instrumentation : ",response.text)

    def frida_api_monitor(self):
        """Frida API Monitor API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/frida/api_monitor', data=data, headers=headers)
        print(response.text)

    def frida_get_dependencies_api(self):
        """Frida Get Runtime Dependencies API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/frida/api_monitor', data=data, headers=headers)
        print("Frida Get Runtime Dependencies : ",response.text)

    def frida_view_logs(self):
        """Frida View Logs API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/frida/logs', data=data, headers=headers)
        print("Frida View Logs : ",response.text)
    
    def frida_list_scripts(self):
        """Frida List Scripts API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash}
        response = requests.post(f'{self.server}/api/v1/frida/list_scripts', data=data, headers=headers)
        print(response.text)

    def frida_get_script(self, scripts):
        """Frida Frida Get Script API"""
        if not self.scan_hash:
            print("No file uploaded or hash not found")
            return
        headers = {'Authorization': self.api_key}
        data = {'hash': self.scan_hash,
                'scripts[]':scripts}
        response = requests.post(f'{self.server}/api/v1/frida/list_scripts', data=data, headers=headers)
        print("Frida Frida Get Script : ",response.text)




