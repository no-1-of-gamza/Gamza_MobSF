"""
MOBSF REST API Python Requests
"""

import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder


class MobSF_API:
    def __init__(self, server, api_key, file_path):
        self.server = server
        self.api_key = api_key
        self.file_path = file_path
        self.scan_hash = None  

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
        result = response.json()  #
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

