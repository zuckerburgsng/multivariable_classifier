import requests
import os
import hashlib
import json
import time
import math
import pandas as pd
import csv

# import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
from selenium import webdriver
from androguard.misc import AnalyzeAPK

test_apk_set_dir = './test_apk_dump'

### Free api_key:
# 3522986cbd570a5581ff04148308b53b2098389ad4944ef2118f4505cbb3aa2b
#2ed918c8fda6876a4a586277b53af11ccb735f19c9b52e0073fd053e50637296
VT_api_key = 'e8b97c527619fc6b432935f41c83d3b3cf258592a3d1e8f10aad171192e4f427'
spacer = '============================================================================================================================='
dataset_csv_path = './combined_data.csv'

def check_file_size(file_dir):
    file_stat = os.stat(file_dir)
    #print('File size: {s}'.format(s= file_stat.st_size))
    return file_stat.st_size

def hash_file(filename):
   """"This function returns the SHA-1 hash
   of the file passed into it"""
   # make a hash object
   h = hashlib.sha1()
   # open file for reading in binary mode
   with open(filename,'rb') as file:
       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           chunk = file.read(1024)
           h.update(chunk)
   # return the hex representation of digest
   return h.hexdigest()

def get_file_lists(apk_dump_dir):
    apk_file_lists_dir = {'file_path':[],'file_name':[]}
    for file in os.listdir(apk_dump_dir):
        if file.endswith('.apk'):
            apk_file_lists_dir['file_path'].append(os.path.join(apk_dump_dir,file))
            apk_file_lists_dir['file_name'].append(file)
    return apk_file_lists_dir

def hash_file_list(full_file_name_list):
    hash_list = []
    for file in full_file_name_list:
        hash_list.append(hash_file(file))
    return hash_list

def get_files_hash(file_path_list):
    confirm_hash = input('Start hashing {n} files? [Y/N]: '.format(n =len(file_path_list)))
    if confirm_hash.lower() == 'y':
        hash_list = hash_file_list(file_path_list)
        print("Completed Hashing ")
        return hash_list
    elif confirm_hash.lower() == 'n':
        return print('Hashing cancelled')
    else:
        print('Please select only [Y/N]')
        return get_files_hash(file_path_list)
    
def get_VT_report_from_hash(hash):
    url = "https://www.virustotal.com/api/v3/files/{h}".format(h=hash)
    headers = {
    "accept": "application/json",
    "x-apikey": VT_api_key
    }
    response = requests.get(url, headers=headers)
    return response

def get_upload_link():
    print('Getting upload URL...')
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_api_key
    }
    response = requests.get(url, headers=headers)
    url = json.loads(response.text)['data']
    print('Get upload URL: SUCCESS')
    return url

def upload_small_file_to_VT(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    files = { "file": (file_path, open(file_path, "rb"), "application/vnd.android.package-archive") }
    headers = {
        "accept": "application/json",
        "x-apikey": VT_api_key    
        }
    print('Uploading file to VT...')
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        print('Upload file to VT: SUCCESS')
        return response.text
    else: 
        print('Uploading file failed\nError code: {}'.format(response.status_code))
        return None

def upload_big_file_to_VT(file_path,fresh_url):
    url = fresh_url
    files = { "file": (file_path, open(file_path, "rb"), "application/vnd.android.package-archive") }
    headers = {
        "accept": "application/json",
        "x-apikey": VT_api_key    
        }
    print('Uploading file to VT...')
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        print('Upload file to VT: SUCCESS')
        return response.text
    else: 
        print('Uploading file failed\nError code: {code}'.format(code = response.status_code))
        return None

def scrape_online_apk_tool(file_path):
    apktool_url = 'https://www.sisik.eu/apk-tool'
    driver = webdriver.Firefox()
    driver.get(apktool_url)
    time.sleep(2)
    driver.find_element(By.ID, 'file-input').send_keys(file_path)
    time.sleep(1)
    if driver.find_element(By.ID, 'apk-tool-error').get_attribute('style')=='display: block;':
        print('Error: file cannot be analysed by online apktool')
        return None
    raw_manifest = driver.find_element(By.ID, 'android-manifest').text 
    soup = BeautifulSoup(raw_manifest,'lxml')
    permissions = soup.find_all('uses-permission')
    perm_list = []
    for tag in permissions:
        perm = check_android_perm(tag.get('android:name'))
        perm_list.append(perm)
    return perm_list

def get_permissions(input_json_text):
    data = json.loads(input_json_text)
    type_description = data['data']['attributes']['type_description']
    if type_description == 'Android':
        permission_list = []
        try:
            permissions = data['data']['attributes']['androguard']['permission_details']
            for perm in permissions:
                android_perm = check_android_perm(perm)
                if type(android_perm) == str:
                    permission_list.append(android_perm)
            print(permission_list)
            return permission_list
        except:
            print("VirusTotal unable to extract permission info\nTrying online APKtool")
            return None
    else:
        print('ERROR: file type not APK')
        return None

def check_android_perm(perm_name):
    substring = 'android.permission.'
    if perm_name.startswith(substring) == True:
        return remove_prefix(perm_name,substring)
    else:
        return None
    
def remove_prefix(s: str, prefix: str) -> str:
    """Replicate behavior of str.removeprefix() for Python versions < 3.9"""
    if s.startswith(prefix):
        return s[len(prefix):]
    return s

def check_malicious(input_json_text,threshold):
    data = json.loads(input_json_text)
    n_malicious = data['data']['attributes']['last_analysis_stats']['malicious']
    n_undetected = data['data']['attributes']['last_analysis_stats']['undetected']
    if n_undetected <=15:
        print('ERROR:\nAnalysis not through\nNumber of Antivirus scanned: {n}\nTry again later'.format(n = n_undetected))
    else:
        if n_malicious >= threshold:
            return True
        else:
            return False

def get_upload_link():
    print('Getting upload URL...')
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_api_key
    }
    response = requests.get(url, headers=headers)
    url = json.loads(response.text)['data']
    print('Get upload URL: SUCCESS')
    return url            

def upload_small_file_to_VT(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    files = { "file": (file_path, open(file_path, "rb"), "application/vnd.android.package-archive") }
    headers = {
        "accept": "application/json",
        "x-apikey": VT_api_key    
        }
    print('Uploading file to VT...')
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        print('Upload file to VT: SUCCESS')
        return True
    else: 
        print('Uploading file failed\nError code: {}'.format(response.status_code))
        return False

def upload_big_file_to_VT(file_path,fresh_url):
    url = fresh_url
    files = { "file": (file_path, open(file_path, "rb"), "application/vnd.android.package-archive") }
    headers = {
        "accept": "application/json",
        "x-apikey": VT_api_key    
        }
    print('Uploading file to VT...')
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        print('Upload file to VT: SUCCESS')
        return True
    else: 
        print('Uploading file failed\nError code: {code}'.format(code = response.status_code))
        return False

def get_dataset_headers_as_dict(dataset_csv_fp):
    # Read the CSV file
    data = pd.read_csv(dataset_csv_fp, nrows=0)  # Read only the first row to get the column names
    # Get the column names
    headers = data.columns.tolist()
    # Create a dictionary where the keys are the headers and the values are None
    header_dict = dict.fromkeys(headers, None)
    return header_dict

def write_perms_to_dict(header_dict,permissions_list,file_name,malicious_file):
    for key in header_dict.keys():
        if key == 'Name':
            header_dict[key] = file_name
        elif key == 'Classification':
            if malicious_file == True:
                header_dict[key] = 'Malicious'
            elif malicious_file == False:
                header_dict[key] = 'Benign'
        else:
            if key in permissions_list:
                header_dict[key]= 1
            else:
                header_dict[key]= 0
    return header_dict

def write_perms_dict_to_csv(dataset_path,new_csv_path,perm_dict):
    df = pd.read_csv(dataset_path)
    column_names = df.columns.tolist()
    # Check if file exists
    if not os.path.isfile(new_csv_path):
        with open(new_csv_path, 'w', newline='') as write_obj:
            csv_writer = csv.DictWriter(write_obj, fieldnames = column_names)
            csv_writer.writeheader()
    with open(new_csv_path, 'a', newline='') as f:
        # Create a writer object with the column names from the existing file
        writer = csv.DictWriter(f, fieldnames=column_names)
        # Re-order the header_dict according to column_names
        ordered_dict = {k: perm_dict.get(k, '') for k in column_names}
        # Append the dictionary as a new row
        writer.writerow(ordered_dict)
    print("Completed generating dataset")

def append_apk_analysis_data(dataset_fp,apk_perms,apk_name,malicious_file,new_csv_name):
    dataset_headers = get_dataset_headers_as_dict(dataset_fp)
    perm_dict = write_perms_to_dict(dataset_headers,apk_perms,apk_name,malicious_file)
    write_perms_dict_to_csv(dataset_fp,new_csv_name,perm_dict)

def extract_permissions(apk_path):
    apk,d,dx = AnalyzeAPK(apk_path)
    permissions = apk.get_permissions()
    return permissions

def analyse_file(hash, file_path, mal_threshold):
    VT_response = get_VT_report_from_hash(hash)
    permissions_list = get_permissions(VT_response.text) or extract_permissions(file_path)
    file_malicious = check_malicious(VT_response.text, mal_threshold)
    print('File is malicious' if file_malicious else "File is benign")
    return permissions_list, file_malicious

def analyse_files(apk_dir, mal_threshold, dataset_path):
    file_lists = get_file_lists(apk_dir)
    file_path_list = file_lists['file_path']
    file_name_list = file_lists['file_name']
    file_hash_list = get_files_hash(file_path_list)
    
    if input('\nStart analysising {n} files? [Y/N]: '.format(n = len(file_hash_list))).lower() != 'y':
        return print('Analysis cancelled')

    save_csv_file_name = input('Save csv file as (input name without .csv): ')+'.csv'
    
    for hash in file_hash_list:
        apk_file_name = file_name_list[file_hash_list.index(hash)]
        print('{line}\nSha1 HASH: {h}\n{line}\nSearching VirusTotal Database...'.format(line = spacer, h = hash))
        
        VT_response = get_VT_report_from_hash(hash)
        if VT_response.status_code == 200:
            print('SUCCESS: HASH found in VirusTotal Database')
            permissions_list, file_malicious = analyse_file(hash, file_path_list[file_hash_list.index(hash)], mal_threshold)
        elif VT_response.status_code == 404:
            print('FAILED: HASH not found in VirusTotal Database')
            time.sleep(1)
            file_path = file_path_list[file_hash_list.index(hash)]
            file_size_MB = math.ceil(check_file_size(file_path)/1000000)
            print('File size: {size} MB'.format(size = file_size_MB))
            
            if file_size_MB <= 29:
                print('File is smaller than 32 MB')
                upload_response = upload_small_file_to_VT(file_path)
            elif 29< file_size_MB <= 630:
                print('File is larger than 32 MB')
                upload_response = upload_big_file_to_VT(file_path, get_upload_link())
            else:
                print('ERROR: File is too large\nPlease limit file size to 650MB')
                continue
            
            if upload_response:
                print('File analysing...\nPATIENCE IS A VIRTUE')
                while True:
                    time.sleep(300)
                    try:
                        permissions_list, file_malicious = analyse_file(hash, file_path, mal_threshold)
                        break
                    except:
                        print("File is still analysing\nWaiting for another 5 minutes")
            else:
                print('ERROR: Uploading file failed\nFile name: {name}\nTry to upload file manually using VirusTotal GUI'.format(name= file_path))
        
        append_apk_analysis_data(dataset_path, permissions_list, apk_file_name, file_malicious, save_csv_file_name)
    
    return save_csv_file_name
