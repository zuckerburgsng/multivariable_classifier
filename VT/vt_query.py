from VT_decompile import check_file_size, upload_big_file_to_VT, upload_small_file_to_VT, get_upload_link, hash_file, get_VT_report_from_hash
from pprint import pprint
from time import perf_counter
import math
import os


def format_response(response):
    res = {}
    
    attributes = response["data"]["attributes"]
    res["md5-hash"] = attributes["md5"]
    threat_classification = attributes.get("popular_threat_classification", {})
    
    res["Potential Threat Label"] = threat_classification.get("suggested_threat_label", "None")
    
    cats = threat_classification.get("popular_threat_category", [])
    res["Threat Categories"] = {cat["value"]: cat["count"] for cat in cats} or "None"
    
    names = threat_classification.get("popular_threat_name", [])
    res["Threat Names"] = {name["value"]: name["count"] for name in names} or "None"
    
    res["Crowdsourced Alert Summary"] = attributes.get("crowdsourced_ids_stats", "None")
    
    vendor_detections = attributes["last_analysis_stats"]
    total_scanned = vendor_detections["harmless"] + vendor_detections["malicious"] + vendor_detections["suspicious"] + vendor_detections["undetected"]
    res["Vendor Detection"] = f"{vendor_detections['malicious']}/{total_scanned}"
        
    return res

def upload_file(file_path):
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
    
    if upload_response.status_code == 200:
        return upload_response
    else:
        print('ERROR: Uploading file failed\nFile name: {name}\nTry to upload file manually using VirusTotal GUI'.format(name= file_path))

def analyse_apk(file):
    hash = hash_file(file)
    res = analyse_hash(hash)
    
    if not res:
        response = upload_file(file)
        res = format_response(response.json())

    return res

def analyse_hash(hash):
    response = get_VT_report_from_hash(hash)
    if response.status_code == 404:
        print('FAILED: HASH not found in VirusTotal Database')
        return None
    res = format_response(response.json())
    return res

def rename_files_with_threat_labels(malicious_folder_path):
    malicious_folder = os.fsencode(malicious_folder_path)
    for file in os.listdir(malicious_folder):
        filename = os.fsdecode(file)
        malicious_file_path = malicious_folder_path + filename

        threat_label = analyse_apk(malicious_file_path)['Potential Threat Label']
        threat_label_formatted = threat_label.replace('.', '_').replace('/', '_') + "_"
        new_filename = malicious_folder_path + threat_label_formatted + filename
        os.rename(malicious_file_path, new_filename)



if __name__ == '__main__':
    t1_start = perf_counter()
    malicious_folder_path = '/home/vboxuser/multivariable_classifier_jstap/database/malicious_dataset_unanalysed/'
    try:
        rename_files_with_threat_labels(malicious_folder_path=malicious_folder_path)

    except KeyError:
        print(f'KeyError: API limit hit')

    except FileNotFoundError:
        print(f'FileNotFoundError: File not found')

    t1_stop = perf_counter()

    print("Elapsed time:", t1_stop, t1_start)
    print("Elapsed time during the whole program in seconds:", t1_stop-t1_start)


