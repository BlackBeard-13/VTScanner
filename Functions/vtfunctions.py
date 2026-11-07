import os
import pathlib
import json
import requests
import sys
import time
from .utils import safe_json

###FUNCTIONS FOR VT APIS


##Check to make sure the API is in Place
# Windows: setx VT_API "your_key"
# macOS/Linux: export VT_API="your_key"
def get_key():
    key = os.environ.get("VT_API", "").strip()
    #if it is not the key is not found, exit out and tell the user
    if not key:
        sys.exit("Error: Key is not found. Please set as environment variable.")
    return key

# This function validates the API key
def check_key():
    #first we build the get user object call from VT
    key = get_key()
    url = f"https://www.virustotal.com/api/v3/users/{key}"

    header = {"x-apikey": key}

    #Make the Call and if an exception error occurs display it
    try:
        check = requests.get(url, headers=header, timeout=15)
    except requests.RequestException as error:
        print(f"Unable to reach VirusTotal: {type(error).__name__}")
        return False
    #Depending on the status code, we want to proceed or tell the user what the status is and why it occured
    if check.status_code == 200:
        return True
    elif check.status_code in (401, 403):
        print(f"API key Invalid (status {check.status_code}). Please check VT_API.")
    elif check.status_code == 429:
        print("Rate limit or quota exceeded. Wait a minute and try again.")
    else:
        print(f"Issue reaching out to VirusTotal (status {check.status_code}).")
    return None

#Used if the user picks the file option in main program
def file_option (max_tries=3):
    path_object = None
    #First we ask for the file name. We then will grab the file path
    for file_attempts in range(1, max_tries +1):
        the_file = input("Enter file Path: ").strip(' "')
        if not the_file:
            print("No path entered. Try again")
            continue
        path_object = pathlib.Path(the_file)
        if path_object.is_file():
            break
        else:
            print("File Not Found. Try Again.")
            path_object = None
    #Exit out and notify the user if file is not in location
    if not path_object:
        print("File not found. Please check file path")
        return None

    ## we are calling the first API to get the ID, this is only for files under 32Mb
    file_url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": get_key()
        }   
    #Open file, grab the file name and ake the Call. If an exception error occurs display it
    try:
        with open(path_object, "rb") as name:
            files = {"file": (path_object.name, name)}
            file_response = requests.post(file_url, files=files, headers=headers, timeout=30)
    except requests.RequestException as error:
        print(f"Unable to reach VirusTotal: {type(error).__name__}")
        return None

    # Convert response to dictionary
    id_data = safe_json(file_response)
    # Check if the call was successful and proceed with analysis
    if file_response.status_code == 200:
        file_id = id_data.get("data", {}).get("id")
        print(f"Successfully retrieved ID: {file_id}")
        #provides a summary of the main pojnts of the JSON results
        summary = id_analysis(file_id)
        if summary:
            print_summary(summary)
        if not file_id:
            print("VirusTotal returned an unexpected response.")
            return None
    # If it's not successfull, handle the error safely without crashing
    else:
        print(f"API Error (Status Code {file_response.status_code}):")
        
        # Pull the descriptive error message out of the response if available
        if "error" in id_data:
            print(f"Code: {id_data['error'].get('code')}")
            print(f"Message: {id_data['error'].get('message')}")
            #if the ID is known allow the user to proceed
            file_id = input("Do you know the ID? ").strip(' "')
            if file_id: 
                summary = id_analysis(file_id)
                if summary:
                    print_summary(summary)
        else:
            print(id_data)
    return None

#Used ifthe user picks the URL option in main program
def url_option(max_tries=3):
    the_url = ""
    #Obtain the URL and enter routine to check its validity
    for url_attempt in range(1, max_tries +1):
        the_url = input("Enter URL: ").strip(' "')
        if the_url:
            break
        print("no Url entered. Try again.")
        if url_attempt == 3:
            print("Exiting Program...")
            return None

        # add http if missing
    if the_url and not the_url.startswith(('http://', 'https://')):
        the_url = 'https://' + the_url
        #makes sure we can connect to the site
    try:
            test = requests.get(the_url, timeout=10)
            test.raise_for_status()
    except requests.exceptions.RequestException as error:
        print(f"Issue accessing site! unreachable or returned an error: {type(error).__name__}")
        return None
    
    #construct API call
    url = "https://www.virustotal.com/api/v3/urls"
    payload = { "url": the_url }
    headers = {
        "accept": "application/json",
        "x-apikey": get_key(),
        "content-type": "application/x-www-form-urlencoded"
        }

    #Make the Call and if an exception error occurs display it
    try:
        url_response = requests.post(url, data=payload, headers=headers, timeout=30)
    except requests.RequestException as error:
        print(f"Unable to reach VirusTotal: {type(error).__name__}")
        return None
    
    ## Convert response to dictionary. this is the same logic as the file option. Note repeated.
    url_data = safe_json(url_response)
    # Check if the call was successful and proceed with analysis
    if url_response.status_code == 200:
        url_id = url_data.get("data", {}).get("id")
        print(f"Successfully retrieved ID: {url_id}")
        summary = id_analysis(url_id)
        #provides a summary of the main pojnts of the JSON results
        if summary:
            print_summary(summary)
        if not url_id:
            print("VirusTotal returned an unexpected response.")
            return None
    #handle the error safely without crashing
    else:
        print(f"VirusTotal API Error (Status Code {url_response.status_code}):")
        
        # Pull the descriptive error message out of the response if available
        if "error" in url_data:
            print(f"Code: {url_data['error'].get('code')}")
            print(f"Message: {url_data['error'].get('message')}")
            url_id = input("Do you know the ID? ").strip(' "')
            #if the ID is known allow the user to proceed
            if url_id:
                summary = id_analysis(url_id)
                if summary:
                    print_summary(summary)
        else:
            print(url_data)
    return None

#Main analysis program, called at the end of the option functions to analyze the ID and pull the JSON results.
#Set a max tried and delay limit so program does not hang.
def id_analysis (id, max_tries=10, delay=20):
    #Take the ID receive in other function add it to the API call
    scan_id = f"https://www.virustotal.com/api/v3/analyses/{id}"
    headers = {
        "accept": "application/json",
        "x-apikey": get_key()
        }   
    #start the try attempts on the API call
    for attempt in range(1, max_tries +1):
        ##Make the Call and if an exception error occurs display it
        try:
            response = requests.get(scan_id, headers=headers, timeout=60)
        except requests.RequestException as error:
            print(f"Unable to reach VirusTotal: {type(error).__name__}")
            return None
        #if rate is limited, wait 60 seconds and try again
        if response.status_code == 429:
            print("Rate Limited. Waiting to try again")
            time.sleep(delay)
            continue
        #if not success, give the user the status code
        if response.status_code != 200:
            print(f"Error! (status code {response.status_code})")
            return None
        # Convert response to dictionary
        data = safe_json(response)
        #grab the status from the JSON results
        status = data.get("data", {}).get("attributes", {}).get("status")
        if not status:
            print("VirusTotal returned an unexpected response.")
            return None
       
        # Ensures our json results are the completed results and not the queued results
        if status == "completed":
            with open("results.json", "w", encoding="utf-8") as file:
                json.dump(data, file, indent=4, sort_keys=True)
            print("Scan Complete")
            return data
        # Give the user an update status if results are not completed yet
        else: 
            print(f"Status: {status} (check {attempt}/{max_tries}). Waiting {delay}s...") 
            time.sleep(delay)
   #Exit and Display if results time out
    print(f"Timed out waiting for the analysis. ID: {id}")
    return None       

#Gives a user a summary of the results
def print_summary(data):
    #grab the stats for the json results which resides in attributes in the JSON
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})
    
    #grab the stats that will be reported
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    #display the stats
    print("\n--- Scan Summary ---")
    print(f"Malicious:  {malicious}")
    print(f"Suspicious: {suspicious}")
    print(f"Harmless:   {harmless}")
    print(f"Undetected: {undetected}")

    #if anythign is flagged display it, if not 
    if malicious or suspicious:
        print("Result: FLAGGED")
        flagged = [
            engine for engine, result in attributes.get("results", {}).items()
            if result.get("category") in ("malicious", "suspicious")
        ]
        print("Flagged by:", ", ".join(flagged))
    else:
        print("Result: no items flagged at this time")