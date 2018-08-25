import requests
import sys
import time
import json

print("""
 _    ___                ______      __        __
| |  / (_)______  ______/_  __/___  / /_____ _/ /
| | / / / ___/ / / / ___// / / __ \/ __/ __ `/ / 
| |/ / / /  / /_/ (__  )/ / / /_/ / /_/ /_/ / /  
|___/_/_/   \__,_/____//_/  \____/\__/\__,_/_/   

                                    By Dr4g0v
""")

def url_scan(ip):
    global a
    url='https://www.virustotal.com/vtapi/v2/url/scan'
    params={'apikey':<apikey>,'url':ip}
    try:
        response=requests.post(url,data=params)
        a=response.json()
        print(a['url'])
    except:
        print("Cannot be connect to the VirusTotal Server")

def url_list():
    global urls
    urls=[]
    with open("url.txt","r") as f:
        file=f.read()
        file=file.split("\n")
        for i in file:
            urls.append(i)

def url_report():
    scan_id=a['scan_id']
    url='https://www.virustotal.com/vtapi/v2/url/report'
    params={'apikey': <apikey>, 'resource':scan_id}
    response=requests.get(url,params=params)
    b=response.json()
    #print(b)
    try:
        threat=b['positives']
        print("[+]Completed. The result is {}/{}\n".format(threat,b['total']))
        if threat!=0:
            with open("result.txt","a") as f:
                file=f.write(a['url'])
                file=f.write(" ")
                file=f.write(a['permalink'])
                file=f.write("\n")
    except KeyError:
        print("[!]VirusTotal server error...")
    except:
        print("[!]Unknown error")
    time.sleep(30.5) #Public Api_Key has time limit (4 request per minute)

def show_report():
    with open("result.txt","r") as f:
        file=f.read()
        print(file)

while True:
    print("""

1-)Scan a URL
2-)Scan URL List
3-)Show report
4-)Exit
""")
    
    choice=input("Select an option :")
    if choice=="1":
        url_base=input("Enter a URL: ")
        url_scan(url_base)
        url_report()
    elif choice=="2":
        url_list()
        #print(urls[0])
        counter=0
        for i in urls:
            counter+=1
            print("{}/{} completed".format(counter,len(urls)))
            url_scan(i)
            url_report()
    elif choice=="3":
        show_report()
    elif choice=="4":
        sys.exit()
    else:
        print("Wrong option. Try again")
    
