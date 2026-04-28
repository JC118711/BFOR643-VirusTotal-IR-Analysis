import requests
import os
import time
import pandas as pd
import matplotlib.pyplot as plt
import re
from dotenv import load_dotenv
from tabulate import tabulate

load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY,
    "accept": "application/json"
}

def get_virus_total_ip(ip):
    url = f"{BASE_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ioc": ip,
            "type": "ip",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }
    else:
        return None

def get_virus_total_domain(domain):
    url = f"{BASE_URL}/domains/{domain}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ioc": domain,
            "type": "domain",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }
    return None

def get_virus_total_hash(file_hash):
    url = f"{BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ioc": file_hash,
            "type": "hash",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }
    return None

def get_ioc_type(ioc):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    elif len(ioc) in [32, 40, 64]:  # MD5, SHA1, SHA256
        return "hash"
    else:
        return "domain"

def get_iocs(ioc_list):
    results = []

    for ioc in ioc_list:
        ioc_type = get_ioc_type(ioc)
        print("Querying VirusTotal: ", ioc)

        if ioc_type == "ip":
            result = get_virus_total_ip(ioc)
        elif ioc_type == "domain":
            result = get_virus_total_domain(ioc)
        elif ioc_type == "hash":
            result = get_virus_total_hash(ioc)
        else:
            result = None

        if result:
            results.append(result)

    return pd.DataFrame(results)
    
def create_visualizations (df): 
  label_colors = {
      "malicious": "red",
      "suspicious": "yellow",
      "harmless": "green",
      "undetected": "gray"
  }

  for index, row in df.iterrows():
    ioc = row["ioc"]
    labels = ["malicious", "suspicious", "harmless", "undetected"]
    sizes = [row["malicious"], row["suspicious"], row["harmless"], row["undetected"]]

    # Filter out zero values and corresponding labels
    filtered_labels = [label for label, size in zip(labels, sizes) if size > 0]
    filtered_sizes = [size for size in sizes if size > 0]
    filtered_colors = [label_colors[label] for label in filtered_labels]

    if not filtered_sizes:
        print(f"No data to display for IOC: {ioc}")
        continue

    fig1, ax1 = plt.subplots()
    ax1.pie(filtered_sizes, labels=filtered_labels, autopct='%1.1f%%', startangle=90, colors=filtered_colors)
    ax1.axis('equal')
    plt.title(f"IOC: {ioc}")
    
    filename = os.path.join("outputs", f"ioc_pie_chart_{ioc}.png")
    plt.savefig(filename)
    
def assign_risk_level(malicious):
    if malicious > 10:
        return "HIGH"
    elif malicious >= 3:
        return "MEDIUM"
    else:
    	return "LOW"

if __name__ == "__main__":

    sample_iocs = [
        "a5952e45646d033bff8380fc508a0b9527bb4943f2788046005f0e80e6ebb290",
        "e263e41c5adb36fd21a26656f2478cbf5140846e872fd70c53341a71fb3d64f5",
        "ccba027446f898e9c330e570ec4d9a0bd4eb3d6b9f89ce49f6108a3a18e937f0",
        "d9c88c1a21fc918ce8082e3c71e47e8b7e694b6b1fab0d94693bba1ddc13e693",
        "scxzswx.lovestoblog.com",
        "icanhazip.com",
        "185.27.134.154"
    ]

    df = get_iocs(sample_iocs)
    
    create_visualizations(df)
    
    df["risk"] = df["malicious"].apply(assign_risk_level)
    df = df.sort_values(by="malicious", ascending=False)
    
    df.to_csv("outputs/enriched_iocs.csv", index=False)
    
    print("\n==== VirusTotal Results ====\n")
    print(tabulate(df, headers="keys", tablefmt="grid", showindex=False))
    print("\nCompleted!")
