from collections import Counter
import re
import csv


filelocation = "samplelog.txt"

with open(filelocation, "r") as f:
    inforamtion = f.read()

#Extracting Ip address
#Task 1
print("TASK 1:- Count Requests Per IP Address:")
ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
address = re.findall(ip_pattern, inforamtion) 
ip_count = Counter(address)
counting = sorted(ip_count.items(), key=lambda x:x[1], reverse=True)
print(f"{'IP Address':<20} {'Request Count'}")
for ip, count in counting:
    print(f"{ip:<20}{count}")

print()
#TASK2 
print("TASK 2:- Identifying the Most Frequently Accessed Endpoint:  ")

access_pattern = r'(?:GET|POST|PUT|DELETE) (\S+)'
endpoint = re.findall(access_pattern, inforamtion)


endpoint_count = Counter(endpoint)

if endpoint_count:
    most_visited = endpoint_count.most_common(1)[0]
    print(f"Most Visited Endpoint: {most_visited[0]}")
    print(f"Access Count: {most_visited[1]}")
else:
    print("No Endpoints Accessed") 
    
print()
    
#Task 3 
print("TASK 3:- Detect Suspicious Activity: ")

failed_threshold = 3
incorrect_pattern = r"(\d+\.\d+\.\d+\.\d+).*401|(\d+\.\d+\.\d+\.\d+).*Invalid credentials"

attempts_failedlogin = re.findall(incorrect_pattern, inforamtion)
failedclean = [ip[0]  if ip[0] else ip[1] for ip in attempts_failedlogin]

Ip_failedcount = Counter(failedclean)

suspicious = {ip:count for ip, count in Ip_failedcount.items() if count> failed_threshold}

if suspicious:
    print("Suspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in suspicious.items():
        print(f"{ip:<20} {count}")
else:
    print("No Suspicious acitvity detected!!")
    
    
print()

    
#Task 4
print("TASK 4:- Output results:")

with open('log_analysis_results.csv', mode = 'w' , newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Requests per IP'])
    writer.writerow(['IP Address', "Request Count"])
    for ip, count in counting:
        writer.writerow([ip, count])
    writer.writerow([])
    writer.writerow(['Most Accessed endpoint'])
    if most_visited:
        writer.writerow(["Endpoint", "AccessCount"])
        writer.writerow([most_visited[0], most_visited[1]])
    else:
        writer.writerow(["No Endpoint Accessed"])
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    if suspicious:
        writer.writerow(["IP Addredss", "Failed Login Attempts"])
        for ip, count in suspicious.items():
            writer.writerow([ip, count])
    else:
        writer.writerow(['No Suspicious Activity Found!!!'])
        
print()
        
print('\n Results saved in log_analysis_results.csv')
    
     

