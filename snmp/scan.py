import threading
import queue
import time
import snmpwalk
import translate

# variables 
FILE_IP = "IPS.txt"
COMMUNITY = "public"
OID = "1.3.6.1"

# Time
start = time.time()

# Function that will be called to start the threads
def start_threads(q):
    while True:
          HOST = q.get()
          output_file = f'scan/ip:{HOST}.txt'
            
          print(f'LOG: STARTING SCAN ON IP {HOST}')
          # module snmpwalk and snmptranslate
          snmpwalk.snmpwalk(HOST, COMMUNITY, OID ,output_file)
          translate.snmptranslate(output_file)
          print(f'LOG: FINISHED IP SCAN {HOST}')
          q.task_done()


# read ips adress
array_ips = []
with open(FILE_IP, 'r') as file:
  
  for ips in file:
    array_ips.append(ips)
    
    

# IPs passed as string, remove \n
array_ips = [ip.strip() for ip in array_ips]


# Maximum number of concurrent threads
numero_maximo_threads = 20

# Create a queue to store instances
fila_hosts = queue.Queue()

# Start the threads
for _ in range(numero_maximo_threads):
    t = threading.Thread(target=start_threads, args=(fila_hosts,))
    t.daemon = True  # Threads will terminate when the main program exits
    t.start()

# Add instances to the queue
for host in array_ips:
    fila_hosts.put(host)

# Waits until all instances are processed
fila_hosts.join()

print("All instances have been processed")

end = time.time()

# Total program duration
total = end - start

# Print total duration in seconds
print(f"The program took {total:.2f} seconds to execute.")