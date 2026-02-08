from datetime import datetime
from random import choice

# A list of good ip addresses
good_ip = {"192.168.1.105", "192.168.1.112", "192.168.1.118", "192.168.1.125", "192.168.1.131",
           "192.168.1.202", "73.152.84.11", "217.164.78.233", "142.250.185.206", "101.44.63.87"}


# A list of bad ip addresses
bad_ip = ["185.220.101.141", "94.102.61.24", "45.155.205.233"]

# A list of bad ip addresses
all_ip = good_ip + bad_ip

# Status (Failed or Accepted)
status = ["Accepted", "Failed"]

def log_generator():
    pass