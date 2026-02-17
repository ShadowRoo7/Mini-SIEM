import re
import datetime
import time

# Building the Parser
class LogParser:
    def __init__(self):
        # Regex pattern to capture Timestamp, Status, User, and IP
        # ex: Feb 08 22:26:05 sshd[1234]: Accepted password for Root from 192.168.1.131 port 22
        pattern = r"(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) sshd\[1234\]: (?P<status>\w+) password for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port 22"

        # Compile the regex so it's ready for fast matching
        self.regex = re.compile(pattern)

    def parse(self, log_line):
        # scan the text
        match = self.regex.search(log_line)

        # Verify if the line matches the pattern
        if match:
            # Extract info from the line, store them in a dictionary and return them
            return {"Timestamp": match.group("timestamp"),
                    "Status": match.group("status"),
                    "User": match.group("user"),
                    "IP": match.group("ip")}
        # Otherwise if the line is empty or doesn't match the patter
        else:
            return None

# parser = LogParser()
# fake_log = "Feb 08 22:26:05 sshd[1234]: Accepted password for Root from 192.168.1.131 port 22"
# result = parser.parse(fake_log)
# print(result)

class DetectionEngine(LogParser):
    def __init__(self, threshold=3, window_size=60):
        super().__init__()
        self.memory = {}
        self.threshold = threshold
        self.window_size = window_size

    def process_event(self, log_data):
        # Parse the log data using the parse method from LogParser()
        result = self.parse(log_data)

        # Verify if the result match the pattern or not if not we pass
        if result is None:
            pass
        # if the result status is "Accepted" we delete it's "IP" from the memory if existed in it else we pass
        elif result["Status"] == "Accepted":
            if result["IP"] in self.memory:
                del self.memory[result["IP"]]
            else:
                pass
        # if the result status is "Failed"
        else:
            # 1. CONVERT: Convert the incoming log timestamp string to a datetime object
            current_dt = datetime.datetime.strptime(result["Timestamp"], "%b %d %H:%M:%S")

            # Check if IP exists and count is less than 3
            # FIXED: Changed len(result["IP"]) to len(self.memory[result["IP"]])
            if result["IP"] in self.memory and len(self.memory[result["IP"]]) < self.threshold:

                valid_timestamps = []

                # Loop through the stored timestamps
                for stored_time_str in self.memory[result["IP"]]:
                    # 2. CONVERT: Convert stored string to datetime for math
                    stored_dt = datetime.datetime.strptime(stored_time_str, "%b %d %H:%M:%S")

                    # 3. MATH: Calculate difference in seconds
                    if (current_dt - stored_dt).total_seconds() < self.window_size:
                        valid_timestamps.append(stored_time_str)

                # Update memory with only the recent timestamps
                self.memory[result["IP"]] = valid_timestamps

                # Add the new timestamp (stored as string)
                self.memory[result["IP"]].append(result["Timestamp"])

            # Check for alert logic
            # FIXED: Moved this check AFTER adding the new timestamp so it catches the 3rd try immediately
            if result["IP"] in self.memory and len(self.memory[result["IP"]]) >= self.threshold:
                print(f"Brute Force Attack from {result['IP']}")
                del self.memory[result["IP"]]

            # Else it creates the new entry
            elif result["IP"] not in self.memory:
                self.memory[result["IP"]] = [result["Timestamp"]]