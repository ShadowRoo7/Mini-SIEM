import re

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
# result = parser.parse(fake_log)
# print(result)
# fake_log = "Feb 08 22:26:05 sshd[1234]: Accepted password for Root from 192.168.1.131 port 22"

class DetectionEngine:
    def __init__(self, threshold = 5, window_size = 60):
        self.memory = {}

    def process_event(self, log_data):
        ...