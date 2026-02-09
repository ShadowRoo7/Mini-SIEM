import re

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

        if match:
            return {"Timestamp": match.group("timestamp"),
                    "Status": match.group("status"),
                    "User": match.group("user"),
                    "IP": match.group("ip")}
        else:
            return None

fake_log = "Feb 08 22:26:05 sshd[1234]: Accepted password for Root from 192.168.1.131 port 22"
parser = LogParser()
result = parser.parse(fake_log)
print(result)