
import json
with open("lucky.html", "r", encoding="utf-16le") as f:
    text = f.read()
import re
print("API endpoints found:")
for match in re.findall(r"/api/[^\"]+", text):
    print(match)

