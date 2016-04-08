#!/usr/bin/env python

import requests

url = 'http://www.marigoldtech.com/lists/co.php'
response = requests.get(url, timeout=3.05)

codes = []
text = response.text
startIndex = text.find("<table width=400px class='iplocation'")
text = text[startIndex:]
searchString = "<a href='co.php?state="
startIndex = text.find(searchString) + len(searchString)
while startIndex > len(searchString):
    codes.append(text[startIndex:(startIndex + 2)])
    text = text[startIndex:]
    startIndex = text.find(searchString) + len(searchString)

print(codes)
