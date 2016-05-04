#!/usr/bin/env python3

file_data = open('telecom_ipconnect.data', 'r')
count = 0
false_count = 0
w_file = open('telecom_wrong.data', 'w')

for line in file_data:
    ip, domain = line.split(',')
    ip_blocks = ip.split('.')
    hexdata = ''
    for block in ip_blocks:
        hexdata = hexdata + hex(int(block))[2:].zfill(2)

    if hexdata.upper() in domain.upper():
        count = count + 1
    else:
        w_file.write('{}'.format(line))
        if domain[0] == 'p':
            false_count = false_count + 1

print(count)
print(false_count)
