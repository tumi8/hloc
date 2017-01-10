"""
A set of constants and keys used in the framework
"""

import re
import string

ACCEPTED_CHARACTER = frozenset('{0}.-_'.format(string.printable[0:62]))
DROP_RULE_TYPE_REGEX = re.compile(r'<<(?P<type>[a-z]*)>>')
JSON_CLASS_IDENTIFIER = '_c'
IPV4_IDENTIFIER = 'ipv4'
IPV6_IDENTIFIER = 'ipv6'
PROBE_API_KEY = '66bcd4c1-fdca-46f1-b1b9-8f7c333379e9'
PROBE_API_URL_PING = \
    'https://kong.speedcheckerapi.com:8443/ProbeAPIService/Probes.svc/StartPingTestByBoundingBox'
PROBE_API_URL_GET_PROBES = \
    'https://kong.speedcheckerapi.com:8443/ProbeAPIService/Probes.svc/GetProbesByBoundingBox'
EARTH_RADIUS = 6371
