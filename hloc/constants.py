"""
A set of constants and keys used in the framework
"""

import re

DROP_RULE_TYPE_REGEX = re.compile(r'<<(?P<type>[a-z]*)>>')
JSON_CLASS_IDENTIFIER = '_c'
IPV4_IDENTIFIER = 'ipv4'
IPV6_IDENTIFIER = 'ipv6'

PROBE_API_URL_PING = \
    'https://kong.speedcheckerapi.com:8443/ProbeAPIService/Probes.svc/StartPingTestByBoundingBox'
PROBE_API_URL_GET_PROBES = \
    'https://kong.speedcheckerapi.com:8443/ProbeAPIService/Probes.svc/GetProbesByBoundingBox'
EARTH_RADIUS = 6371

DEFAULT_BUFFER_TIME = 9

PROBE_CACHING_PATH = '/var/cache/hloc/ripe_probes.cache'

HLOC_RIPE_TAG = 'HLOC-geolocation'
