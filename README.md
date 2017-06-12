# HLOC: Hints-Based Geolocation Leveraging Multiple Measurement Frameworks

This repository servers both for providing additional data for our publication [branch tma17](https://github.com/tumi8/hloc/tree/tma17) and ongoing development of our tool [branch master](https://github.com/tumi8/hloc).

Our architecture approach:

![Approach](images/schema.jpg)

`TODO: Scale picture`

`TODO: One execution example per step`

## Code Collection


## Pre-Processing

The pre-processing step obtains locations and codes from various sources and merges them into a .json file. We deliver the .json file we have used in our study for convenience.   
It also parses IP/DNS files to a json format, which we can not deliver due to its size.

## Find

The find step does:

* Convert the location/code json file into a trie
* Match the IP/DNS json file against this trie
* Produce a .found json

## Measure

The measure step does:

* Read the .found json from find step
* Conduct measurements with various frameworks
* Produces .measured json files
* Offers a converter to easily legible csv files

## Evaluate

The evaluate step is used for comparison against other location hints provided by e.g., databases or other measurement-based approaches

## Dateset

The data is hosted by the TUM library: [https://mediatum.ub.tum.de/1359182](https://mediatum.ub.tum.de/1359182)

The structure of the data is as follows: 

 -  Input Files
    - Router rdns files:
        - All router rdns entries: `rdns-sources/router.domains.rdns`
        - DRoP domains: `rdns-sources/``
    - Location File: `location-codes.json`
    - Zmap measurement results:
        - IPv4: `zmap-measurements/ipv4-zmap-results`
        - IPv6: `zmap-measurements/ipv6-zmap-results`
 -  IPv4
    - Preprocessed data: `ipv4`
    - No IP encoded: `ipv4/wo-encoded-ip/`
        - Drop: `ipv4/wo-encoded-ip/drop/`
        - IP2Location: `ipv4/wo-encoded-ip/ip2loc/`
        - GeoLite: `ipv4/wo-encoded-ip/geoip/`
    - IP encoded: `ipv4/w-encoded-ip/`
        - Drop: `ipv4/w-encoded-ip/drop`
        - IP2Location: `ipv4/w-encoded-ip/ip2loc/`
        - GeoLite: `ipv4/w-encoded-ip/geoip/`
 - IPv6
    - Preprocessed data: `ipv6/`
    - No IP encoded: `ipv6/wo-encoded-ip/`
        - Drop: `ipv6/wo-encoded-ip/drop/`
        - IP2Location: `ipv6/wo-encoded-ip/ip2loc/`

    - IP encoded: `ipv6/w-encoded-ip/`
        - Drop: `ipv6/w-encoded-ip/drop/`
        - IP2Location: `ipv6/w-encoded-ip/ip2loc/`
 -  DRoP domains
    - All data in: `drop-main-domains`
    - *HLOC DRoP reproduction* results are directly in each subfolder
    - HLOC results are in a subfolder of each domain called `hloc-results`

#### File Endings
 These endings are always after the file ending and the process number (`<filename>-<process-number><file-ending>`)
 
 - After preprocessing
    - Correct (`.cor`)
        All domains not filtered by the preprocessing step
    - Unallowed Characters (`.bad`)
        All domains filtered out for characters not allowed in domains
    - IP encoded (`.ipencoded`)
        Domains which have their own IP encoded in the domain name
    - Invalid TLD (`-dns.bad`)
        All domains with a TLD which is not specified by ICANN (e.g., `.local`)
    - Custom filtered (`-custom-filtered`)
        Domains filtered by a custom blacklist
 - After searching
    - Found (`-found.json`)
        Domains with location matches
    - Not Found (`-not-found.json`)
        Domains without location matches
 - After verifying
    - Checked (`-found.checked`)
        The verified results




