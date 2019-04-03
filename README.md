# HLOC: Hints-Based Geolocation Leveraging Multiple Measurement Frameworks

This repository servers both for providing additional data for our publication [branch tma17](https://github.com/tumi8/hloc/tree/tma17) and ongoing development of our tool [branch master](https://github.com/tumi8/hloc).

Our architecture approach:

<img src="images/schema.jpg" alt="Drawing" width=500 />

## Codes Parsing

The Codes Parsing process collect location codes from the selected sources, merges them if desired and stores them in the database.

## Pre-Processing

The pre-processing step parses IP/DNS files and classifies/filters the domain into multiple groups. The domains with their group information are then stored in the database.
We cannot deliver the IP/DNS files due to its size.

## Find

The find step does:

* Create a trie out of all location information
* Match the domain labbel stored in the pre-processing step against this trie
* Store the resulting location hints in the database

## Measure

The measure step can:

* Read all domains randomly
* Conduct measurements with various frameworks for all location hints of a domain
* Store all measurement results in the database

## Evaluate

We produce a daily export with all location hints for all domains with the minimal RTT measurement to the corresponding IP address.
The file contains the following columns (the csv column title is in brackets):

* **Domain id** (domain\_id): The id of the domain entry in the domains table of the database.
* **Domain name** (domain\_name): The full domain name.
* **IP address** (ip\_address): The IP address of the domain name from the time of the rDNS export.
* **Location hint id** (location\_hints\_id): The id of the location hint in the location\_hints table of the database.
* **Location code** (hint\_location\_code): The location code which has been found in the domain name and which is checked
* **Location code type** (location\_hint\_type): The type of the location code (e.g. iata, geonames, \ldots)
* **Hint Location id** (hint\_location\_id): The id of the location, corresponding to the location code, in the locations table of the database.
* **Hint location latitude** (hint\_location\_lat): The latitude of the hint location.
* **Hint location longitude** (hint\_location\_lon): The latitude of the hint location.
* **Probe id** (probe\_id): The id of the measurement probe in the probes table of the database. The probe information is for the measurement with the global minimum RTT to the IP address.
* **Probe location latitude** (probe\_location\_lat): The latitude of the hint location.
* **Probe location longitude** (probe\_location\_lon): The latitude of the hint location.
* **Measurement result id** (measurement\_results\_id): The id of the measurement result in the measurement\_results table of the database. This measurement conatins the current global minimum RTT to the destination IP address.
* **RIPE Atlas measurement id** (ripe\_measurement\_id): If the fastest measurement was from RIPE Atlas this column contains the RIPE Atlas measurement id else it is empty.
* **Measurement timestamp** (measurement\_timestamp): The timestamp of the measurement as a UNIX timestamp in UTC
* **Measurement type** (measurement\_type): The source of the measurement, e.g. RIPE Atlas, Caida, \ldots
* **Is from traceroute** (from\_traceroute): A boolean value indicating if this measurement result was extracted from a traceroute measurement.
* **Minimal RTT** (min\_rtt\_ms): The RTT in milliseconds of the measurement
* **Distance** (distance\_km): The distance between the probe location and the hints location (the suspected location). This is relevant to determine the maximal error and if a hint can be considered valid.
* **Is the hint possible** (possible): A boolean value indicating if the location hint is theoretical still possible considering this global minimal RTT.

## Try out HLOC yourself

### Prerequisites

- Postgres v10.0 or newer: HLOC 2.0 uses a Postgres database to store the collected information
- Python v3.4.2: We tested everything on 3.4.2 but also newer versions should work
- Install all Python dependencies using `pip install -r requirements.txt`
- All shell scripts were only tested on a standard Debian bash

### Import location codes

- First you need download several loaction code sources (we used the `location-data` directory as collection point for these):
    - `location-data` already contains our self created list of IATA metropolitan codes
    - unpack the `offline-pages.tar.xz` archive. It contains a scraped list of pages from [www.world-airport-codes.com](www.world-airport-codes.com). 
    Our HTML parser is outdated for their current data format. Therefore, we use this stored version.
    - Get the locode files from [UNECE](https://www.unece.org/cefact/codesfortrade/codes_index.html) we only need the three *CodeListPart* files
    - Unfortunately we could not find a public available CLLI list. If you still have one it should match the following format (without header):
    
    ```
    CLLI code<tab (\t)>latitude<tab (\t)>longitude
    ```

Finally you can execute the codes parsing script. An example of how this could look like can be seen in the shell script `example-initial-db-setup`.
For more information on the different parameters please read the help output of the script.
    
### Preprocessing of domain names

- To preprocess the list of domains to geolocate you only need two file:
    - The valid TLDs file (get if from [IANA](http://data.iana.org/TLD/tlds-alpha-by-domain.txt))
    - The domain list file in the format:
    IP,DOMAIN - without a space inbetween
    
*ATTENTION*

This script assumes the tables domains and domain_labels are empty! 
This is due to a drawback in our current implementation.

The second command executed in `example-initial-db-setup` shows how to preprocess the domains.
    
### Searching for location hints

- No additional sources are needed here. Our balcklist can be found in the `blacklists` directory

Try to execute `python -m hloc.scripts.find -p <nr_cores> -c blacklists/code.blacklist.txt -f blacklists/word.blacklist.txt -s blacklists/special.blacklist.txt -dbn <database_name> -l <log_file_name>`

### Validation

Before executing the validate script you need to create the folder /var/cache/hloc if you do not want to run the script from root.

If you want to perform active measurements on the [RIPE Atlas](https://atlas.ripe.net) platform you need an account and credits to do that.
Use option `-o` to validate against the current available measurements for the IP address.

The `example-validation.sh` script provides an easier access to the script with usefull prefilled parameters.
Check and adopt these accordingly
