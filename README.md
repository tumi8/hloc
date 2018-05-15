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

The measure step does:

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

