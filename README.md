# HLOC: Hints-Based Geolocation Leveraging Multiple Measurement Frameworks


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
