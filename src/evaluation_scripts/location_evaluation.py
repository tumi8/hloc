#!/usr/bin/env python
import json
import argparse
from math import radians, cos, sqrt, fsum, isnan
from multiprocessing import Process


def my_comp(location1, location2):
    """
    Calculate the distance (km) between two points
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians
    lon1 = radians(float(location1['lon']))
    lat1 = radians(float(location1['lat']))
    lon2 = radians(float(location2['lon']))
    lat2 = radians(float(location2['lat']))
    return (((lon2 - lon1) * cos(0.5*(lat2+lat1)))**2 + (lat2 - lat1)**2)


def compute_for_list(locations):
    """computes the average minimum for this list"""
    mins = []
    # minDict = {}
    for location in locations:
        ll = locations[:]
        ll.remove(location)
        lmin = min([my_comp(location, x) for x in ll])
        if isnan(lmin):
            print(location)
            return
        mins.append(lmin)
        # minDict[lmin] = location

    avg = float(fsum(mins)) / len(mins)
    abs_min = min(mins)
    print(avg, ' ', abs_min)
    print('average minimal distance: ', sqrt(avg) * 6371,
          ' median: ', sqrt(sorted(mins)[len(mins)//2])*6371,
          ' absolute minimum: ', sqrt(abs_min) * 6371)


def main():
    """Main"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--input-filename', type=str, default='collectedData.json',
                        dest='filename', help='Specify the input filename')
    args = parser.parse_args()

    locFile = open(args.filename, 'r')
    locations = json.load(locFile)
    locFile.close()
    locLen = len(locations)
    p1 = Process(target=compute_for_list, args=(locations[:locLen//8],))
    p2 = Process(target=compute_for_list, args=(locations[locLen//8:locLen//4],))
    p3 = Process(target=compute_for_list, args=(locations[locLen//4:3*locLen//8],))
    p4 = Process(target=compute_for_list, args=(locations[3*locLen//8:locLen//2],))
    p5 = Process(target=compute_for_list, args=(locations[locLen//2:5*locLen//8],))
    p6 = Process(target=compute_for_list, args=(locations[5*locLen//8:3*locLen//4],))
    p7 = Process(target=compute_for_list, args=(locations[3*locLen//4:7*locLen//8],))
    p8 = Process(target=compute_for_list, args=(locations[7*locLen//8:],))
    p1.start()
    p2.start()
    p3.start()
    p4.start()
    p5.start()
    p6.start()
    p7.start()
    p8.start()
    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p6.join()
    p7.join()
    p8.join()

if __name__ == '__main__':
    main()
