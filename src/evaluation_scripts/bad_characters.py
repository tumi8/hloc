#!/usr/bin/env python3.5

from __future__ import print_function
import pickle
import argparse
import operator


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='template for path for bad charater files', type=str)
    parser.add_argument('number_of_files', help='The amount of bad character files to read',
                        type=int)
    args = parser.parse_args()

    concatDict = {}
    for index in range(0, args.number_of_files):
        tempDict = read_character_file('{0}{1}-character.stats'
                                       .format(args.filename, index))
        for key, value in tempDict.items():
            if key in concatDict.keys():
                concatDict[key] = concatDict[key] + value
            else:
                concatDict[key] = value

    sortedTupleList = sorted(concatDict.items(), key=operator.itemgetter(1))

    for (key, value) in sortedTupleList:
        print(ord(key), key, value, sep=',')


def read_character_file(filename):
    """reads a character file and returns the dictionary"""
    returnDict = {}
    with open(filename, 'rb') as characterFile:
        returnDict = pickle.load(characterFile)

    return returnDict


if __name__ == '__main__':
    main()
