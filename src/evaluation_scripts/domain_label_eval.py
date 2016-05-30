#!/usr/bin/env python3

import ujson as json
import pickle
import argparse
import operator


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='template for path for domain label dict', type=str)
    parser.add_argument('number_of_files', help='The amount of files to read',
                        type=int)
    parser.add_argument('-r', '--regex-file', type=str, help='The regex pickle file '
                        'with the regular expressions for all locations', dest='regex_file')
    parser.add_argument('-p', '--print-all', help='prints the whole dict sorted desc',
                        dest='print_all', action='store_true')
    args = parser.parse_args()

    concatDict = {}
    for index in range(0, args.number_of_files):
        tempDict = read_stats_file('{0}{1}-domain-label.stats'
                                   .format(args.filename, index))
        for key, value in tempDict.items():
            if key in concatDict.keys():
                concatDict[key] = concatDict[key] + value
            else:
                concatDict[key] = value

    print('sum labels ', sum(concatDict.values()))

    print('amount of _: ', count_occurences('_', concatDict.keys()))
    print('amount of -: ', count_occurences('-', concatDict.keys()))
    print('Collected data on a total of ', len(concatDict), ' items')
    a = filter_amount(concatDict.values(), 2, val=True)
    print(len(a), ' items have more than 2 occurences with ', sum(a))
    a = filter_amount(a, 3, val=True)
    print(len(a), ' items have more than 3 occurences with ', sum(a))
    a = filter_amount(a, 4, val=True)
    print(len(a), ' items have more than 4 occurences with ', sum(a))
    a = filter_amount(a, 5, val=True)
    print(len(a), ' items have more than 5 occurences with ', sum(a))
    a = filter_amount(a, 8, val=True)
    print(len(a), ' items have more than 8 occurences with ', sum(a))
    a = filter_amount(a, 10, val=True)
    print(len(a), ' items have more than 10 occurences with ', sum(a))
    a = filter_amount(a, 15, val=True)
    print(len(a), ' items have more than 15 occurences with ', sum(a))
    a = filter_amount(a, 20, val=True)
    print(len(a), ' items have more than 20 occurences with ', sum(a))

    with open('popular_labels_10.json', 'w') as popular_file:
        json.dump(dict(filter_amount(concatDict.items(), 10)), popular_file)

    with open('popular_labels_5.json', 'w') as popular_file:
        json.dump(dict(filter_amount(concatDict.items(), 5)), popular_file)

    if args.print_all:
        with open(args.regex_file, 'rb') as regex_file:
            regexes = pickle.load(regex_file)
        sortedTupleList = sorted(concatDict.items(), key=operator.itemgetter(1), reverse=True)
        sublist = sorted([(x[0], x[1], len(get_matches(x[0], regexes)))
                          for x in sortedTupleList[:10000]],
                         key=lambda ele: ele[1] * ele[2], reverse=True)
        print(json.dumps(sublist, indent=2))


def get_matches(label, regexes):
    ret = []
    for location_id, regex in regexes:
        matches = regex.search(label)
        if matches is not None:
            group_dict = matches.groupdict()
            for group_key, code in group_dict.items():
                if code is not None:
                    ret.append((location_id, group_key))
                    break
    return ret


def filter_amount(flist, amount, val=False, key=False):
    """filters all elements with value higher or equal than amount"""
    if not key and not val:
        return [(key, value) for key, value in flist if value >= amount]
    else:
        if val:
            return [value for value in flist if value >= amount]
        else:
            return [value for key, value in flist if value >= amount]


def count_occurences(string, list_strings):
    count = 0
    for label in list_strings:
        count = count + label.count(string)
    return count


def read_stats_file(filename):
    """reads a pickle file and returns the dictionary"""
    returnDict = {}
    with open(filename) as characterFile:
        returnDict = json.load(characterFile)

    return returnDict


if __name__ == '__main__':
    main()
