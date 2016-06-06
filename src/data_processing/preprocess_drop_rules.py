#!/usr/bin/env python3

import argparse
import time
import os
import yaml
import src.data_processing.util as util

def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('drop_rules_file_path', type=str,
                        help='The path to the file containing the drop rules')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()
    rules = []
    with open(args.drop_rules_file_path) as drop_rules_file:
        docs = yaml.load(drop_rules_file)
        for doc in docs:
            if 'source' in doc and doc['name'].find('DRoP') >= 0:
                rules.append(util.DRoPRule.create_rule_from_yaml_dict(doc))

    outputfilename = os.path.basename(args.drop_rules_file_pat).split('.')[0] + '.json'
    with open(os.path.join(os.path.dirname(
            args.drop_rules_file_path), [outputfilename])) as output_file:
        util.json_dump(rules, output_file)


if __name__ == '__main__':
    main()
