#!/usr/bin/env python3

import argparse
import time
import yaml


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('drop_rules_file_path', type=str,
                        help='The path to the file containing the drop rules')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()
    with open(args.drop_rules_file_path) as drop_rules_file:
        print(yaml.load(drop_rules_file))


if __name__ == '__main__':
    main()
