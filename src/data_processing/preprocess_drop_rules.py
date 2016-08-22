#!/usr/bin/env python3

import argparse
import yaml
import time
import src.data_processing.util as util

RULE_NAME = '__rule__'
logger = None


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('drop_rules_file_path', type=str,
                        help='The path to the file containing the drop rules')
    parser.add_argument('output_filename', type=str, default='drop_rules.json',
                        help='The path and name for the outputfile')
    parser.add_argument('-l', '--logging-file', type=str, default='preprocess_drop.log',
                        dest='log_file', help='The logging file where the log should be saved')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()
    start_time = time.time()
    global logger
    logger = util.setup_logger(args.log_file, 'process')

    rules = []
    with open(args.drop_rules_file_path) as drop_rules_file:
        docs = yaml.load_all(drop_rules_file)
        for doc in docs:
            if 'source' in doc and doc['name'].find('DRoP') >= 0:
                rules.append(util.DRoPRule.create_rule_from_yaml_dict(doc))

    rules_trie = create_trie_for_rules(rules)

    with open(args.output_filename, 'w') as output_file:
        util.json_dump(rules_trie, output_file)

    end_time = time.time()
    logger.info('Collected {} DRoP rule objects'.format(len(rules)))
    logger.info('Collected {} DRoP rules'.format(sum([len(rule.rules) for rule in rules])))
    logger.info('{} different first level domain name rules exist'.format(len(rules_trie)))
    logger.info('running time: {}'.format((end_time - start_time)))


def create_trie_for_rules(rules: [util.DRoPRule]) -> [str, object]:
    """
    Creates a trie like structure in a dict for the drop rules
    :returns the rule trie
    :return: [str, object]
    """
    dct = {}
    for rule in rules:
        rule_domain_parts = rule.name.split('.')
        assert len(rule_domain_parts) > 1
        main_domain = '.'.join(rule_domain_parts[-2:])
        rule_domain_parts.pop()
        rule_domain_parts[-1] = main_domain
        tmp = dct
        for part in rule_domain_parts[::-1]:
            if part not in tmp:
                tmp[part] = {}
            tmp = tmp[part]
        tmp[RULE_NAME] = rule

    return dct


if __name__ == '__main__':
    main()
