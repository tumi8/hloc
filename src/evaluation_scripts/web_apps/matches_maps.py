import flask
import flask_googlemaps
import argparse
import src.data_processing.util as util
import collections
import heapq
import numpy as np
import logging
import datetime


RED_COLOR = '#FF0000'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='drop_filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-dc', dest='drop_checked_filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-t', dest='trie_filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-tc', dest='trie_checked_filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-df', '--drop-file-count', type=int, default=8,
                        dest='drop_file_count', help='number of files from preprocessing')
    parser.add_argument('-tf', '--trie-file-count', type=int, default=8,
                        dest='trie_file_count', help='number of files from preprocessing')
    parser.add_argument('-loc', '--location-file-name', required=True, type=str,
                        dest='location_filename', help='The path to the location file.'
                        ' The output file from the codes_parser')
    parser.add_argument('-a', action='store_true', dest='analyze')

    args = parser.parse_args()
    if not args.drop_filename_proto and not args.trie_filename_proto and not \
            args.drop_checked_filename_proto and not args.trie_checked_filename_proto:
        logging.critical('Neither drop filename proto nor trie filename proto is defined!')
        return 1

    util.setup_logging('matches_maps_{}.log'.format(datetime.date.today().strftime('%d_%m')))

    with open(args.location_filename) as location_file:
        locations = util.json_load(location_file)
    drop_location_counts, drop_checked_location_counts = [None] * 2
    trie_location_counts, trie_checked_location_counts = [None] * 2
    if args.drop_filename_proto:
        drop_location_counts, drop_codes = get_codes_and_location_counts(
            args.drop_filename_proto, args.drop_file_count)
        if args.analyze:
            logging.info('### DROP Statistics ###')
            calc_stats(drop_location_counts, drop_codes, locations, 'drop_codes.stats')

    if args.drop_checked_filename_proto:
        drop_checked_location_counts, drop_codes = get_data_from_checked(
            args.drop_checked_filename_proto, args.drop_file_count)
        if args.analyze:
            logging.info('### DROP Checked Statistics ###')
            calc_stats(drop_checked_location_counts, drop_codes, locations,
                       'drop_checked_codes.stats')

    if args.trie_filename_proto:
        trie_location_counts, trie_codes = get_codes_and_location_counts(
            args.trie_filename_proto, args.trie_file_count)
        if args.analyze:
            logging.info('### TRIE Statistics ###')
            calc_stats(trie_location_counts, trie_codes, locations, 'trie_codes.stats')

    if args.trie_checked_filename_proto:
        trie_checked_location_counts, trie_codes = get_data_from_checked(
            args.trie_checked_filename_proto, args.trie_file_count)
        if args.analyze:
            logging.info('### TRIE Checked Statistics ###')
            calc_stats(trie_checked_location_counts, trie_codes, locations, 'drop_checked_codes.stats')

    if not args.analyze:
        application = flask.Flask(__name__, static_folder='/data/rdns-parse/src/evaluation_scripts/'
                                                          'web_apps/static')
        flask_googlemaps.GoogleMaps(application, key='AIzaSyBE3G8X89jm3rqBksk4OllYshmlUdYl1Ds')

        @application.route('/<any("drop","trie"):method>/<any(circles,markers):mark_type>')
        def matches_map(method, mark_type):
            location_counts = None
            checked = flask.request.args.get('checked', None) is not None
            if method == 'drop':
                if checked:
                    location_counts = drop_checked_location_counts
                else:
                    location_counts = drop_location_counts
            elif method == 'trie':
                if checked:
                    location_counts = trie_checked_location_counts
                else:
                    location_counts = trie_location_counts

            if location_counts:
                limit = int(flask.request.args.get('limit', 0))
                if mark_type == 'circles':
                    matches_map_obj = create_matches_map_with_radius(location_counts, locations,
                                                                     limit)
                else:
                    cluster = flask.request.args.get('cluster', None) is not None
                    matches_map_obj = create_matches_map_with_marker(location_counts, locations,
                                                                     cluster, limit)
                return flask.render_template('matches_maps.html', matches_map=matches_map_obj)

        application.run()


def create_matches_map_with_radius(location_counts, locations, limit):
    matches_map = flask_googlemaps.Map(identifier='matches_mao', lat=0, lng=0, zoom=4,
                                       maptype='TERRAIN', style='height:100%;')
    default_dict = {
        'stroke_color': RED_COLOR,
        'stroke_opacity': 0.8,
        'stroke_weight': 2,
        'fill_color': RED_COLOR,
        'fill_opacity': 0.35
    }
    multiplier = 100
    max_value = max(location_counts.values())
    if max_value > 500000:
        multiplier = 1
    elif max_value > 50000:
        multiplier = 10
    for location_id, location_count in location_counts.items():
        location_dct = default_dict.copy()
        location = locations[str(location_id)]
        matches_map.add_circle(center_lat=location.lat,
                               center_lng=location.lon,
                               radius=location_count*multiplier, **location_dct)
        if location_count*multiplier > limit*1000:
            matches_map.add_marker(lat=location.lat,
                                   lng=location.lon,
                                   infobox=get_location_html_infobox_text(location, location_count))
    return matches_map


def create_matches_map_with_marker(location_counts, locations, cluster: bool, limit: int):
    matches_map = flask_googlemaps.Map(identifier='matches_mao', lat=0, lng=0, zoom=4,
                                       maptype='TERRAIN', style='height:100%;', cluster=cluster,
                                       cluster_imagepath='/static/images/m')
    for location_id, location_count in location_counts.items():
        location = locations[str(location_id)]
        for _ in range(0, location_count):
            if location_count > limit:
                matches_map.add_marker(lat=location.lat, lng=location.lon,
                                       infobox=get_location_html_infobox_text(location,
                                                                              location_count))
    return matches_map


def get_location_html_infobox_text(location, count):
    return '<strong>{}:</strong> {}<br>{} {}'.format(location.city_name, count,
                                                     location.lat, location.lon)

def get_codes_and_location_counts(filename_proto, file_count):
    location_counts = collections.defaultdict(int)
    codes = {}
    for index in range(0, file_count):
        with open(filename_proto.format(index)) as matches_file:
            for line in matches_file:
                domains = util.json_loads(line)
                for domain in domains:
                    for match in domain.all_matches:
                        location_counts[str(match.location_id)] += 1
                        if match.code not in codes:
                            codes[match.code] = collections.defaultdict(int)
                        codes[match.code]['count'] += 1
                        codes[match.code][str(match.location_id)] += 1

    return location_counts, codes


def get_data_from_checked(filename_proto, file_count):
    location_counts = collections.defaultdict(int)
    codes = {}
    for index in range(0, file_count):
        with open(filename_proto.format(index)) as matches_file:
            for line in matches_file:
                matches = util.json_loads(line)
                for match in matches:
                    location_counts[str(match.location_id)] += 1
                    if match.code not in codes:
                        codes[match.code] = collections.defaultdict(int)
                    codes[match.code]['count'] += 1
                    codes[match.code][str(match.location_id)] += 1

    return location_counts, codes


def calc_stats(location_counts, codes, locations, output_filename):
    high_locs = heapq.nlargest(20, list(location_counts.items()), key=lambda x: x[1])
    logging.info('most matched locations')
    for loc_id, count in high_locs:
        location = locations[str(loc_id)]
        logging.info('{} {} {} {}'.format(location.city_name, location.lat, location.lon, count))

    high_codes = heapq.nlargest(20, list(codes.items()), key=lambda x: x[1]['count'])
    logging.info('most matched location codes')
    for code, code_eval in high_codes:
        location_names = ''
        for key, key_count in sorted(list(code_eval.items()), key=lambda x: x[1], reverse=True):
            if key == 'count':
                continue
            location_names += 'id {}, name {}, count {}\n'.format(
                key, locations[str(key)].city_name, key_count)
        logging.info('{} {}\n{}'.format(code, code_eval['count'], location_names.strip()))

    codes_cdf = np.sort([code_eval['count'] for code_eval in codes.values()])[::-1]
    np.savetxt(output_filename, codes_cdf)


if __name__ == "__main__":
    main()
