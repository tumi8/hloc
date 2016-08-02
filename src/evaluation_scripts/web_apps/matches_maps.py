import flask
import flask_googlemaps
import argparse
import src.data_processing.util as util
import collections
import heapq
import numpy as np


RED_COLOR = '#FF0000'

parser = argparse.ArgumentParser()
parser.add_argument('drop_filename_proto', type=str,
                    help=r'The path to the files with {} instead of the filenumber'
                         ' in the name so it is possible to format the string')
parser.add_argument('-t', dest='trie_filename_proto', type=str,
                    help=r'The path to the files with {} instead of the filenumber'
                         ' in the name so it is possible to format the string')
parser.add_argument('-f', '--drop-file-count', type=int, default=8,
                    dest='drop_file_count', help='number of files from preprocessing')
parser.add_argument('-tf', '--trie-file-count', type=int, default=8,
                    dest='trie_file_count', help='number of files from preprocessing')
parser.add_argument('-loc', '--location-file-name', required=True, type=str,
                    dest='location_filename', help='The path to the location file.'
                    ' The output file from the codes_parser')
parser.add_argument('-a', action='store_true', dest='analyze')

args = parser.parse_args()
location_counts = collections.defaultdict(int)
codes = collections.defaultdict(int)
for index in range(0, args.file_count):
    with open(args.filename_proto.format(index)) as matches_file:
        for line in matches_file:
            domains = util.json_loads(line)
            for domain in domains:
                for match in domain.all_matches:
                    location_counts[match.location_id] += 1
                    codes[match.code] += 1

with open(args.location_filename) as location_file:
    locations = util.json_load(location_file)

high_locs = heapq.nlargest(20, list(location_counts.items()), key=lambda x: x[1])
print('most matched locations')
for loc_id, count in high_locs:
    location = locations[str(loc_id)]
    print(location.city_name, location.lat, location.lon, count)

high_codes = heapq.nlargest(20, list(codes.items()), key=lambda x: x[1])
print('most matched location codes')
for code, code_count in high_codes:
    print(code, code_count)



if not args.analyze:
    application = flask.Flask(__name__, static_folder='/data/rdns-parse/src/evaluation_scripts/'
                                                      'web_apps/static')
    flask_googlemaps.GoogleMaps(application, key='AIzaSyBE3G8X89jm3rqBksk4OllYshmlUdYl1Ds')


    @application.route('/matches/<any(drop,trie):method>/<any(circles,markers):type>')
    def drop_matches_map(type):
        if type == 'circles':
            matches_map = create_matches_map_with_radius()
        else:
            cluster = flask.request.args.get('cluster', None) is not None
            matches_map = create_matches_map_with_marker(cluster)
        return flask.render_template('matches_maps.html', matches_map=matches_map)


def create_matches_map_with_radius():
    matches_map = flask_googlemaps.Map(identifier='matches_mao', lat=0, lng=0, zoom=4,
                                       maptype='TERRAIN', style='height:100%;')
    default_dict = {
        'stroke_color': RED_COLOR,
        'stroke_opacity': 0.8,
        'stroke_weight': 2,
        'fill_color': RED_COLOR,
        'fill_opacity': 0.35
    }
    for location_id, location_count in location_counts.items():
        location_dct = default_dict.copy()
        matches_map.add_circle(center_lat=locations[str(location_id)].lat,
                               center_lng=locations[str(location_id)].lon,
                               radius=location_count*100, **location_dct)
    return matches_map


def create_matches_map_with_marker(cluster: bool):
    matches_map = flask_googlemaps.Map(identifier='matches_mao', lat=0, lng=0, zoom=4,
                                       maptype='TERRAIN', style='height:100%;', cluster=cluster,
                                       cluster_imagepath='/static/images/m')
    for location_id, location_count in location_counts.items():
        location = locations[str(location_id)]
        for _ in range(0, location_count):
            matches_map.add_marker(lat=location.lat, lng=location.lon)
    return matches_map


if __name__ == "__main__":
    application.run()
