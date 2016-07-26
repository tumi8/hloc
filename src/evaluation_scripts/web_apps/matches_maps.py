import flask
import flask_googlemaps
import argparse
import src.data_processing.util as util
import collections


RED_COLOR = '#FF0000'

parser = argparse.ArgumentParser()
parser.add_argument('filename_proto', type=str,
                    help=r'The path to the files with {} instead of the filenumber'
                         ' in the name so it is possible to format the string')
parser.add_argument('-f', '--file-count', type=int, default=8,
                    dest='file_count', help='number of files from preprocessing')
parser.add_argument('-loc', '--location-file-name', required=True, type=str,
                    dest='location_filename', help='The path to the location file.'
                    ' The output file from the codes_parser')

args = parser.parse_args()
location_counts = collections.defaultdict(int)
for index in range(0, args.file_count):
    with open(args.filename_proto.format(index)) as matches_file:
        for line in matches_file:
            domains = util.json_loads(line)
            for domain in domains:
                for match in domain.all_matches:
                    location_counts[match.location_id] += 1

application = flask.Flask(__name__)
flask_googlemaps.GoogleMaps(application, key='AIzaSyBE3G8X89jm3rqBksk4OllYshmlUdYl1Ds')
with open(args.location_filename) as location_file:
    locations = util.json_load(location_file)


@application.route('/matches/drop')
def drop_matches_map():
    matches_map = create_matches_map()
    return flask.render_template('matches_maps.html', matches_map=matches_map)


def create_matches_map():
    matches_map = flask_googlemaps.Map(identifier='matches_mao', lat=0, lng=0, zoom=4,
                                       maptype='TERRAIN')
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

if __name__ == "__main__":
    application.run()
