#!/usr/bin/python

import argparse
import matplotlib
# matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--data-filename', dest='filename',
                        type=str, help='The filename with the data')
    args = parser.parse_args()

    if args.filename:
        data_file = open(args.filename)
        data = []
        index = 0
        for line in data_file:
            if index % 1000 == 0:
                data.append(int(line) / 1000000)
            index = index + 1




    ax = plt.axes(aspect=1)
    codes = [5776, 9837, 15183, 30842, 56627, 103602]
    code_sum = sum(codes)
    codes_per = [x/code_sum for x in codes]
    codes_labels = ['iata (HOU)', 'icao (KHOU)', 'faa (04TE)', 'clli (HSTNTXMOCG0)', 'locode\n(US HOU)', 'geonames\n(Chiouston, Hiustonas, ...)']
    codes_colors = ['#aaaaaa', '#fadc4a', '#f08a0b', '#ff0000', '#00ff00', '#0486e7']

    locations = [24035, 29727, 30842, 56627]
    locations_sum = sum(locations)
    locations_per = [x/locations_sum for x in locations]
    locations_labels = ['geonames', 'airport', 'clli', 'locode']
    locations_colors = ['#0486e7', '#fadc4a', '#ff0000', '#00ff00']

    # geo_types = [20, 861, 31459, 563122, 1837079]
    # geo_types_sum = sum(geo_types)
    # geo_types_per = [x/geo_types_sum for x in geo_types]
    # geo_types_labels = ['icao', 'faa', 'iata', 'locode', 'geonames']
    # geo_types_colors = ['#fadc4a', '#f08a0b', '#aaaaaa', '#00ff00', '#0486e7']
    # ax.pie(codes_per, colors=codes_colors, labels=codes_labels, autopct='%1.1f%%')
    edges, texts, _ = ax.pie(codes_per, colors=codes_colors, labels=codes_labels,
                             autopct='%1.1f%%', pctdistance=0.8, textprops={'fontsize': 14})
    for text in texts:
        text.set_fontsize(18)
        text.set_color('black')

    for edge in edges:
        edge.set_edgecolor('white')


    fig, ax = plt.subplots()
    # ax.plot(list(range(0, len(data))), data)
    # plt.xlabel('The most influential labels\n(Total 151 million labels)')
    # plt.ylabel('Summed up the generated location matches [in billions]\n(Total approx. 37.8 billion matches)')
    # plt.vlines(284, 0, 20, label='20 billions')
    # plt.vlines(3462, 0, 25, label='25 billions')
    # xticks = ax.get_xticks().tolist()
    # xticks.append(284)
    # xticks.append(3462)
    # ax.set_xticks(xticks)
    # ax.set_xlim([0, 8792])

    # ax.plot([x / 1000 for x in range(0, len(data))], data)
    # plt.xlabel('Labels sorted by number of occurrences [in millions]\n(Total 151 million labels)')
    # plt.ylabel('Summed up occurrences [in millions]\n(Total 1.055 billion occurrences)')
    # ax.set_xlim([0, len(data) / 1000])
    #
    # ax.get_yaxis().get_major_formatter().set_scientific(False)
    # ax.get_xaxis().get_major_formatter().set_scientific(False)
    plt.show()
    # plt.savefig('myfig', format='pdf')


if __name__ == '__main__':
    main()
