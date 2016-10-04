#!/usr/bin/env python3.5

import src.data_processing.util as util
import collections
import os

# file=open('ip_results_m.json', 'r')
# for line in file:
#     es = json.loads(line)
#     for e in es:
#         count = count + 1
#         if e['blacklisted']:
#             blacklisted = blacklisted + 1
#         elif e['rtt']['munich'] is None:
#             countN = countN + 1
#         else:
#             if e['rtt']['munich'] > 10000:
#                 print(e)
#                 continue
#             sum = sum + e['rtt']['munich']
#
#
# def extract_coords(loc_file):
#     locs = json.load(loc_file)
#     coords = []
#     for loc in locs.values():
#         codes = 1
#         if loc['locode'] is not None:
#             codes = codes + len(loc['locode']['placeCodes'])
#         codes = codes + len(loc['alternateNames'])
#         codes = codes + len(loc['clli'])
#         if loc['airportInfo'] is not None:
#             if len(loc['airportInfo']['iataCode']) > 0:
#                 codes = codes + len(loc['airportInfo']['iataCode'])
#             if len(loc['airportInfo']['icaoCode']) > 0:
#                 codes = codes + len(loc['airportInfo']['icaoCode'])
#             if len(loc['airportInfo']['faaCode']) > 0:
#                 codes = codes + len(loc['airportInfo']['faaCode'])
#         coords.append({'id': loc['id'], 'lat': loc['lat'], 'lng': loc['lon'], 'amount_codes': codes})
#     with open('google_coords.json', 'w') as gFile:
#         json.dump(coords, gFile)
#
# def ana_codes(locs):
#     anz3 = 0
#     anz4 = 0
#     codes = {}
#     def update_anzs(code):
#         nonlocal anz3
#         nonlocal anz4
#         if code is None:
#             return
#         if code not in codes.keys():
#             codes[code] = 1
#             if len(code) == 3:
#                 anz3 = anz3 + 1
#             elif len(code) == 4:
#                 anz4 = anz4 + 1
#         else:
#             codes[code] = codes[code] + 1
#     for loc in locs.values():
#         if loc['locode'] is not None:
#             for c in loc['locode']['placeCodes']:
#                 update_anzs(c)
#         for c in loc['alternateNames']:
#             update_anzs(c)
#         for c in loc['clli']:
#             update_anzs(c)
#         update_anzs(loc['cityName'])
#         if loc['airportInfo'] is not None:
#             if len(loc['airportInfo']['iataCode']) > 0:
#                 for c in loc['airportInfo']['iataCode']:
#                     update_anzs(c)
#             if len(loc['airportInfo']['icaoCode']) > 0:
#                 for c in loc['airportInfo']['icaoCode']:
#                     update_anzs(c)
#             if len(loc['airportInfo']['faaCode']) > 0:
#                 for c in loc['airportInfo']['faaCode']:
#                     update_anzs(c)
#     print('3', anz3, '4', anz4)
#     return codes
#

# def collect_find_loc(file_proto):
#     loc_id_dict = {}
#     def inc_type(loc_id, m_type):
#         if loc_id not in loc_id_dict.keys():
#             loc_id_dict[loc_id] = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0,
#                                    'locode': 0}
#         loc_id_dict[loc_id][m_type] = loc_id_dict[loc_id][m_type] + 1
#     for index in range(0, 8):
#         find_file = open(file_proto.format(index), 'r')
#         for line in find_file:
#             find_domains = json.loads(line)
#             for domain in find_domains:
#                 for key, label_dict in domain['domainLabels'].items():
#                     if key == 'tld':
#                         continue
#                     for match in label_dict['matches']:
#                         inc_type(match['location_id'], match['type'])
#     with open('loc_find_eval_type.json', 'w') as locFile:
#         json.dump(loc_id_dict, locFile)
#     # loc_s = sorted(list(loc_id_dict.items()), key=lambda am: am[1], reverse=True)
#     # for i in range(0, 20):
#     #     print(loc_s[i])


#
# f1.close()
# f2.close()
# f3.close()
# f1 = open('ip_results_m.json', 'r')
# f2 = open('ip_results_s.json', 'r')
# f3 = open('ip_results_d.json', 'r')
#
#
# def merge_rtt_measures(file1, file2, file3):
#     tomerge = {}
#     final = {}
#     blacklisted = {}
#     def merge(items):
#         for i in items:
#             if i['blacklisted']:
#                 blacklisted[i['ip']] = i
#             elif i['ip'] not in tomerge.keys():
#                 tomerge[i['ip']] = i
#             else:
#                 tomerge[i['ip']]['rtt'].update(i['rtt'])
#                 if len(tomerge[i['ip']]['rtt']) == 3:
#                     final[i['ip']] = tomerge.pop(i['ip'], None)
#     for line in file1:
#         merge(json.loads(line))
#         while len(tomerge) > 10**4:
#             merge(json.loads(file2.readline()))
#             merge(json.loads(file3.readline()))
#     line2 = file2.readline()
#     while len(line2) > 0:
#         merge(json.loads(line2))
#         line2 = file2.readline()
#     line3 = file3.readline()
#     while len(line3) > 0:
#         merge(json.loads(line3))
#         line3 = file3.readline()
#     with open('merged_rtts.json', 'w') as rttFile:
#         print(len(tomerge))
#         final.update(blacklisted)
#         json.dump(final, rttFile)
#     with open('n_merged_rtts.json', 'w') as nrttFile:
#         json.dump(tomerge, nrttFile)
#
#
# def sep_rtts(rttfile, file_proto):
#     rtts = json.load(rttfile)
#     for i in range(0, 8):
#         dFile = open(file_proto.format(i), 'r')
#         results = {}
#         for line in dFile:
#             domain_locations = json.loads(line)
#             for domain in domain_locations:
#                 if domain['ip'] in rtts.keys():
#                     results[domain['ip']] = rtts[domain['ip']]
#                 else:
#                     print(domain['ip'])
#         with open(file_proto.format(str(i) + '-ips'), 'w') as rFile:
#             json.dump(results, rFile)
#
# sep_rtts(rrtsf, 'rdns_10m_find/20150902-rdns-{}_found.json')
#
# file_proto = '20150902-rdns-{}_found.json'
# for i in range(0, 8):
#     ofile = open(file_proto.format(i), 'r')
#     nfile = open('../' + file_proto.format(str(i) + '-t'), 'w')
#     for line in ofile:
#         els = json.loads(line)
#         for j in range(0, (len(els)//1000) + 1):
#             json.dump(els[(j * 1000):((j + 1) * 1000)], nfile)
#             nfile.write('\n')
#     nfile.close()
#     ofile.close()

# file_proto = '20150902-rdns-{}.cor'
# total = 0
# for i in range(0, 8):
#     ofile = open(file_proto.format(i), 'r')
#     for line in ofile:
#         ds = json.loads(line)
#         total = total + len(ds)
#     ofile.close()


# def get_data(file):
#     cor = 0
#     wrong = 0
#     blacklisted = 0
#     total_len = 0
#     type_count = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0, 'locode': 0}
#     for line in file:
#         elems = json.loads(line)
#         total_len = total_len + len(elems['not_responding']) + len(elems['correct']) + \
#             len(elems['no_location']) + len(elems['blacklisted'])
#         cor = cor + len(elems['correct'])
#         for e in elems['correct']:
#             type_count[e['correctMatch']['type']] = type_count[e['correctMatch']['type']] + 1
#         wrong = wrong + len(elems['no_location'])
#         blacklisted = blacklisted + len(elems['blacklisted'])
#     return (total_len, cor, wrong, blacklisted, type_count)
#
#
# def get_all_data():
#     for i in range(0, 8):
#         data_file = open('check_domains_output_{}.json'.format(i))
#         print(i, get_data(data_file))


# def get_measurements(ip_addr):
#     max_age = int(time.time()) - 60*60*24*350
#     params = {'status': '2,4,5',
#               'target_ip': ip_addr,
#               'type': 'ping',
#               'stop_time__gte': max_age}
#     measurements = MeasurementRequest(**params)
#     skip = 0
#     if measurements.total_count > 200:
#         skip = ceil(measurements.total_count / 100) - 2
#         measurements.next_batch()
#         for _ in range(0, skip):
#             measurements.next_batch()
#     return measurements

# wfile = open('net_results.txt', 'w')
# for i in range(0,8):
#     f = open('20150902-rdns-{}.cor'.format(i))
#     for line in f:
#         elems = json.loads(line)
#         nets = [x for x in elems if 'net' in x['domainLabels'].values()]
#         json.dump(nets, wfile, indent=2)


# Fix old wrong dataformat
# for i in range(0,8):
#     o_file = open('/data2/trie-results/router.domains-{}-found.checked'.format(i))
#     r_file = open('/data2/trie-results/router.domains-{}-found.checked.rep'.format(i), 'w')
#     for line in o_file:
#         domains = util.json_loads(line)
#         for domain in domains[util.DomainType.correct.value]:
#             domain.location_id = domain.matching_match.location_id
#         util.json_dump(domains, r_file)
#         r_file.write('\n')
#     o_file.close()
#     r_file.close()


# for i in range(0,8):
#     with open('/data2/trie-results/router.domains-{}-found.checked.rep'.format(i)) as file:
#         for line in file:
#             domains = util.json_loads(line)
#             for domain in domains[util.DomainType.correct.value]:
#                 if domain.location_id is None:
#                     print(domain.ip_address)
#                     print(domain.matching_match)
#                     print(domain.matching_match.location_id)


# ips = set()
# for i in range(0,8):
#     with open('/data2/router-ip-filtered/router.domains-{}.cor'.format(i)) as file:
#         for line in file:
#             domains = util.json_loads(line)
#             for domain in domains:
#                 ips.add(domain.ip_address)
# with open('/data2/router-ip-filtered/cor-ips.data', '2') as output_file:
#     string_to_write = ''
#     for ip in ips:
#         string_to_write += '{}\n'.format(ip)
#     _ = output_file.write(string_to_write)


ips = set()
with open('/data2/router-ip-filtered/cor-ips.data') as ip_file:
    for line in ip_file:
        ips.add(line.strip())

def split_results(filename, ip_version, ips):
    for i in range(0,8):
        with open(filename.format(i)) as file, \
                open(filename.format(i) + '.wip', 'w') as w_ip_file, \
                open(filename.format(i) + '.woip', 'w') as wo_ip_file:
            domains_w_ip = collections.defaultdict(list)
            count_w_ip = 0
            domains_wo_ip = collections.defaultdict(list)
            count_wo_ip = 0
            for line in file:
                domains_dict = util.json_loads(line)
                # for key, d_list in domains_dict.items():
                #     for domain in d_list:
                #         if domain.ip_for_version(ip_version) in ips:
                #             domains_w_ip[key].append(domain)
                #             count_w_ip += 1
                #             if count_w_ip >= 10**3:
                #                 util.json_dump(domains_w_ip, w_ip_file)
                #                 _ = w_ip_file.write('\n')
                #                 domains_w_ip.clear()
                #                 count_w_ip = 0
                #         else:
                #             domains_wo_ip[key].append(domain)
                #             count_wo_ip += 1
                #             if count_wo_ip >= 10**3:
                #                 util.json_dump(domains_wo_ip, wo_ip_file)
                #                 _ = wo_ip_file.write('\n')
                #                 domains_wo_ip.clear()
                #                 count_wo_ip = 0
                for domain in domains_dict:
                    if domain.ip_for_version(ip_version) in ips:
                        domains_w_ip['0'].append(domain)
                        count_w_ip += 1
                        if count_w_ip >= 10 ** 3:
                            util.json_dump(domains_w_ip, w_ip_file)
                            _ = w_ip_file.write('\n')
                            domains_w_ip.clear()
                            count_w_ip = 0
                    else:
                        domains_wo_ip['0'].append(domain)
                        count_wo_ip += 1
                        if count_wo_ip >= 10 ** 3:
                            util.json_dump(domains_wo_ip, wo_ip_file)
                            _ = wo_ip_file.write('\n')
                            domains_wo_ip.clear()
                            count_wo_ip = 0
            util.json_dump(domains_w_ip, w_ip_file)
            w_ip_file.write('\n')
            util.json_dump(domains_wo_ip, wo_ip_file)
            wo_ip_file.write('\n')


split_results('/data2/trie-results/router.domains-{}-found.json', 'ipv4', ips)

def get_stats_for_filenameproto(filename_proto):
    lens = collections.defaultdict(int)
    for i in range(0,8):
        with open(filename_proto.format(i)) as d_file:
            for line in d_file:
                domain_dict = util.json_loads(line)
                for key, value in domain_dict.items():
                    lens[key] += len(value)
    print(lens)

def count_domains(filename_proto):
    count_d = 0
    for i in range(0,8):
        with open(filename_proto.format(i)) as d_file:
            for line in d_file:
                count_d += len(json.loads(line))
    print(count_d)


def collect_rtts(filename_proto):
    cor_rtts = []
    no_v_rtts = []
    for i in range(0, 8):
        with open(filename_proto.format(i)) as file:
            for line in file:
                domains = util.json_loads(line)
                for domain in domains[util.DomainType.correct.value]:
                    cor_rtts.append(domain.matching_match.matching_rtt)
                for domain in domains[util.DomainType.no_verification.value]:
                    rtts = [match.matching_rtt for match in domain.all_matches if match.matching_rtt and match.matching_rtt > 0]
                    if rtts:
                        no_v_rtts.append(min(rtts))
    with open(os.path.join(os.path.dirname(filename_proto), 'corr_rtts'), 'w') as output_file:
        wr_str = ''
        for rtt in cor_rtts:
            wr_str += '{}\n'.format(rtt)
        output_file.write(wr_str)
    with open(os.path.join(os.path.dirname(filename_proto), 'no_v_rtts'), 'w') as output_file:
        wr_str = ''
        for rtt in no_v_rtts:
            wr_str += '{}\n'.format(rtt)
        output_file.write(wr_str)
    print('cor avg {}  min {}   max {}'.format((sum(cor_rtts)/len(cor_rtts)), min(cor_rtts),
                                               max(cor_rtts)))
    print('nov avg {}  min {}   max {}'.format((sum(no_v_rtts) / len(no_v_rtts)), min(no_v_rtts),
                                               max(no_v_rtts)))


collect_rtts('/data2/trie-results/router.domains-{}-found.checked')

rtts=[]
with open('/data2/trie-results/corr_rtts') as rtt_file:
    for line in rtt_file:
        rtts.append(float(line.strip()))



# file_name_v4 = '/data2/trie-results/router.domains-{}-found.json'
# file_name_v6 = '/data2/rdns-results-v6/ipv6_rdns-{}-found.json'
def count_ips(file_name):
    ips = []
    for i in range(0, 8):
        with open(file_name.format(i)) as file:
            for line in file:
                domains = util.json_loads(line)
                ips.extend([domain.ipv6_address for domain in domains])
    u_ips = set(ips)
    a_ips = set()
    # with open('/data/scan-2016-07-15/dallas/router.ips.announced') as ips_file:
    with open('/data/rdns-parse/ipv6-router.ips.announced') as ips_file:
        for line in ips_file:
            line = line.strip()
            a_ips.add(line)
    # print(len(ips))
    # print(len(u_ips.intersection(a_ips)))
    print('filtered {}'.format(len(ips) - len(u_ips.intersection(a_ips))))
    # with open('/data/cleared-ipv4-results.zmap') as zmap_file:
    with open('/data/ipv6-zmap.results') as zmap_file:
        _ = zmap_file.readline()
        line = zmap_file.readline()
        results = util.json_loads(line)
    reachables = set(results.keys())
    # print(len(reachables))
    # print(len(u_ips.intersection(a_ips).intersection(reachables)))
    print('timeouts {}'.format(len(ips) - len(u_ips.intersection(a_ips).intersection(reachables)) - (len(ips) - len(u_ips.intersection(a_ips)))))

