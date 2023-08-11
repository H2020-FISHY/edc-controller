import json
from lib2to3.pytree import Base
import clips
import re
import requests
import ipaddress
import re
import argparse
import os
import xml.etree.ElementTree as et
import networkx as nx

from rules import RULES, TEMPLATES
from company_database import *
from ipv4_with_negation import *

API_ENDPOINT = "host.docker.internal"
ENV_API_ENDPOINT = os.environ.get("API_ENDPOINT")
if ENV_API_ENDPOINT is not None and isinstance(ENV_API_ENDPOINT, str):
    API_ENDPOINT = ENV_API_ENDPOINT

NSF_catalogue_host = f'http://{API_ENDPOINT}:8984'
if ('NSF_catalogue_host' in os.environ):
    NSF_catalogue_host = os.environ['NSF_catalogue_host']

NSF_catalogue_credentials = ('admin', 'admin')

env = clips.Environment()
for template in TEMPLATES:
    env.build(template)

graph = nx.Graph()


def build_graph():
    for device, values in NetworkBackbone.items():
        for value in values:
            graph.add_edge(FirewallAndSubnet[device], FirewallAndSubnet[value])

    # These commands are to show networkx graph

    # net = Network()
    # first_vertex = list(NetworkBackbone.keys())[0]
    # lists = list(NetworkBackbone.values())
    # vertices = [x for values in lists for x in values]
    # vertices.insert(0, first_vertex)
    # for vertex in vertices:
    #     net.add_node(vertices.index(vertex), label=vertex)
    # for device, values in NetworkBackbone.items():
    #     for value in values:
    #         index_device = vertices.index(device)
    #         index_value = vertices.index(value)
    #         net.add_edge(index_device, index_value)
    # # net.show_buttons(filter_=['nodes', 'edges', 'physics'])
    # net.set_options("""
    # var options = {
    #   "nodes": {
    #     "color": {
    #       "highlight": {
    #         "background": "rgba(233,232,255,1)"
    #       }
    #     },
    #     "font": {
    #       "color": "rgba(0,0,0,1)",
    #       "size": 18
    #     },
    #     "scaling": {
    #       "max": 178
    #     }
    #   },
    #   "edges": {
    #     "color": {
    #       "inherit": true
    #     },
    #     "smooth": false
    #   },
    #   "physics": {
    #     "minVelocity": 0.75
    #   }
    # }
    # """)
    # net.show("../network_topology.html")

    return


def assert_error(msg, detail, hsplid):
    print('ERROR: ',  msg)
    temp_err = env.find_template('error')
    temp_err.assert_fact(message=msg, detail=detail, hsplid=hsplid)


def parse_hspl(hspl):
    hspl_id = hspl.attrib["id"]
    sub = hspl.find('{http://fishy-project.eu/hspl}subject').text
    act = hspl.find('{http://fishy-project.eu/hspl}action').text
    if "notify" in act:
        # continue # ???
        pass
    obj = hspl.find('{http://fishy-project.eu/hspl}object').text

    optional_fields = []
    for optF in hspl.findall('{http://fishy-project.eu/hspl}optionalField'):
        opt_type = optF.find('{http://fishy-project.eu/hspl}optionType').text
        opt_value = optF.find('{http://fishy-project.eu/hspl}optionValue').text
        optional_fields.append((opt_type, opt_value))

    parsed = {
        'id': hspl_id,
        'subject': sub,
        'action': act,
        'object': obj
    }

    return parsed, optional_fields


def database_search_entity_info(x):
    res = {}

    if x in entity_data:
        if isinstance(entity_data[x], dict):
            for k, v in entity_data[x].items():
                res[k] = str(v)
            # if "IP" in entity_data[x]:
            #     res['IP'] = str(entity_data[x]['IP'])
            # if "WID" in entity_data[x]:
            #     res['WID'] = str(entity_data[x]['WID'])
            # if "DID" in entity_data[x]:
            #     res['DID'] = str(entity_data[x]['DID'])
        else:
            res['IP'] = str(entity_data[x])
    elif x in sub_obj_URL:
        res['URL'] = str(sub_obj_URL[x])
    else:
        try:
            ipaddress.ip_address(x)
            res['IP'] = x
        except ValueError:  # Default source when subject is not found in database, and it is not an IP address is towards Internet
            pass
            #res['IP'] = '0.0.0.0/0'
    print('### ', x, res)
    return res


def entity_analysis(sub, obj, hsplid):
    data = database_search_entity_info(sub)

    # print(sub, data)

    if (len(data) == 0):
        assert_error('Entity not defined',
                     'No record in database for the entity: ' + sub, hsplid)

    temp = env.find_template('entity')
    data['name'] = sub
    for x in ['IP', 'WID', 'DID']:
        if not x in data:
            data[x] = ''
    temp.assert_fact(**data)

    data = database_search_entity_info(obj)

    # print(obj, data)

    if (len(data) == 0):
        assert_error('Entity not defined',
                     'No record in database for the entity: ' + obj, hsplid)

    temp = env.find_template('entity')
    data['name'] = obj
    for x in ['IP', 'WID', 'DID']:
        if not x in data:
            data[x] = ''

    temp.assert_fact(**data)


def add_entity_req_capabilities(hsplid, sub, obj):

    template = env.find_template('reqcapability')

    if (obj in objectsINFO):
        info = objectsINFO[obj]
        for i in info:
            x = i.split(' ')
            cap = x[0]
            detail = ''
            if (len(x) > 1):
                detail = x[1]

            template.assert_fact(capability=cap, detail=detail, hsplid=hsplid)


def get_req_capabilities(hsplid):
    cap = []

    for f in env.facts():
        if (f.template.name == 'reqcapability'):
            if (f['hsplid'] == hsplid):
                cap.append(f['capability'])

    return cap


def get_nsfs_with_cap(capabilities):

    capabilities = ','.join(capabilities)

    params = {'run': 'capa_set_search.xq',
              'capa_set': capabilities}

    response = requests.get(
        NSF_catalogue_host + '/rest', params=params, auth=NSF_catalogue_credentials)

    nsfs = re.findall(r'NSF (\w+)', response.text)
    return nsfs


def get_device_nsf_list(device):
    if device in DevicesNSF:
        return DevicesNSF[device]
    return []


def find_configuration(ip_src, ip_dst, hsplid, output_paths_filename=None, input_conf_filename=None):
    paths = path_search(ip_src, ip_dst, hsplid)

    if (len(paths) == 0):
        assert_error(
            'No path found between entities', f'No path between {ip_src} and {ip_dst}', hsplid)
        return

    print('PATHS: ', paths)

    req_capabilities = get_req_capabilities(hsplid)

    try:
        suitable_nsfs = get_nsfs_with_cap(req_capabilities)
    except BaseException as e:
        assert_error(f'Failed query to NSF catalogue, {e}', '', hsplid)
        return

    print('REQUIRED CAPABILITIES: ', req_capabilities)
    print('SUITABLE NSFS: ', suitable_nsfs)

    suitable_devices = []

    suitable_nsfs_of_device = {}

    for path in paths:
        suit_dev_in_path = set()
        for device in path:
            dev_nsfs = get_device_nsf_list(device)
            sn = [n for n in dev_nsfs if n in suitable_nsfs]
            if sn:
                sn.sort()
                suitable_nsfs_of_device[device] = sn
                suit_dev_in_path.add(device)

        if (len(suit_dev_in_path) == 0):
            assert_error(
                'No suitable devices found in a path', f'Suitable NSFS : {suitable_nsfs} | Path: {path}',  hsplid)
            return

        suitable_devices.append(suit_dev_in_path)

    print('SUITABLE DEVICES: ', suitable_devices)

    if (output_paths_filename):
        # add the suitable devices to choose in the file
        obj = json.load(open(output_paths_filename, 'r'))
        obj[hsplid] = []
        for l in suitable_devices:
            obj[hsplid].append(list(l))
        json.dump(obj, open(output_paths_filename, 'w'))

    def choose_devices_to_configure(suitable_devices_list):

        # check if there is a single device to cover all the paths
        common_devices = set(suitable_devices_list[0])
        for devs in suitable_devices[1:]:
            common_devices &= devs

        print('COMMON DEVICES: ', common_devices)

        if (len(common_devices) != 0):
            cd = list(common_devices)
            cd.sort()
            selected_devices = [cd[0]]
        else:
            # add one by one if needed
            suitable_devices_list.sort(key=lambda x: len(x))
            selected_devices = set()
            for devs in suitable_devices:
                if len(devs & selected_devices) == 0:
                    l_devs = list(devs)
                    l_devs.sort()
                    selected_devices.add(l_devs[0])
                # print(selected_devices)
            selected_devices = list(selected_devices)
        return selected_devices

    if (not input_conf_filename):
        # we choose the selected devices
        selected_devices = choose_devices_to_configure(suitable_devices)
    else:
        try:
            selected_devices = json.load(
                open(input_conf_filename, 'r'))[hsplid]
        except BaseException as e:
            assert_error('Error while reading selected devices',
                         str(e), hsplid)
            return

        # check that the selected devices cover all the requirements
        set_sel_devs = set(selected_devices)
        for devs in suitable_devices:
            if (not devs & set_sel_devs):
                assert_error('Selected devices don\'t cover all the paths',
                             f'selected: {set_sel_devs} , required: {devs}', hsplid)
                return

    devices_nsfs = [get_device_nsf_list(dev) for dev in selected_devices]

    # selected_nsf = suitable_nsfs.pop()
    print('SELECTED DEVICES: ', selected_devices)

    temp_conf = env.find_template('configuration')
    for dev in selected_devices:
        temp_conf.assert_fact(
            device=dev, nsf=suitable_nsfs_of_device[dev][0], hsplid=hsplid)

    # env.assert_string(f'(Configure {device} {mode})')
    # env.assert_string(f'(NSFs {nsf})')


def path_search(source, destination, hsplid):
    source_node = None
    destination_node = None
    print(source, destination)
    if "/" in source:
        source = IPv4NetworkWithNegation(source)
        if source in subnetIP.values():
            source_node = source
        else:
            for value in subnetIP.values():
                if source.subnet_of(value):
                    source_node = value
                    break
    else:
        source_ip = IPv4Address(source)
        for value in subnetIP.values():
            if source_ip in value:
                source_node = value
                break

    if "/" in destination:
        destination = IPv4NetworkWithNegation(destination)
        if destination in subnetIP.values():
            destination_node = destination
        else:
            for value in subnetIP.values():
                if destination.subnet_of(value):
                    destination_node = value
                    break
    else:
        destination_ip = IPv4Address(destination)
        for value in subnetIP.values():
            if destination_ip in value:
                destination_node = value
                break

    try:
        print(source_node, destination_node)

        # path = nx.shortest_path(graph, source_node, destination_node)
        paths = nx.all_simple_paths(graph, source_node, destination_node)
    except nx.NodeNotFound:
        assert_error('Node not present in the network topology graph',
                     f'Source: {source_node}, Destination: {destination_node}', hsplid)
        return

    all_paths = []
    for path in paths:
        # remove src and dst
        all_paths.append(path[1:-1])

    return all_paths


def swap_cap_src_dest(capabilities):
    # swap source and destination ips
    for i in range(len(capabilities)):
        cap = capabilities[i]
        if cap['capability'] == 'IpDestinationAddressConditionCapability':
            nc = cap.copy()
            nc['capability'] = 'IpSourceAddressConditionCapability'
            capabilities[i] = nc
        if cap['capability'] == 'IpSourceAddressConditionCapability':
            nc = cap.copy()
            nc['capability'] = 'IpDestinationAddressConditionCapability'
            capabilities[i] = nc
    return capabilities


def generate_rules(conf, required_capabilities):
    device = conf['device']
    hsplid = conf['hsplid']
    nsf = conf['nsf']

    req_cap = []
    modes = []
    for x in required_capabilities:
        nc = {
            'capability': x['capability'],
            'detail': x['detail']
        }
        req_cap.append(nc)

        cap = x['capability']

        if (cap == 'RejectActionCapability' or cap == 'AcceptActionCapability'):
            modes.append('FILTER')

        if (cap == 'EncryptionActionCapability'):
            modes.append('CONFIDENTIALITY')

        if (cap == 'DataAuthenticationActionCapability'):
            modes.append('INTEGRITY')

    print(modes)

    capabilities = []

    if ('FILTER' in modes):
        # filter case

        # check if the selected nsf support stateful filter rules
        stateful_nsf = get_nsfs_with_cap(['AppendRuleActionCapability',
                                          'MatchActionCapability', 'ConnTrackStateConditionCapability'])

        stateful = nsf in stateful_nsf

        stateful = False

        cap_forward = req_cap.copy()
        cap_backward = req_cap.copy()

        if (stateful):
            cap_forward.append({'capability': 'MatchActionCapability',
                                'detail': 'conntrack'})
            cap_forward.append({'capability': 'ConnTrackStateConditionCapability',
                                'detail': 'NEW,ESTABLISHED'})

            cap_backward.append({'capability': 'MatchActionCapability',
                                 'detail': 'conntrack'})
            cap_backward.append({'capability': 'ConnTrackStateConditionCapability',
                                 'detail': 'ESTABLISHED,RELATED'})

        # swap source and destination in backward rule
        cap_backward = swap_cap_src_dest(cap_backward)

        capabilities.append(cap_forward)
        capabilities.append(cap_backward)

    elif ('CONFIDENTIALITY' in modes or 'INTEGRITY' in modes):

        confidentiality = 'CONFIDENTIALITY' in modes
        integrity = 'INTEGRITY' in modes

        spi = os.urandom(4)
        req_cap.append({'capability': 'PolicySpiConditionCapability',
                       'detail': '0x'+spi.hex()})

        sec_association_forw = req_cap.copy()
        sec_association_back = req_cap.copy()
        sec_policy_forw = req_cap.copy()
        sec_policy_back = req_cap.copy()

        sec_ass = {'capability': 'IpSecRuleTypeActionCapability',
                   'detail': 'SecurityAssociation'}
        sec_association_forw.append(sec_ass)
        sec_association_back.append(sec_ass)

        sec_pol = {'capability': 'IpSecRuleTypeActionCapability',
                   'detail': 'SecurityPolicy'}
        sec_policy_forw.append(sec_pol)
        sec_policy_back.append(sec_pol)

        key = os.urandom(16).hex()

        add_ass_cap = []
        add_pol_cap = []
        if (confidentiality and integrity):
            # both confidentiality and integrity -> esp, ah
            add_ass_cap.append({'capability': 'AEADActionCapability',
                                'detail': 'aeadAlgoMode mode gcm16 algoAEAD aes128'})
            add_ass_cap.append({'capability': 'AEADActionCapability',
                                'detail': 'key ' + key})
            add_ass_cap.append({'capability': 'IpProtocolTypeConditionCapability',
                                'detail': 'esp, ah'})

            add_pol_cap.append({'capability': 'IpProtocolTypeConditionCapability',
                                'detail': 'esp, ah'})
            add_pol_cap.append({'capability': 'PacketEncapsulationActionCapability',
                                'detail': 'transport'})
            add_pol_cap.append({'capability': 'PolicyDirConditionCapability',
                                'detail': 'fwd'})
        elif (confidentiality):
            # confidentiality -> esp
            add_ass_cap.append({'capability': 'EncryptionActionCapability',
                                'detail': 'encAlgoMode mode cbc algoEnc aes128'})
            add_ass_cap.append({'capability': 'EncryptionActionCapability',
                                'detail': 'key ' + key})
            add_ass_cap.append({'capability': 'IpProtocolTypeConditionCapability',
                                'detail': 'esp'})

            add_pol_cap.append({'capability': 'IpProtocolTypeConditionCapability',
                                'detail': 'esp'})
            add_pol_cap.append({'capability': 'PacketEncapsulationActionCapability',
                                'detail': 'transport'})
            add_pol_cap.append({'capability': 'PolicyDirConditionCapability',
                                'detail': 'fwd'})
        elif (integrity):
            # integrity -> ah
            add_ass_cap.append({'capability': 'DataAuthenticationActionCapability',
                                'detail': 'authAlgoMode mode hmac algoHash sha256'})
            add_ass_cap.append({'capability': 'DataAuthenticationActionCapability',
                                'detail': 'key ' + key})
            add_ass_cap.append({'capability': 'IpProtocolTypeConditionCapability',
                                'detail': 'ah'})

            add_pol_cap.append({'capability': 'IpProtocolTypeConditionCapability',
                                'detail': 'ah'})
            add_pol_cap.append({'capability': 'PacketEncapsulationActionCapability',
                                'detail': 'transport'})
            add_pol_cap.append({'capability': 'PolicyDirConditionCapability',
                                'detail': 'fwd'})

        for cap in add_ass_cap:
            sec_association_forw.append(cap)
            sec_association_back.append(cap)

        for cap in add_pol_cap:
            sec_policy_forw.append(cap)
            sec_policy_back.append(cap)

        # swap source and destination in backward rules
        sec_association_back = swap_cap_src_dest(sec_association_back)
        sec_policy_back = swap_cap_src_dest(sec_policy_back)

        capabilities += [sec_association_forw, sec_association_back,
                         sec_policy_forw, sec_policy_back]
    else:
        raise BaseException('not implemented')

    rules = []
    for cap in capabilities:
        rules.append({
            'hsplid': hsplid,
            'device': device,
            'nsf': nsf,
            'capabilities': cap
        })

    return rules


def main(policy_filename, output_filename, output_paths_filename, input_conf_filename):
    build_graph()
    env.define_function(entity_analysis, name='entity-analysis')
    env.define_function(lambda ip_src, ip_dst, hsplid: find_configuration(
        ip_src, ip_dst, hsplid, output_paths_filename=output_paths_filename, input_conf_filename=input_conf_filename), name='find-configuration')
    env.define_function(add_entity_req_capabilities,
                        name='add-entity-req-capabilities')
    env.define_function(lambda s: s.split()[0], name='get-start-time')
    env.define_function(lambda s: s.split()[1], name='get-stop-time')

    if (output_paths_filename):
        # to export the possible comnfiguration we start from an empty object
        json.dump({}, open(output_paths_filename, 'w'))

    for rule in RULES:
        env.build(rule)

    file = et.parse(policy_filename)
    hspl_list = file.getroot()

    for hspl in hspl_list.iterfind('.//{http://fishy-project.eu/hspl}hspl'):

        parsed, optional_fields = parse_hspl(hspl)
        temp = env.find_template('hspl')
        temp_opt = env.find_template('option')

        temp.assert_fact(**parsed)
        for field, value in optional_fields:
            temp_opt.assert_fact(hsplid=parsed['id'], type=field, value=value)

    env.run()

    print('--------------')

    # object to save as intermediate.json
    facts_dict = {}

    for fact in env.facts():
        print(fact)

        if (fact.template.name not in facts_dict):
            facts_dict[fact.template.name] = []
        facts_dict[fact.template.name].append(dict(fact))

    print('--------------')

    if('error' in facts_dict or 'configuration' not in facts_dict):
        print('something went wrong')
        print(facts_dict)
        exit(1)

    intermediate = []

    for configuration in facts_dict['configuration']:
        hsplid = configuration['hsplid']

        req_cap = list(filter(lambda c: c['hsplid'] == hsplid,
                              facts_dict['reqcapability']))

        intermediate += generate_rules(configuration, req_cap)

    print(intermediate)
    if (output_filename):
        json.dump(intermediate, open(output_filename, 'w'))

    return


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('policy_filename',
                        help='the xml input file with the hspl policies')
    parser.add_argument('-o', dest='output_filename',
                        help='filename of the json output')
    parser.add_argument('--paths-info', dest='output_paths_filename',
                        help='filename to save the suitable paths to choose from')
    parser.add_argument('--choosen-conf', dest='input_conf_filename',
                        help='filename with the choosen configurations to use')
    args = parser.parse_args()

    main(args.policy_filename, args.output_filename,
         args.output_paths_filename, args.input_conf_filename)
