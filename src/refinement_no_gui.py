import sys
import clips
import re
import requests
import ipaddress
import random

import networkx as nx
import socket as s
from rules_old import RULES, TEMPLATES
from company_database_old import *
from info_database import INFO_obj
from colorama import Fore, init
import xml.etree.ElementTree as et

init(autoreset=True)

API_ENDPOINT = "host.docker.internal"
ENV_API_ENDPOINT = os.environ.get("API_ENDPOINT")
if ENV_API_ENDPOINT is not None and isinstance(ENV_API_ENDPOINT, str):
    API_ENDPOINT = ENV_API_ENDPOINT

IP_address_NSF_catalogue = API_ENDPOINT

# template_hspl = {}

# Global variable to distinguish between filter, protection, enable etc.
case = ''

# Global variable to configure INPUT and OUTPUT chain
position = ''

# Used in start_path_search and device_configuration_selection
near_configuration = False

multiple_device_conf = False

env = clips.Environment()
for template in TEMPLATES:
    env.build(template)

graph = nx.Graph()


def subject_analysis(sub):
    print('    subject_analysis()')

    #sub = template_hspl['subject']
    if len(sub.split()) != 1:  # If there are more than one subject
        subject_list = sub.split()
        if subject_list[0] == 'All':  # Case: All except .....
            included_subject = []
            for sub, value in sub_obj_IP.items():
                if "Subnet" in sub:
                    included_subject.append(value)
            assert subject_list[1] == 'except'
            subject_list = subject_list[2:]
            excluded_subject = []
            for i in range(len(subject_list)):
                # Even positions are excluded subjects and odd positions are logical operators
                if i % 2 == 0:
                    if subject_list[i] in sub_obj_IP:
                        excluded_subject.append(
                            sub_obj_IP[subject_list[i]])
                    else:
                        try:
                            ip_found = s.gethostbyname(
                                sub_obj_URL[subject_list[i]])
                        except s.gaierror:
                            print(
                                Fore.RED+"SubjectURL can't be resolved in an IP address")
                            env.assert_string('(Error)')
                            return 1
                        subject_ip = IPv4Address(ip_found)
                        excluded_subject.append(subject_ip)
            found_subjects = list(set(included_subject) &
                                  set(excluded_subject))
            included_difference = list(
                set(included_subject) - set(found_subjects))
            excluded_difference = list(
                set(excluded_subject) - set(found_subjects))
            if len(excluded_difference) != 0:
                for sub in excluded_difference:
                    env.assert_string('(ExcludeIP ' + str(sub) + ')')
            for sub in included_difference:
                env.assert_string('(IPSource ' + str(sub) + ')')
        else:  # Case: Subject and Subject except ...
            except_split = sub.split(' except ')
            if len(except_split) == 2:  # If there is an 'except'
                included_subjects = except_split[0].split(' and ')
                for pos_sub in included_subjects:
                    database_subject_search(pos_sub, False)
                excluded_subjects = except_split[1].split(' and ')
                for exc_sub in excluded_subjects:
                    database_subject_search(exc_sub, True)
            else:  # There is/are only 'and'
                included_subjects = except_split[0].split(' and ')
                for pos_sub in included_subjects:
                    database_subject_search(pos_sub, False)
    else:  # There is only 1 subject
        database_subject_search(sub, False)
    env.assert_string('(Sources done)')
    return


def object_filter_protection_analysis(obj):
    print('    object_filter_protection_analysis()')

    #obj = template_hspl['object']
    if obj in sub_obj_IP:
        env.assert_string('(IPDestination ' + str(sub_obj_IP[obj]) + ')')
    elif obj in sub_obj_URL:
        env.assert_string('(URLDestination ' + str(sub_obj_URL[obj]) + ')')
    # First search in company_database.py (company related) for info regarding objects
    found = False
    for key, value in objectsINFO.items():
        if obj == key:
            found = True
            for i in value:
                env.assert_string('(' + i + ')')
            break
    # then if not found info in company_database.py look up in info_database.py (generic, not related to company)
    if not found:
        for key, value in INFO_obj.items():
            if obj == key:
                for i in value:
                    env.assert_string('(' + i + ')')
                break
    if "Intranet" in obj:
        for subnet in subnetIP.values():
            env.assert_string('(IPDestination ' + str(subnet) + ')')
    elif "P2P" in obj:
        print("P2P traffic")  # TODO: identify P2P traffic
    elif "3G/4G" in obj:
        print("3G/4G traffic")  # TODO: identify 3G/4G traffic
    env.assert_string('(Destinations done)')
    return


def start_path_search():
    print('    start_path_search()')
    sources = []
    destinations = []
    global near_configuration
    global multiple_device_conf
    for fact in env.facts():
        if "IPSource" == fact.template.name:
            sources.append(fact[0])
            continue
        elif "DestinationType" == fact.template.name:
            near_configuration = True
            destinations.append(fact[0])
        elif "IPDestination" == fact.template.name:
            destinations.append(fact[0])
            continue
    if not destinations:
        # Default route is towards Internet
        destinations.append('192.168.0.0/16')
    if not sources:
        sources.append('192.168.0.0/16')   # Default route is towards Internet

    if len(sources) > 1 or len(destinations) > 1:
        multiple_device_conf = True
        env.assert_string('(BlockPrint)')

    if not near_configuration:
        for source in sources:
            for destination in destinations:
                path_search(source, destination)
    else:
        # Case near configuration: there isn't a path, should be configured the nearest device
        for source in sources:
            path = []
            if "/" in source:
                source_ip = IPv4Network(source)
            else:
                source_ip = IPv4Address(source)
                for value in subnetIP.values():
                    if source_ip in value:
                        source_ip = value
                        break
            for neighbor in graph.neighbors(source_ip):
                path.append(neighbor)
            path.append(source)
            for destination in destinations:
                fail = device_configuration_selection(
                    path, source, destination)
                if fail:
                    env.assert_string('(Error)')
                    return 1
    return


def path_search(source, destination):
    print('    path_search()')

    if "/" in source:
        source_ip = IPv4Network(source)
    else:
        source_ip = IPv4Address(source)
        for value in subnetIP.values():
            if source_ip in value:
                source_ip = value
                break

    if "/" in destination:
        destination_ip = IPv4Network(destination)
    else:
        destination_ip = IPv4Address(destination)
        for value in subnetIP.values():
            if destination_ip in value:
                destination_ip = value
                break

    # Just to avoid warning: Local variable 'path' might be referenced before assignment
    path = []

    try:
        path = nx.shortest_path(graph, source_ip, destination_ip)
    except nx.NodeNotFound:
        for key, value in sub_obj_IP.items():
            if "Internet" in key:
                source_ip = value
                try:
                    path = nx.shortest_path(graph, source_ip, destination_ip)
                except nx.NodeNotFound:
                    print('Destination not present in the network topology graph.')
                    env.assert_string('(Error)')
                    return 1
                break

    # Remove first and last element from path (source_ip and destination_ip) and add source and destination.
    # NOTE: source_ip and destination_ip are IPv4Network elements we need source and destination that are strings.
    path = path[1:-1]
    path.insert(0, source)
    path.append(destination)

    # print("PATH:")
    # print(path)
    fail = device_configuration_selection(path, source, destination)
    if fail:
        env.assert_string('(Error)')
        return 1
    return


def device_configuration_selection(path, source, destination):
    print('    device_configuration_selection()')
    global case
    advanced_capabilities = ''
    for fact in env.facts():
        if fact.template.name == 'Case':
            case = fact[0]
    facts = []
    for fact in env.facts():
        facts.append(str(fact))
    facts = ' '.join(facts)
    required_capabilities = re.findall(r'\w*Capability+', facts)
    required_capabilities = ','.join(required_capabilities)
    # I need these capabilities because I have a source and a destination, the real capability is added
    # below in this function before printing.
    required_capabilities = required_capabilities + \
        ',IpSourceAddressConditionCapability,IpDestinationAddressConditionCapability'
    if case == 'filtering':
        # required_capabilities = required_capabilities + ',AppendRuleActionCapability'
        advanced_capabilities = required_capabilities + \
            ',AppendRuleActionCapability,MatchActionCapability,ConnTrackStateConditionCapability'
    print("REQUIRED CAPABILITIES:")
    print(required_capabilities)

    # Control variable to display popup error in case no device supports required capabilities
    fail = True

    response = ""
    response_stateful = ""
    devices = []

    for device in path:
        if device not in DevicesNSF:
            continue
        device_NSFs = DevicesNSF[device]
        found = False
        params = {'run': 'capa_set_search.xq',
                  'capa_set': required_capabilities}

        print('REQUIRED CAPABILITIES: ', required_capabilities)
        try:
            response = requests.get(
                'http://'+IP_address_NSF_catalogue+':8984/rest', params=params, auth=('admin', 'admin'))
        except requests.exceptions.RequestException as e:
            print("ERROR: Can't contact NSF-Catalogue.")
            env.assert_string('(Error)')
            sys.exit(e)
        if any(nsf in response.text for nsf in device_NSFs):
            found = True
        if found:
            fail = False
            if case == 'filtering':
                params = {'run': 'capa_set_search.xq',
                          'capa_set': advanced_capabilities}
                response_stateful = requests.get(
                    'http://'+IP_address_NSF_catalogue+':8984/rest', params=params, auth=('admin', 'admin'))
                if any(nsf in response_stateful.text for nsf in device_NSFs):
                    devices.append(device+' stateful')
                else:
                    devices.append(device+' stateless')
            else:
                devices.append(device)

    if fail:
        params = {'run': 'capa_set_search.xq',
                  'capa_set': required_capabilities}
        requests.get('http://'+IP_address_NSF_catalogue +
                     ':8984/rest', params=params, auth=('admin', 'admin'))
        # TODO: add logging to signal this error
        # print(Fore.RED + 'These are the NSFs that supports the required capabilities:')
        # print(Fore.RED + response.text)

        env.assert_string('(Error)')
        return 1

    global multiple_device_conf
    if len(devices) > 1:
        multiple_device_conf = True
        env.assert_string('(BlockFinalPrint)')
        device = random.choice(devices)
    else:
        device = devices[0]

    global position
    selectable_NSFs = []
    if "stateful" in device:
        device_name = device.split()[0]
        device_NSFs = DevicesNSF[device_name]
        for nsf in device_NSFs:
            if nsf in response_stateful.text:
                selectable_NSFs.append(nsf)
    elif "stateless" in device:
        device_name = device.split()[0]
        device_NSFs = DevicesNSF[device_name]
        for nsf in device_NSFs:
            if nsf in response.text:
                selectable_NSFs.append(nsf)
    else:
        device_NSFs = DevicesNSF[device]
        for nsf in device_NSFs:
            if nsf in response.text:
                selectable_NSFs.append(nsf)
    selectable_NSFs = " ".join(selectable_NSFs)
    env.assert_string('(NSFs '+selectable_NSFs+')')
    if near_configuration:
        env.assert_string(
            '(IpDestinationAddressConditionCapability 0.0.0.0/0)')
    elif not near_configuration:
        env.assert_string(
            '(IpDestinationAddressConditionCapability ' + destination + ')')
    env.assert_string('(IpSourceAddressConditionCapability ' + source + ')')
    if ("stateful" in device) and (case == 'filtering'):
        env.assert_string('(MatchActionCapability conntrack)')
        env.assert_string(
            '(ConnTrackStateConditionCapability NEW,ESTABLISHED)')
        device_position_identification(device, path)
    elif ("stateless" in device) and (case == 'filtering'):
        position = 'STATELESS'
        multiple_device_conf = True
        env.assert_string('(BlockFinalPrint)')
    elif case == 'protection':
        position = 'STATE'
        multiple_device_conf = True
        env.assert_string('(BlockFinalPrint)')
    env.assert_string('(Configure ' + device + ' from ' +
                      source + ' to ' + destination + ')')
    if multiple_device_conf:
        print('A'*500)
        multiple_device_facts_printer()
    if case == 'protection':
        path_middle = path[1:-1]
        if IPv4Network('192.168.0.0/16') in path_middle:
            env.assert_string('(PacketEncapsulationActionCapability tunnel)')
        else:
            env.assert_string(
                '(PacketEncapsulationActionCapability transport)')
        device_position_identification(device, path)
        print('B'*500)
        multiple_device_facts_printer()
    return


def device_position_identification(device, path):
    print('    device_position_identification()')
    global position
    global multiple_device_conf
    if not near_configuration:
        if path[0] in device:
            if case == 'filtering':
                env.assert_string('(AppendRuleActionCapability OUTPUT)')
                position = 'INPUT'
            elif case == 'protection':
                env.assert_string('(PolicyDirConditionCapability in)')
                env.assert_string('(TemplateConditionCapability)')
                env.assert_string(
                    '(IpSecRuleTypeActionCapability SecurityPolicy)')
                position = 'out'
            multiple_device_conf = True
            env.assert_string('(BlockFinalPrint)')
        elif path[-1] in device:
            if case == 'filtering':
                env.assert_string('(AppendRuleActionCapability INPUT)')
                position = 'OUTPUT'
            elif case == 'protection':
                env.assert_string('(PolicyDirConditionCapability out)')
                env.assert_string('(TemplateConditionCapability)')
                env.assert_string(
                    '(IpSecRuleTypeActionCapability SecurityPolicy)')
                position = 'in'
            multiple_device_conf = True
            env.assert_string('(BlockFinalPrint)')
        else:
            if case == 'filtering':
                env.assert_string('(AppendRuleActionCapability FORWARD)')
                position = 'FORWARD'
            elif case == 'protection':
                env.assert_string('(PolicyDirConditionCapability fwd)')
                env.assert_string('(TemplateConditionCapability)')
                env.assert_string(
                    '(IpSecRuleTypeActionCapability SecurityPolicy)')
                position = 'out'
            multiple_device_conf = True
            env.assert_string('(BlockFinalPrint)')
    else:
        if path[-1] in device:
            if case == 'filtering':
                env.assert_string('(AppendRuleActionCapability OUTPUT)')
                position = 'INPUT'
            elif case == 'protection':
                env.assert_string('(PolicyDirConditionCapability in)')
                env.assert_string('(TemplateConditionCapability)')
                env.assert_string(
                    '(IpSecRuleTypeActionCapability SecurityPolicy)')
                position = 'out'
            multiple_device_conf = True
            env.assert_string('(BlockFinalPrint)')
        else:
            if case == 'filtering':
                env.assert_string('(AppendRuleActionCapability FORWARD)')
                position = 'FORWARD'
            elif case == 'protection':
                env.assert_string('(PolicyDirConditionCapability fwd)')
                env.assert_string('(TemplateConditionCapability)')
                env.assert_string(
                    '(IpSecRuleTypeActionCapability SecurityPolicy)')
                position = 'out'
            multiple_device_conf = True
            env.assert_string('(BlockFinalPrint)')
    return


def protection_algorithm_sel(action):
    print('    protection_algorithm_sel()')
    if action == "confidentiality":
        algo = protectionALGO['Encryption']['algoEnc']
        mode = protectionALGO['Encryption']['mode']
        key = protectionALGO['Encryption']['key']
        env.assert_string(
            '(EncryptionActionCapability encAlgoMode mode '+mode+' algoEnc '+algo+')')
        env.assert_string('(EncryptionActionCapability key '+key.hex()+')')
    elif action == 'integrity':
        algo = protectionALGO['Authentication']['algoHash']
        mode = protectionALGO['Authentication']['mode']
        key = protectionALGO['Authentication']['key']
        env.assert_string(
            '(DataAuthenticationActionCapability authAlgoMode mode '+mode+' algoHash '+algo+')')
        env.assert_string(
            '(DataAuthenticationActionCapability key '+key.hex()+')')
    elif action == 'confidentiality-integrity':
        algo = protectionALGO['ConfAuth']['algoAEAD']
        mode = protectionALGO['ConfAuth']['mode']
        key = protectionALGO['ConfAuth']['key']
        env.assert_string(
            '(AEADActionCapability aeadAlgoMode mode '+mode+' algoAEAD '+algo+')')
        env.assert_string('(AEADActionCapability key '+key.hex()+')')
    spi = os.urandom(4)
    env.assert_string('(IpSecRuleTypeActionCapability SecurityAssociation)')
    env.assert_string('(PolicySpiConditionCapability 0x'+spi.hex()+')')
    return


def check_destination_device(obj, capability, value, action):
    print('    check_destination_device()')
    obj_ip = str(sub_obj_IP[obj])
    if obj_ip not in DevicesNSF:
        print(Fore.RED+'Destination device has no NSF available.')
        return
    obj_NSFs = DevicesNSF[obj_ip]
    selectable_NSFs = []
    params = {'run': 'capa_set_search.xq', 'capa_set': capability}
    response = requests.get('http://'+IP_address_NSF_catalogue +
                            ':8984/rest', params=params, auth=('admin', 'admin'))
    if any(nsf in response.text for nsf in obj_NSFs):
        for nsf in obj_NSFs:
            if nsf in response.text:
                selectable_NSFs.append(nsf)
        selectable_NSFs = " ".join(selectable_NSFs)
        print('(NSFs ' + selectable_NSFs + ')')
        print('(Configure '+obj_ip+' to '+action+')')
        if action == 'deny':
            print('(RejectActionCapability)')
        elif action == 'accept':
            print('(AcceptActionCapability)')
        print('(' + capability + ' ' + value + ')')
        print('----------------')
    return


def database_subject_search(sub, exclude):
    print('    database_subject_search()')
    if exclude:
        if sub in sub_obj_IP:
            env.assert_string('(ExcludeIP ' + str(sub_obj_IP[sub]) + ')')
        elif sub in sub_obj_URL:
            env.assert_string('(ExcludeURL ' + sub_obj_URL[sub] + ')')
    else:
        if sub in sub_obj_IP:
            if isinstance(sub_obj_IP[sub], dict):
                if "IP" in sub_obj_IP[sub]:
                    env.assert_string(
                        '(IPSource ' + str(sub_obj_IP[sub]['IP']) + ')')
                if "WID" in sub_obj_IP[sub]:
                    env.assert_string(
                        '(WID: ' + str(sub_obj_IP[sub]['WID']) + ')')
                if "DID" in sub_obj_IP[sub]:
                    env.assert_string(
                        '(DID: ' + str(sub_obj_IP[sub]['DID']) + ')')
            else:
                env.assert_string('(IPSource ' + str(sub_obj_IP[sub]) + ')')
        elif sub in sub_obj_URL:
            env.assert_string('(URLSource ' + sub_obj_URL[sub] + ')')
        else:
            try:
                ipaddress.ip_address(sub)
            except ValueError:  # Default source when subject is not found in database, and it is not an IP address is towards Internet
                env.assert_string('(IPSource 192.168.0.0/16)')
            else:
                env.assert_string('(IPSource ' + sub + ')')
    return


def facts_printer():
    print('    facts_printer()')
    # print("facts_printer function")
    for fact in env.facts():
        if "IPSource" == fact.template.name:
            continue
        if "IPDestination" == fact.template.name:
            continue
        if "DestinationType" == fact.template.name:
            continue
        if "Configured" == fact.template.name:
            continue
        if "BlockFinalPrint" == fact.template.name:
            continue
        if "DistributedIDConditionCapability" == fact.template.name:
            continue
        if "WalletIDConditionCapability" == fact.template.name:
            continue
        if "WID:" == fact.template.name:
            continue
        if "DID:" == fact.template.name:
            continue
        if "Case" == fact.template.name:
            continue
        print(fact)
    print('-------------------------')
    return


def multiple_device_facts_printer():
    print('    multiple_device_facts_printer()')
    global position
    facts_printer()
    if case == 'filtering':
        for fact in env.facts():
            if "AppendRuleActionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "ConnTrackStateConditionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if ("MatchActionCapability" == fact.template.name) and (fact[0] != "time"):
                fact.retract()
    elif (case == 'protection') and (position != 'STATE'):
        for fact in env.facts():
            if "IpSecRuleTypeActionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "PolicyDirConditionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "EncryptionActionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "DataAuthenticationActionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "EncryptionActionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "DataAuthenticationActionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "AEADActionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "AEADActionCapability" == fact.template.name:
                fact.retract()
    if position:
        newFacts = []
        if (position != 'STATELESS') and (case == 'filtering'):
            env.assert_string('(AppendRuleActionCapability '+position+')')
            env.assert_string('(MatchActionCapability conntrack)')
            env.assert_string(
                '(ConnTrackStateConditionCapability ESTABLISHED,RELATED)')
        elif (position != 'STATE') and (case == 'protection'):
            env.assert_string(
                '(PolicyDirConditionCapability ' + position + ')')
            env.assert_string('(IpSecRuleTypeActionCapability SecurityPolicy)')
        for fact in env.facts():
            if "DestinationPortConditionCapability" in fact.template.name:
                newFacts.append(fact.template.name.replace(
                    "Destination", "Source") + ' ' + str(fact[0]))
                fact.retract()
        for fact in env.facts():
            if "SourcePortConditionCapability" in fact.template.name:
                newFacts.append(fact.template.name.replace(
                    "Source", "Destination") + ' ' + str(fact[0]))
                fact.retract()
        for fact in env.facts():
            if "IpSourceAddressConditionCapability" == fact.template.name:
                newFacts.append(fact.template.name.replace(
                    "Source", "Destination") + ' ' + str(fact[0]))
                fact.retract()
        for fact in env.facts():
            if "IpDestinationAddressConditionCapability" == fact.template.name:
                newFacts.append(fact.template.name.replace(
                    "Destination", "Source") + ' ' + str(fact[0]))
                fact.retract()
        for fact in env.facts():
            if "Configure" == fact.template.name:
                if case == 'filtering':
                    env.assert_string(
                        '(Configure '+str(fact[0])+' '+str(fact[1])+' from '+str(fact[5])+' to '+str(fact[3])+')')
                else:
                    env.assert_string(
                        '(Configure '+str(fact[0])+' from '+str(fact[4])+' to '+str(fact[2])+')')
                fact.retract()
        for fact in newFacts:
            env.assert_string('('+fact+')')
        position = ''
        multiple_device_facts_printer()
    if case == 'filtering':
        for fact in env.facts():
            if "Configure" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "IpSourceAddressConditionCapability" == fact.template.name:
                fact.retract()
        for fact in env.facts():
            if "IpDestinationAddressConditionCapability" == fact.template.name:
                fact.retract()
    return


def build_graph():
    for device, values in NetworkBackbone.items():
        for value in values:
            graph.add_edge(FirewallAndSubnet[device], FirewallAndSubnet[value])

    # These commands are to show networkx graph
    # nx.draw_networkx(graph)
    # ax = plt.gca()
    # ax.margins(0.20)
    # plt.axis("off")
    # plt.show()
    return


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


def main():
    build_graph()
    env.define_function(facts_printer, name='facts-printer')
    env.define_function(subject_analysis, name='subject-analysis')
    env.define_function(object_filter_protection_analysis,
                        name='object-filter-protection-analysis')
    env.define_function(start_path_search, name='start-path-search')
    env.define_function(check_destination_device,
                        name='check-destination-device')
    env.define_function(protection_algorithm_sel,
                        name='protection-algorithm-sel')
    for rule in RULES:
        env.build(rule)

    file = et.parse(sys.argv[1])
    hspl_list = file.getroot()
    # global template_hspl
    for reaction in hspl_list.findall('{http://fishy-project.eu/hspl}reaction'):
        for hspl in reaction.findall('{http://fishy-project.eu/hspl}hspl'):

            parsed, optional_fields = parse_hspl(hspl)
            temp = env.find_template('hspl')
            template_hspl = temp.assert_fact(**parsed)
            for field, value in optional_fields:
                env.assert_string('(Option ' + field + ' ' + value + ')')

            env.run()
            env.reset()
    for hspl in hspl_list.findall('{http://fishy-project.eu/hspl}hspl'):

        parsed, optional_fields = parse_hspl(hspl)
        temp = env.find_template('hspl')
        template_hspl = temp.assert_fact(**parsed)
        for field, value in optional_fields:
            env.assert_string('(Option ' + field + ' ' + value + ')')

        env.run()

        # multiple_device_facts_printer()

        env.reset()
    return


if __name__ == '__main__':
    if os.path.exists('..'+os.sep+'Intermediate.txt'):
        os.remove(".."+os.sep+"Intermediate.txt")
    sys.stdout = open(".."+os.sep+"Intermediate.txt", "x")
    # This is to print the first separator when first Capabilities are printed
    print('-------------------------')
    main()
    sys.stdout.close()
