import os
import sys
import xml.etree.ElementTree as et
import json

# et.register_namespace('', "http://www.w3.org/2001/XMLSchema-instance")


def rule_analysis(block, output_folder):
    policy = None
    rule_id = 0

    print(block)
    nsf = block['nsf']
    device = block['device']
    file_name = device + '_' + nsf + '_RuleInstance.xml'

    if os.path.exists(output_folder + os.sep + file_name):
        file = et.parse(output_folder + os.sep + file_name)
        policy = file.getroot()
        rule_id = policy.findall('rule')[-1].get('id')
        rule_id = int(rule_id) + 1
    else:
        attr_qname = et.QName(
            "http://www.w3.org/2001/XMLSchema-instance", "noNamespaceSchemaLocation")
        policy = et.Element(
            "policy", {attr_qname: "language_" + nsf + ".xml"}, nsfName=nsf)
        if "generic" in nsf.lower():
            policy.set('targetRuleSet', 'INPUT')
        elif "xfrm" in nsf.lower():
            policy.set('ipSecAction', 'add')
        rule_id = 0

    rule = et.SubElement(policy, "rule", id=str(rule_id))

    for cap in block['capabilities']:
        if cap['detail'] == '':
            et.SubElement(rule, cap['capability'])
        else:
            # line = line.split()
            if ("ip" in cap['capability'].lower()) and ("address" in cap['capability'].lower()):
                capability = et.SubElement(rule, cap['capability'])
                capabilityIpValue = et.SubElement(
                    capability, "capabilityIpValue")
                negated = False
                ip = cap['detail']
                if (ip[0] == '~'):
                    negated = True
                    ip = ip[1:]
                if "/" in ip:
                    capability.set('operator', 'rangeCIDR')
                    rangeCIDR = et.SubElement(capabilityIpValue, "rangeCIDR")
                    et.SubElement(
                        rangeCIDR, "address").text = ip.split("/")[0]
                    et.SubElement(
                        rangeCIDR, "maskCIDR").text = ip.split("/")[1]
                else:
                    capability.set('operator', 'exactMatch')
                    et.SubElement(capabilityIpValue,
                                  "exactMatch").text = ip
                if negated:
                    et.SubElement(capabilityIpValue,
                                  "operation").text = 'NOT_EQUAL_TO'
            elif (("encryption" in cap['capability'].lower() or
                   "authentication" in cap['capability'].lower() or
                   "aead" in cap['capability'].lower()) and ("action" in cap['capability'].lower())):
                if "algomode" in cap['detail'].lower():
                    capability = et.SubElement(rule, cap['capability'])
                    line = [cap['capability']] + cap['detail'].split()
                    algoMode = et.SubElement(capability, line[1])
                    if "mode" in line[2].lower():
                        et.SubElement(algoMode, line[2]).text = line[3]
                        et.SubElement(algoMode, line[4]).text = line[5]
                    else:
                        et.SubElement(algoMode, line[2]).text = line[3]
                elif "key" in line[1].lower():
                    et.SubElement(capability, line[1]).text = line[2]
            elif "ipsecruletype" in cap['capability'].lower():
                rule.set('ruleType', cap['detail'])
            else:
                capability = et.SubElement(rule, cap['capability'])
                capabilityValue = et.SubElement(capability, "capabilityValue")
                if len(cap['detail'].split(',')) == 1:
                    et.SubElement(capabilityValue,
                                  "exactMatch").text = cap['detail']
                    capability.set('operator', 'exactMatch')
                else:
                    values = cap['detail'].split(',')
                    capability.set('operator', 'union')
                    union = et.SubElement(capabilityValue, "union")
                    for value in values:
                        et.SubElement(union, "elementValue").text = value

    tree = et.ElementTree(policy)
    # et.indent(tree, space="\t", level=0)
    tree.write(output_folder + os.sep + file_name)
    return


def main(intermediate_file, output_folder):
    if (os.path.exists(output_folder)):
        print('Error, output folder already exists')
        return
    else:
        os.makedirs(output_folder)

    intermediate = json.load(open(intermediate_file, 'r'))

    for rule in intermediate:
        rule_analysis(rule, output_folder)

    return


if __name__ == '__main__':
    intermediate_file = sys.argv[1]
    output_folder = sys.argv[2]
    main(intermediate_file, output_folder)
