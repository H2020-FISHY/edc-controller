import os
import sys
import random
import xml.etree.ElementTree as et

# et.register_namespace('', "http://www.w3.org/2001/XMLSchema-instance")


def block_analysis(block):
    new_block = ""
    policy = ""
    file_name = ""
    rule_id = 0
    nsf = ""
    for line in block.splitlines():
        line = line[1:-1]  # Remove first and last parenthesis from each line
        line = line[0].lower() + line[1:]   # Transform first letter of capability in lower case
        if "nsfs" in line.lower():
            possible_NSFs = line[5:].split(',')  # Remove "NSFs " from the beginning and if present more than 1 NSFs configurable it separates them
            if len(possible_NSFs) != 1:
                nsf = random.choice(possible_NSFs)
            else:
                nsf = possible_NSFs
            nsf = ''.join(nsf)
        elif "configure" in line.lower():
            start = line.find("configure ") + len("configure ")
            end = line.find(" from")
            device = line[start:end].replace(' ', '_')
            file_name = device + '_' + nsf + '_RuleInstance.xml'
            if os.path.exists(".."+os.sep+"RuleInstance"+os.sep+file_name):
                file = et.parse(".."+os.sep+"RuleInstance"+os.sep+file_name)
                policy = file.getroot()
                rule_id = policy.findall('rule')[-1].get('id')
                rule_id = int(rule_id) + 1
            else:
                attr_qname = et.QName("http://www.w3.org/2001/XMLSchema-instance", "noNamespaceSchemaLocation")
                policy = et.Element("policy", {attr_qname: "language_" + nsf + ".xml"}, nsfName=nsf)
                if "generic" in nsf.lower():
                    policy.set('targetRuleSet', 'INPUT')
                elif "xfrm" in nsf.lower():
                    policy.set('ipSecAction', 'add')
                rule_id = 0
        elif "hspl" in line.lower():
            pass
        else:
            new_block = new_block + line + '\n'

    rule = et.SubElement(policy, "rule", id=str(rule_id))
    for line in new_block.splitlines():
        if len(line.split()) == 1:
            et.SubElement(rule, line)
        else:
            line = line.split()
            if ("ip" in line[0].lower()) and ("address" in line[0].lower()):
                capability = et.SubElement(rule, line[0])
                capabilityIpValue = et.SubElement(capability, "capabilityIpValue")
                if "/" in line[1]:
                    capability.set('operator', 'rangeCIDR')
                    rangeCIDR = et.SubElement(capabilityIpValue, "rangeCIDR")
                    et.SubElement(rangeCIDR, "address").text = line[1].split("/")[0]
                    et.SubElement(rangeCIDR, "maskCIDR").text = line[1].split("/")[1]
                else:
                    capability.set('operator', 'exactMatch')
                    et.SubElement(capabilityIpValue, "exactMatch").text = line[1]
            elif (("encryption" in line[0].lower() or
                   "authentication" in line[0].lower() or
                   "aead" in line[0].lower()) and ("action" in line[0].lower())):
                if "algomode" in line[1].lower():
                    capability = et.SubElement(rule, line[0])
                    algoMode = et.SubElement(capability, line[1])
                    if "mode" in line[2].lower():
                        et.SubElement(algoMode, line[2]).text = line[3]
                        et.SubElement(algoMode, line[4]).text = line[5]
                    else:
                        et.SubElement(algoMode, line[2]).text = line[3]
                elif "key" in line[1].lower():
                    et.SubElement(capability, line[1]).text = line[2]
            elif "ipsecruletype" in line[0].lower():
                rule.set('ruleType', line[1])
            else:
                capability = et.SubElement(rule, line[0])
                capabilityValue = et.SubElement(capability, "capabilityValue")
                if len(line[1].split(',')) == 1:
                    et.SubElement(capabilityValue, "exactMatch").text = line[1]
                    capability.set('operator', 'exactMatch')
                else:
                    values = line[1].split(',')
                    capability.set('operator', 'union')
                    union = et.SubElement(capabilityValue, "union")
                    for value in values:
                        et.SubElement(union, "elementValue").text = value

    tree = et.ElementTree(policy)
    et.indent(tree, space="\t", level=0)
    tree.write(".."+os.sep+"RuleInstance"+os.sep+file_name)
    return


def main():
    directory = '..'+os.sep+'RuleInstance'
    if os.path.exists(directory):
        for f in os.listdir(directory):
            os.remove(os.path.join(directory, f))
    else:
        os.makedirs(directory)
    file = open(sys.argv[1], "r")
    content = file.read()
    blocks = content.split('-------------------------\n')
    for block in blocks:
        if block:
            block_analysis(block)
    file.close()
    return


if __name__ == '__main__':
    main()
