import sys
import ast
import re
import pprint
from ipaddress import IPv4Address, IPv4Network
from company_database import entity_data


def main():
    file_name = sys.argv[1]

    inpFile = open(file_name, 'r')
    data = inpFile.read()
    data_dict = ast.literal_eval(data)
    for key, value in data_dict.items():
        for subkey, subvalue in value.items():
            if subkey == 'IP':
                if '/' in subvalue:
                    value[subkey] = IPv4Network(subvalue)
                else:
                    value[subkey] = IPv4Address(subvalue)
    inpFile.close()

    entity_data.update(data_dict)
    pp_sub_obj_IP = pprint.pformat(entity_data, indent=4)
    pp_sub_obj_IP = 'sub_obj_IP = '+str(pp_sub_obj_IP)
    # print(pp_sub_obj_IP)
    with open('company_database.py', 'r+') as outFile:
        old_contents = outFile.read()
        contents = re.sub(r"sub_obj_IP\s=\s{(?:{[^{}]*}|[^{}])*}",
                          pp_sub_obj_IP, old_contents, flags=re.MULTILINE | re.DOTALL)
        # print(contents)
        outFile.seek(0)
        outFile.truncate()
        outFile.write(contents)

    return


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('You should set the argument in this way:')
        print('python database_inserter.py file_to_insert.txt')
    else:
        main()
