from ipaddress import IPv4Address
from ipv4_with_negation import *


NetworkBackbone = {
    'Firewall1': ['Subnet1.1', 'SubnetDMZ', 'SubnetDecoyDMZ', 'Firewall2', 'Internet'],
    'Internet': ['SubnetAway'],
    'Firewall2': ['Subnet2.1', 'Subnet2.2', 'FirewallHP', 'VPNgateway'],
    'FirewallHP': ['SubnetHP', 'Subnet3.1', 'Internet'],
    'VPNgateway': ['Firewall3'],
    'Firewall3': ['Subnet3.1', 'Subnet3.2', 'Subnet3.3']
}

FirewallAndSubnet = {
    'Firewall1': 'firewall-1',
    'Firewall2': 'firewall-2',
    'Firewall3': 'firewall-3',
    'FirewallHP': 'firewall-HP',
    'VPNgateway': 'vpn-gateway',
    'Subnet1.1': IPv4NetworkWithNegation('10.1.1.0/24'),
    'SubnetDMZ': IPv4NetworkWithNegation('10.1.2.0/24'),
    'SubnetDecoyDMZ': IPv4NetworkWithNegation('10.1.3.0/24'),
    'Subnet2.1': IPv4NetworkWithNegation('10.2.1.0/24'),
    'Subnet2.2': IPv4NetworkWithNegation('10.2.2.0/24'),
    'Subnet3.1': IPv4NetworkWithNegation('10.3.1.0/24'),
    'Subnet3.2': IPv4NetworkWithNegation('10.3.2.0/24'),
    'Subnet3.3': IPv4NetworkWithNegation('10.3.3.0/24'),
    'SubnetHP': IPv4NetworkWithNegation('172.16.1.0/24'),
    'SubnetAway': IPv4NetworkWithNegation('172.16.0.0/24'),
    # 'Internet': IPv4NetworkWithNegation('192.168.0.0/30')
    # 'Internet': IPv4NetworkWithNegation('0.0.0.0/0')
    'Internet': IPv4NetworkWithNegation('10.0.0.0/8', negated=True)
}

DevicesNSF = {
    'firewall-1': ['XFRM', 'IpTables'],
    'firewall-2': ['IpTables'],
    'firewall-3': ['genericPacketFilter'],
    'vpn-gateway': ['XFRM', 'StrongSwan'],
    'firewall-HP': ['IpTables'],
    '10.3.3.24': ['XFRM', 'StrongSwan', 'IpTables'],
    '10.3.1.1': ['ethereumWebAppAuthz']
}

subnetIP = {
    'Subnet1.1': IPv4NetworkWithNegation('10.1.1.0/24'),
    'SubnetDMZ': IPv4NetworkWithNegation('10.1.2.0/24'),
    'SubnetDecoyDMZ': IPv4NetworkWithNegation('10.1.3.0/24'),
    'Subnet2.1': IPv4NetworkWithNegation('10.2.1.0/24'),
    'Subnet2.2': IPv4NetworkWithNegation('10.2.2.0/24'),
    'Subnet3.1': IPv4NetworkWithNegation('10.3.1.0/24'),
    'Subnet3.2': IPv4NetworkWithNegation('10.3.2.0/24'),
    'Subnet3.3': IPv4NetworkWithNegation('10.3.3.0/24'),
    'SubnetHP': IPv4NetworkWithNegation('172.16.1.0/24'),
    'SubnetAway': IPv4NetworkWithNegation('172.16.0.0/24'),

    'Internet': IPv4NetworkWithNegation('10.0.0.0/8', negated=True)
    # 'Internet': IPv4Network('0.0.0.0/0')

}

entity_data = {'Alice': IPv4Address('10.3.3.24'),
               'Bob': IPv4Address('10.1.1.12'),
               #   'Internet traffic': IPv4Network('192.168.0.0/30'),
               'Internet traffic': IPv4NetworkWithNegation('10.0.0.0/8', negated=True),
               'Malicious_User': {'DID': 'CnWZ2pmT6adiW8YEg2znCT',
                                  'IP': IPv4NetworkWithNegation('192.168.0.0/30'),
                                  'WID': '0x38fE4036a3cB5fF2C3f4bF4c5D400f6c57016Dd0'},
               'Malicious_User1': {'IP': IPv4NetworkWithNegation('192.168.0.0/16')},
               'Malicious_User2': {'WID': '0x38fE4036a3cB5fF2C3f4bF4c5D400f6c57016Dd0'},
               'Malicious_User3': {'DID': '0dJsYFQRP2PjEcitqDaGfO',
                                   'IP': IPv4NetworkWithNegation('192.168.0.0/30'),
                                   'WID': '0x4O80aEvsmqoI2tPKwClmrEY33yU79QVpdPn1ONFa'},
               'Subnet1.1': IPv4NetworkWithNegation('10.1.1.0/24'),
               'Subnet2.1': IPv4NetworkWithNegation('10.2.1.0/24'),
               'Subnet2.2': IPv4NetworkWithNegation('10.2.2.0/24'),
               'Subnet3.1': IPv4NetworkWithNegation('10.3.1.0/24'),
               'Subnet3.2': IPv4NetworkWithNegation('10.3.2.0/24'),
               'Subnet3.3': IPv4NetworkWithNegation('10.3.3.0/24'),
               'SubnetAway': IPv4NetworkWithNegation('172.16.0.0/24'),
               'SubnetDMZ': IPv4NetworkWithNegation('10.1.2.0/24'),
               'SubnetDecoyDMZ': IPv4NetworkWithNegation('10.1.3.0/24'),
               'SubnetHP': IPv4NetworkWithNegation('172.16.1.0/24'),
               'Web App': IPv4Address('10.3.1.1')}

sub_obj_URL = {
    'Charlie': 'www.charlie-domain.com',
    'Web App': 'www.webappsyn.com'
}

objectsINFO = {
    'DNS traffic': ['DestinationType DNS', 'IpProtocolTypeConditionCapability udp', 'DestinationPortConditionCapability 53'],
    'Web App': ['IpProtocolTypeConditionCapability tcp,udp', 'DestinationPortConditionCapability 9999'],
    #todo what follows is my addition, these were in info_database.py
    'VoIP traffic': ['DestinationType VoIP', 'IpProtocolTypeConditionCapability udp', 'DestinationPortConditionCapability 5060'],
    'Intranet traffic': ['DestinationType Intranet'],
    'All traffic': ['DestinationType All']
}

# protectionALGO = {
#     'Encryption': {'mode': 'cbc',
#                    'algoEnc': 'aes128',
#                    'key': os.urandom(16)},
#     'Authentication': {'mode': 'hmac',
#                        'algoHash': 'sha256',
#                        'key': os.urandom(20)},
#     'ConfAuth': {'mode': 'gcm16',
#                  'algoAEAD': 'aes128',
#                  'key': os.urandom(16)}
# }
