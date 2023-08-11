from ipaddress import IPv4Address, IPv4Network


class IPv4NetworkWithNegation(IPv4Network):
    negated = False

    def __init__(self, *args, **kwargs):
        new_args = list(args)
        if (new_args[0][0] == '~'):
            new_args[0] = new_args[0][1:]
            self.negated = True
        if ('negated' in kwargs):
            self.negated = kwargs['negated']
            del kwargs['negated']
        super(IPv4NetworkWithNegation, self).__init__(*new_args, **kwargs)

    def __contains__(self, key):
        in_sub = IPv4Network.__contains__(self, key)
        if (self.negated):
            in_sub = not in_sub
        return in_sub

    def __eq__(self, obj):
        return IPv4Network.__eq__(self, obj) and obj.is_negated() == self.negated

    def __hash__(self):
        return IPv4Network.__hash__(self)

    def __str__(self):
        prefix = ''
        if (self.negated):
            prefix = '~'
        return prefix + IPv4Network.__str__(self)

    def subnet_of(a, b):
        neg_a = a.negated
        neg_b = b.is_negated()
        if (not neg_a and not neg_b):
            return IPv4Network.subnet_of(a, b)
        elif (neg_a and neg_b):
            return IPv4Network.supernet_of(a, b)

        # one negated the other one no
        elif (neg_a):
            first_b = b.network_address
            last_b = b.broadcast_address

            first_a_0 = IPv4Address('0.0.0.0')
            last_a_0 = a.network_address
            first_a_1 = a.broadcast_address
            last_a_1 = IPv4Address('255.255.255.255')

            if (first_a_0 == last_a_0 or (first_b >= first_a_0 and last_b <= last_a_0)):
                # first interval empty or inside b
                if(first_a_1 == last_a_1 or (first_b >= first_a_1 and last_b <= last_a_1)):
                    # second interval empty or inside b
                    return True

            return False

        elif (neg_b):
            first_a = a.network_address
            last_a = a.broadcast_address

            first_b_0 = IPv4Address('0.0.0.0')
            last_b_0 = b.network_address
            first_b_1 = b.broadcast_address
            last_b_1 = IPv4Address('255.255.255.255')

            if ((first_a >= first_b_0 and last_a <= last_b_0) or (first_a >= first_b_1 and last_a <= last_b_1)):
                # inside the first interval or the second one
                return True
            return False

    def is_negated(self):
        return self.negated


class IPv4AddressWithNegation(IPv4Address):
    negated = False

    def __init__(self, *args, **kwargs):
        if ('negated' in kwargs):
            self.negated = kwargs['negated']
            del kwargs['negated']
        super(IPv4AddressWithNegation, self).__init__(*args, **kwargs)

    def is_negated(self):
        return self.negated
