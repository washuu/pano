# ideas:
# 1) if there is any nat rule without at least one ip allowed through it
# 2) if there any rules with IPs not matching the zones interfaces IPs or routing through the interfaces
# 3) if there any address objects with IP in name, and different IP in content
# 4) if there are rules with applications defined and "any" service
# 5) if there are any rules without logging
# 6) find overlapping rules
# 7) report on real ip rules
# 8) packet tracer
# 9) find vlan tags matching z in ethx/y.z
# 10) addressgroups without usage
# 11) addressgroups with the same content as shared

# co w dg: adresy, serwisy, grupy, rulki nat i security
# dg_obj[dg]['rule'][rulename][attr] = value
# dg_obj[dg]['address'][address][attr] = value
# co w template: interfejsy, zony, vpny, routing statyczny, routing per service, logowanie, panorama, network profiles, snmp, zmienne
# t_obj[t]['interface'][interface][attr] = value
# ipki sa przypisane do interfejsu. interfejsy sa przypisane do zony, zony sa przypisane do templatów, template sa przypisane do urządzeń
# template -> devices
# template -> zone -> interfaces (possibly empty list)
# template -> interface -> ip address (possibly empty list)
# template-stack -> templates

import re
import time
import sys
import paramiko


# import string, re, pwd, sys, os.path, time, getopt, glob, errno
# data structures - dictionaries:
# address - description, disable-override, ip-netmask, fqdn, ip-range, tag


def line_split(line):
    return re.findall(r'[^\"\s]\S*|\".+?\"', line)


def get_members(data):
    if '[' in data:
        a = line_split(data)
        a.remove('[')
        a.remove(']')
        return a
    return data


def line_split2(line):
    return re.findall("(?:\".*?\"|\S)+", line)


def get_ip_range(ip):
    # function expects argument in form a.b.c.d[/x|-e.f.g.h], as text.
    # returns two lists of numeric octets, respectively for first and last IP for the range.
    # alhough it looks clumsy, it's actually faster than many other implementations, and it is resistant to "non-zero host part" error.

    if '/' in ip:
        t = ip.split('/')
        mask = int(t[1])
        ip = t[0]
        start_ip = list(int(part) for part in ip.split('.'))
        k = 2**((32-mask) % 8)
        if mask >= 24:
            start_ip[3] = start_ip[3]-start_ip[3] % k
            end_ip = start_ip.copy()
            end_ip[3] = start_ip[3]+k-1
        elif mask >= 16:
            start_ip[3] = 0
            start_ip[2] = start_ip[2]-start_ip[2] % k
            end_ip = start_ip.copy()
            end_ip[2] = start_ip[2]+k-1
        elif mask >= 8:
            start_ip[3] = 0
            start_ip[2] = 0
            start_ip[1] = start_ip[1]-start_ip[1] % k
            end_ip = start_ip.copy()
            end_ip[1] = start_ip[1]+k-1
        else:
            start_ip[3] = 0
            start_ip[2] = 0
            start_ip[1] = 0
            start_ip[0] = start_ip[0]-start_ip[0] % k
            end_ip = start_ip.copy()
            end_ip[0] = start_ip[0]+k-1
    elif '-' in ip:
        t = ip.split('-')
        start_ip = t[0]
        end_ip = t[1]
        start_ip = list(int(part) for part in start_ip.split('.'))
        end_ip = list(int(part) for part in end_ip.split('.'))
    else:    # single IP
        start_ip = list(int(part) for part in ip.split('.'))
        end_ip = start_ip
    return (start_ip, end_ip)


def is_in_range(ip1, ip2):
    # function expects both arguments in form a.b.c.d[/x|-e.f.g.h], as text.
    # exit codes:
    # 0 - ip1 and ip2 are identical
    # 1 - ip1 is part of ip2
    # 2 - ip2 is part of ip1
    # 3 - ip1 and ip2 are separate
    # 4 - partial overlap
    # 5 - error, at least one IP has some formatting problem

    start_ip1, end_ip1 = get_ip_range(ip1)
    start_ip2, end_ip2 = get_ip_range(ip2)
#    print('I have IP1 range:', start_ip1, '-:', end_ip1)
#    print('I have IP2 range:', start_ip2, '-:', end_ip2)

    if start_ip1 == start_ip2:
        if end_ip1 == end_ip2: return 0
        elif end_ip1 < end_ip2: return 1
        else: return 2
    if start_ip1 < start_ip2:
        if start_ip2 > end_ip1: return 3
        if end_ip1 >= end_ip2: return 2
        else: return 4
    else:   # start_ip1>start_ip2
        if start_ip1 > end_ip2: return 3
        if end_ip1 <= end_ip2: return 1
        else: return 4


def addressInNetwork(ip, net):
    # shamelessly copied from the stackoverflow, as my solution is much longer...
    # for some reason using the module ipaddress from python 3 turned out to be one order of magnitude slower than this function.
    # unfortunately, it turned out it does not work when the host part of the IP is non-zero, so it is NOT used in the main program.
    # i left it only for reference.
    ipaddr = struct.unpack('>L', socket.inet_aton(ip))[0]
    netaddr, bits = net.split('/')
    netmask = struct.unpack('>L', socket.inet_aton(netaddr))[0]
    ipaddr_masked = ipaddr & (4294967295 << (32-int(bits)))   # Logical AND of IP address and mask will equal the network address if it matches
    if netmask == netmask & (4294967295 << (32-int(bits))):   # Validate network address is valid for mask
        return ipaddr_masked == netmask
    print("***WARNING*** Network", netaddr, "not valid with mask /"+bits)
    return ipaddr_masked == netmask



class config():


    def __init__(self):
        self.devicegroups = set()
        self.dg_inv = {}
        self.deviceid = {}
        self.parent = {}
        self.address = {}
        self.addressgroup = {}
        self.rule = {}
        self.nat = {}
        self.service = {}
        self.servicegroup = {}
        self.appgroup = {'shared':{}}

        self.templates = set()
        self.interface_zone = {}
        self.interface_ip = {}
        self.zone = {}
        self.systemip = {}
        self.tmembers = {}
        self.variable = {}

    def add_dg(self, dg):
        self.rule[dg] = {}
        self.nat[dg] = {}
        self.service[dg] = {}
        self.address[dg] = {}
        self.addressgroup[dg] = {}
        self.servicegroup[dg] = {}
        self.appgroup[dg] = {}
        self.parent[dg] = 'shared'
        self.devicegroups.add(dg)
        self.dg_inv[dg] = {}
        self.dg_inv[dg]['addresses'] = set()
        self.dg_inv[dg]['rules'] = set()
        self.dg_inv[dg]['nats'] = set()
        self.dg_inv[dg]['services'] = set()
        self.dg_inv[dg]['addressgroups'] = set()
        self.dg_inv[dg]['servicegroups'] = set()
        self.dg_inv[dg]['appgroups'] = set()
        #self.dg_obj[dg] = {}
        # print('adding dg', dg)


    def add_t(self, t):
        self.templates.add(t)
        self.interface_zone[t] = {}
        self.interface_ip[t] = {}
        self.zone[t] = {}
        self.systemip[t] = {}
        self.tmembers[t] = {}



    def load_config_ssh(self):
        hostname = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        try:
            teefile = open('pano_current.txt', 'w')
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

            client.connect(hostname, port=22, username=username, password=password)
            # stdin, stdout, stderr = client.exec_command('set cli config-output-format set')
            stdin, stdout, stderr = client.exec_command('cd proclogdir/')
            print(stdout.readlines())
            print("what is")
            print(stderr.readlines())
            stdin, stdout, stderr = client.exec_command('set cli pager off')
            print(stdout.readlines())
            print("what is2")
            print(stderr.readlines())
            stdin, stdout, stderr = client.exec_command('configure')
            print(stdout.readlines())
            print("what is3")
            print(stderr.readlines())
            stdin, stdout, stderr = client.exec_command('show')
            text = stdout.readlines()
            print(text, file=teefile)
        finally:
            client.close()
            teefile.close()


    def rules_parser(self, dg, line, regex, g):
        # g = open('W_unmatched_lines', 'a')
        # set device-group man-pa-ha post-rulebase security rules "GOLD IMAGE ID 016a-print-over-ms-smb" from Workstations
        # set device-group "AWS Singapore" pre-rulebase security rules "Softlayer and AWS-TGW - patch management" service [ TCP-8027 TCP-8031 TCP-8383 ]
        # rule_regex_global = re.compile('(?P<rtype>[a-z-]+) security rules (?P<rname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z-]+) (?P<value>.+)')
        # print("rules_parser: dostalem linie", line)
        match = regex.match(line)
        if match:
            rtype = match.group('rtype')
            rname = match.group('rname')
            attr = match.group('attr')
            value = match.group('value')
            # print('dg = ', dg, 'rtype = ', rtype, 'rname = ', rname, 'attr = ', attr, 'value = ', value)
            if rname not in self.dg_inv[dg]['rules']:
                self.dg_inv[dg]['rules'].add(rname)
                # print('adding rule', rname)
            if rname not in self.rule[dg].keys():
                self.rule[dg][rname] = {}
                self.rule[dg][rname]['ref'] = 0
                # print('creating dict for ', rname)
            # print(self.rule[dg][rname])
            # try:
            if attr not in self.rule[dg][rname].keys():
                self.rule[dg][rname][attr] = value
                self.rule[dg][rname]['rtype'] = rtype
            else:
                if attr == "target":
                    self.rule[dg][rname][attr] = " "+value
                else:
                    print("E: security rules conflict? dg = ", dg, "rname = ", rname, "attr = ", attr, "old value = ", self.rule[dg][rname][attr], "new value = ", value)
            # except AttributeError:
            #    print(self.dg_obj)
            #    exit
        else:
            pass
            print("W: rules_parser: unmatched line", dg, line, file=g)
        # g.close()


    def nat_parser(self, dg, line, regex):
        match = regex.match(line)
        if match:
            rtype = match.group('rtype')
            rname = match.group('rname')
            attr = match.group('attr')
            value = match.group('value')
            # print('dg = ', dg, 'rtype = ', rtype, 'rname = ', rname, 'attr = ', attr, 'value = ', value)
            if rname not in self.dg_inv[dg]['nats']:
                self.dg_inv[dg]['nats'].add(rname)
                # print('adding rule', rname)
            if rname not in self.nat[dg].keys():
                self.nat[dg][rname] = {}
                # print('creating dict for ', rname)
            # print(self.nat[dg][rname])
            # try:
            if attr not in self.nat[dg][rname].keys():
                self.nat[dg][rname][attr] = value
                self.nat[dg][rname]['rtype'] = rtype
            else:
                if attr == "target devices":
                    self.nat[dg][rname][attr] = " "+value
                else:
                    print("E: NAT rules conflict? dg = ", dg, "rname = ", rname, "attr = ", attr, "old value = ", self.nat[dg][rname][attr], "new value = ", value)
            # except AttributeError:
            #    print(self.dg_obj)
            #    exit
        else:
            print("W: NAT_parser: unmatched line", dg, line)


    def address_parser(self, dg, line, regex):
        # print("D: ", dg, "addr_parser: dostalem linie", line)
        match = regex.match(line)
        if match:
            qaname = match.group('aname')
            qattr = match.group('attr')
            qvalue = match.group('value')
            # print("D: matched line:", line, "found name", qaname, "with attr", qattr, "and value", qvalue)
            if qaname not in self.dg_inv[dg]['addresses']:
                self.dg_inv[dg]['addresses'].add(qaname)
            if qaname not in self.address[dg].keys():
                self.address[dg][qaname] = {}
                self.address[dg][qaname]['ref'] = 0
            if qattr not in self.address[dg][qaname].keys():
                self.address[dg][qaname][qattr] = qvalue
            else:
                print("E: address conflict? dg = ", dg, "aname = ", qaname, "attr = ", qattr, "old value = ", self.address[dg][qaname][qattr], "new value = ", qvalue)

        else:
            print("W: address_parser: unmatched line", dg, line)


    def addrgroup_parser(self, dg, line, regex):
        match = regex.match(line)
        if match:
            agrp = match.group('agrp')
            attr = match.group('attr')
            if attr == 'static':
                attr = 'members'
                agrpmembers = line_split(match.group('data'))
            else:
                agrpmembers = match.group('data')
            # print("D: matched line:", line, "found name", agrp, 'attr', attr, "with members", agrpmembers)
            if agrp not in self.dg_inv[dg]['addressgroups']:
                self.dg_inv[dg]['addressgroups'].add(agrp)
            if agrp not in self.addressgroup[dg].keys():
                self.addressgroup[dg][agrp] = {}
                self.addressgroup[dg][agrp]['ref'] = 0
            if attr not in self.addressgroup[dg][agrp].keys():
                self.addressgroup[dg][agrp][attr] = agrpmembers
            else:
                print("E: addgrp conflict? dg = ", dg, "agrp = ", agrp, "oldmembers = ", self.addressgroup[dg][agrp]['members'], "new members = ", agrpmembers)

        else:
            print("W: addrgroup_parser: unmatched line", dg, line)


    def app_group_parser(self, dg, line, regex):
        match = regex.match(line)
        if match:
            agrp = match.group('agrp')
            attr = match.group('attr')
            if attr == 'members':
                agrpmembers = line_split(match.group('data'))
            else:
                agrpmembers = match.group('data')
            # print("dg:",dg,"matched line:", line, "found name", agrp, 'attr', attr, "with members", agrpmembers)
            # print (self.appgroup)
            if agrp not in self.dg_inv[dg]['appgroups']:
                self.dg_inv[dg]['appgroups'].add(agrp)
            if agrp not in self.appgroup[dg].keys():
                self.appgroup[dg][agrp] = {}
                self.appgroup[dg][agrp]['ref'] = 0
            if attr not in self.appgroup[dg][agrp].keys():
                self.appgroup[dg][agrp][attr] = agrpmembers
            else:
                print("appgrp conflict? dg = ", dg, "agrp = ", agrp, "oldmembers = ", self.appgroup[dg][agrp]['members'], "new members = ", agrpmembers)
        else:
            print("appgroup_parser: unmatched line", dg, line)


    def service_parser(self, dg, line, regex):
        f = open('W_missing_attribute', 'a')
        g = open('W_unmatched_lines', 'a')
        # print("service_parser: dostalem linie", dg, line)
        match = regex.match(line)
        if match:
            sname = match.group('sname')
            proto = match.group('proto')
            attr = match.group('attr')
            value = match.group('value')
            if attr is None:
                print("no attr in line", line, file=f)
                attr = 'tag'
                value = match.group('tag')
            # print("matched line:", line, "found name", sname, "with attr", attr, "and value", value)
            if sname not in self.dg_inv[dg]['services']:
                self.dg_inv[dg]['services'].add(sname)
            if sname not in self.service[dg].keys():
                self.service[dg][sname] = {}
                self.service[dg][sname]['ref'] = 0
            # print(self.service[dg][sname])
            if attr not in self.service[dg][sname].keys():
                self.service[dg][sname][attr] = value
                if proto is not None: self.service[dg][sname]['proto'] = proto
            else:
                print("service conflict? dg = ", dg, "sname = ", sname, "attr = ", attr, "old value = ", self.service[dg][sname][attr], "new value = ", value)
            # print(self.service[dg][sname])
        else:
            print("service_parser: unmatched line", dg, line, file=g)
        f.close()
        g.close()


    def service_group_parser(self, dg, line, regex):
        match = regex.match(line)
        if match:
            sgrp = match.group('sgrp')
            attr = match.group('attr')
            if attr == 'members':
                sgrpmembers = line_split(match.group('data'))
            else:
                sgrpmembers = match.group('data')
            # print("matched line:", line, "found name", sgrp, 'attr', attr, "with members", sgrpmembers)
            if sgrp not in self.dg_inv[dg]['servicegroups']:
                self.dg_inv[dg]['servicegroups'].add(sgrp)
            if sgrp not in self.servicegroup[dg].keys():
                self.servicegroup[dg][sgrp] = {}
                self.servicegroup[dg][sgrp]['ref'] = 0
            if attr not in self.servicegroup[dg][sgrp].keys():
                self.servicegroup[dg][sgrp][attr] = sgrpmembers
            else:
                print("srvgrp conflict? dg = ", dg, "sgrp = ", sgrp, "oldmembers = ", self.servicegroup[dg][sgrp]['members'], "new members = ", sgrpmembers)
        else:
            print("srvgroup_parser: unmatched line", dg, line)


    def devices_parser(self, dg, t, line, regex):
        # regex = devices (?P<device_id>[0-9]+)
        match = regex.match(line)
        if match:
            device_id = get_members(match.group('device_id'))
            # print('found device', device_id, 'in dg', dg)
            if isinstance(device_id, list):
                for m in device_id:
                    if m not in self.deviceid.keys():
                        self.deviceid[m] = {}
                        self.deviceid[m]['dg'] = {}
                        self.deviceid[m]['t'] = {}
                    if dg != '':
                        self.deviceid[m]['dg'].append(dg)
                    if t != '':
                        self.deviceid[m]['t'].append(t)
            else:
                if device_id not in self.deviceid.keys():
                    self.deviceid[device_id] = {}
                    self.deviceid[device_id]['dg'] = []
                    self.deviceid[device_id]['t'] = []
                if dg != '':
                    self.deviceid[device_id]['dg'].append(dg)
                    # print('adding', device_id, 'to dg', dg)
                if t != '':
                    self.deviceid[device_id]['t'].append(t)
        else:
            print('devices_parser error! dg:', dg, 'l:', line)


    def address_names_check(self):
        # self.address[dg][qaname][qattr] = qvalue
        start = time.time()
        print('Starting address_names_check')
        f = open('W_mismatch_name_and_content', 'w')
        name_regex = re.compile('\"?(?P<zero>[a-zA-Z0-9_ -]*[-_ ])?(?P<first>[0-9]+)[.-](?P<second>[0-9]+)[.-](?P<third>[0-9]+)[.-](?P<fourth>[0-9]+)[_-]?(?P<mask>[0-9]*)?.*\"?')
        netmask_regex = re.compile('(?P<first>[0-9]+)[.]+(?P<second>[0-9]+)[.]+(?P<third>[0-9]+)[.](?P<fourth>[0-9]+)/?(?P<mask>[0-9]*)')
        name_iprange_regex = re.compile('\"?(?P<zero>[a-zA-Z_ -]+|[a-zA-Z0-9_ -]+[-_ ])?(?P<f1>[0-9]+)[.](?P<f2>[0-9]+)[.](?P<f3>[0-9]+)[.](?P<f4>[0-9]+)[-](?P<t1>[0-9]+)[.](?P<t2>[0-9]+)[.](?P<t3>[0-9]+)[.](?P<t4>[0-9]+)')
        iprange_regex = re.compile('(?P<f1>[0-9]+)[.](?P<f2>[0-9]+)[.](?P<f3>[0-9]+)[.](?P<f4>[0-9]+)[-](?P<t1>[0-9]+)[.](?P<t2>[0-9]+)[.](?P<t3>[0-9]+)[.](?P<t4>[0-9]+)')
        for dg in self.devicegroups:
            for obj in self.address[dg].keys():
                if "ip-netmask" in self.address[dg][obj].keys():
                    ip_value = self.address[dg][obj]['ip-netmask']
                    match2 = netmask_regex.match(ip_value)
                    if match2:
                        mask2 = ("32" if match2.group('mask') == '' else match2.group('mask'))
                        match = name_regex.match(obj)
                        if match:
                            if match.group('mask') == '':
                                mask1 = "32"
                            else:
                                mask1 = match.group('mask')
                            if match.group('first') == match2.group('first') and \
                               match.group('second') == match2.group('second') and \
                               match.group('third') == match2.group('third') and \
                               match.group('fourth') == match2.group('fourth') and \
                               mask1 == mask2:
                                pass
                                # print("D:All clear with ip netmask!")
                            else:
                                # print("W:Something is not matched, please check")
                                print("W: DG:", dg, "addr:", obj, "octets:", match.group('first'), match.group('second'), match.group('third'), match.group('fourth'), "mask:", mask1, file=f)
                                print("W: found ip netmask:", ip_value, "octets:", match2.group('first'), match2.group('second'), match2.group('third'), match2.group('fourth'), "with netmask", mask2, file=f)
                        else:
                            print("I: DG:", dg, "found ip netmask, but the name", obj, "does not match IP, object is ", ip_value, file=f)
                    else:
                        print('E:cannot match IP from ip-netmask:', ip_value)
                elif "ip-range" in self.address[dg][obj].keys():
                    # print("D: obj:", obj, "ip-range: ", self.address[dg][obj]['ip-range'])
                    ip_value = self.address[dg][obj]['ip-range']
                    match2 = iprange_regex.match(ip_value)
                    if match2:
                        if match2.group('f1') == match2.group('t1') and match2.group('f2') == match2.group('t2') and match2.group('f3') == match2.group('t3'):
                            match = name_iprange_regex.match(obj)
                            if match:
                                if match.group('f1') == match2.group('f1') and \
                                 match.group('f2') == match2.group('f2') and \
                                 match.group('f3') == match2.group('f3') and \
                                 match.group('f4') == match2.group('f4') and \
                                 match.group('t1') == match2.group('t1') and \
                                 match.group('t2') == match2.group('t2') and \
                                 match.group('t3') == match2.group('t3') and \
                                 match.group('t4') == match2.group('t4'):
                                    pass
                                    # print("D:all clear with ip-range2!")
                                else:
                                    # print("W:Something is not matched with ip-range2, please check")
                                    print("W:DG:", dg, "name:", obj, "octets:", match.group('f1'), match.group('f2'), match.group('f3'), match.group('f4'), " - ", match.group('f1'), match.group('f2'), match.group('f3'), match.group('f4'), file=f)
                                    print("W:found ip range:", ip_value, "octets:", match2.group('f1'), match2.group('f2'), match2.group('f3'), match2.group('f4'), "end:", match2.group('t4'), file=f)
                            else:
                                match = name_regex.match(obj)
                                if match:
                                    if match.group('first') == match2.group('f1') and \
                                       match.group('second') == match2.group('f2') and \
                                       match.group('third') == match2.group('f3') and \
                                       match.group('fourth') == match2.group('f4') and \
                                       match.group('mask') == match2.group('t4'):
                                        pass
                                        # print("D:all clear with ip-range!")
                                    else:
                                        # print("W:Something is not matched with ip-range, please check")
                                        print("W:DG:", dg, "addr:", obj, "octets:", match.group('first'), match.group('second'), match.group('third'), match.group('fourth'), "end:", mask1, file=f)
                                        print("W:found ip range:", ip_value, "octets:", match2.group('f1'), match2.group('f2'), match2.group('f3'), match2.group('f4'), "end:", match2.group('t4'), file=f)
                                else: print("I: dg:", dg, "found ip-range, ", obj, "but the name does not match", file=f)
                        else: print("I: obj:", obj, "ip range bigger than /24")
                    else: print('E: cannot match IP range from ip-range:', ip_value)
                elif "fqdn" in self.address[dg][obj].keys():
                    if self.address[dg][obj]['fqdn'] not in obj:
                        # print("D: dg: ", dg, "obj:", obj, "found fqdn:", self.address[dg][obj]['fqdn'])
                        pass
                elif "ip-wildcard" in self.address[dg][obj].keys():
                    pass
                else:
                    print("E: not match for IP - DG:", dg, "addr:", obj)
        f.close()
        print('Completed address_names_check in', time.time()-start)


    def return_address_value(self, dg, obj):
        a = get_members(obj)
        if isinstance(a, list):
            # print('i have a list:', a)
            tmp = []
            for b in a:
                if b in self.addressgroup[dg].keys():
                    tmp.append(self.return_address_value(dg, b))
                elif b in self.address[dg].keys():
                    tmp.append(self.return_address_value(dg, b))
                elif dg != 'shared':
                    # print('did not find member', b, 'in', dg, 'going to:', self.parent[dg])
                    tmp.append(self.return_address_value(self.parent[dg], b))
                else:
                    print("Error in", a, "could not find", b, "adding name")
                    tmp.append(b)
            return tmp
        if a != 'any':
            # print('I have single object:', a)
            if a in self.address[dg].keys():
                self.address[dg][a]['ref'] = self.address[dg][a]['ref']+1
                if "ip-netmask" in self.address[dg][a].keys():
                    return self.address[dg][a]['ip-netmask']
                elif "ip-range" in self.address[dg][a].keys():
                    return self.address[dg][a]['ip-range']
                elif "fqdn" in self.address[dg][a].keys():
                    return self.address[dg][a]['fqdn']
                elif "ip-wildcard" in self.address[dg][a].keys():
                    return self.address[dg][a]['ip-wildcard']
                else:
                    print('bad address type? ', a)
                    return None
            if a in self.addressgroup[dg].keys():
                self.addressgroup[dg][a]['ref'] = self.addressgroup[dg][a]['ref']+1
                tmp = []
                for m in self.addressgroup[dg][a]['members']:
                    if m != ']' and m != '[':
                        tmp.append(self.return_address_value(dg, m))
                return tmp
            if dg != 'shared':
                # print('did not find in', dg, 'going to:', self.parent[dg])
                return self.return_address_value(self.parent[dg], a)
                # print("E: could not find object for", a, "adding name as value")
                # exit()
        return a
        

    def object_count(self):
        start = time.time()
        print('Starting object count')
        f = open('I_object_count.txt', 'w')
        for dg in self.devicegroups:
            print('{ dg:', dg, ', ', file=f)
            #for o in ['address', 'addressgroup', 'service', 'servicegroup', 'appgroup']:
            print('\t{', 'address', ': [', file=f)
            for a in self.address[dg].keys():
                print('\t\t{ dg:', dg, ', ', 'address', ':', a, ', count:', self.address[dg][a]['ref'], '}', file=f)
            print('\t] }', file=f)
            print('\t{', 'addressgroup', ': [', file=f)
            for a in self.addressgroup[dg].keys():
                print('\t\t{ dg:', dg, ', ', 'addressgroup', ':', a, ', count:', self.addressgroup[dg][a]['ref'], '}', file=f)
            print('\t] }', file=f)
            print('\t{', 'service', ': [', file=f)
            for a in self.service[dg].keys():
                print('\t\t{ dg:', dg, ', ', 'service', ':', a, ', count:', self.service[dg][a]['ref'], '}', file=f)
            print('\t] }', file=f)
            print('\t{', 'servicegroup', ': [', file=f)
            for a in self.servicegroup[dg].keys():
                print('\t\t{ dg:', dg, ', ', 'servicegroup', ':', a, ', count:', self.servicegroup[dg][a]['ref'], '}', file=f)
            print('\t] }', file=f)
            print('\t{', 'appgroup', ': [', file=f)
            for a in self.appgroup[dg].keys():
                print('\t\t{ dg:', dg, ', ', 'appgroup', ':', a, ', count:', self.appgroup[dg][a]['ref'], '}', file=f)
            print('\t] }', file=f)
            print('}', file=f)
        f.close()
        print('Completed object_count in', time.time()-start)


    def return_service_value(self, dg, obj):
        a = get_members(obj)
        if isinstance(a, list):
            # print('i have a list:', a)
            tmp = []
            for b in a:
                if b in self.servicegroup[dg].keys():
                    tmp.append(self.return_service_value(dg, b))
                elif b in self.service[dg].keys():
                    tmp.append(self.return_service_value(dg, b))
                elif dg != 'shared':
                    # print('did not find member', b, 'in', dg, 'going to:', self.parent[dg])
                    tmp.append(self.return_service_value(self.parent[dg], b))
                else:
                    print("Error in servicegroup", a, "could not find", b, "adding name")
                    tmp.append(b)
            return tmp
        elif a not in ('any','application-default','service-http','service-https'):
            # print('I have single object:', a)
            if a in self.service[dg].keys():
                self.service[dg][a]['ref'] = self.service[dg][a]['ref']+1
                if 'port' in self.service[dg][a].keys():
                    return str(self.service[dg][a]['port']+'/'+self.service[dg][a]['proto'])
                print("cannot find port for dg:", dg, "service:", a)
            elif a in self.servicegroup[dg].keys():
                self.servicegroup[dg][a]['ref'] = self.servicegroup[dg][a]['ref']+1
                tmp = []
                for m in self.servicegroup[dg][a]['members']:
                    if m not in (']','['):
                        tmp.append(self.return_service_value(dg, m))
                return tmp
            elif dg != 'shared':
                # print('did not find in', dg, 'going to:', self.parent[dg])
                return self.return_service_value(self.parent[dg], a)
            print("E: could not find service for", a, "adding name as value")
                # exit()
        return a


    def return_applications(self, dg, obj):
        a = get_members(obj)
        if isinstance(a, list):
            # print('i have a list:', a)
            tmp = []
            for b in a:
                if b in self.appgroup[dg].keys():
                    tmp.append(self.return_applications(dg, b))
            #    elif b in self.dg_obj[dg]['application'].keys():
            #        tmp.append(return_applications(dg, b))
                elif dg != 'shared':
                    # print('did not find member', b, 'in', dg, 'going to:', self.parent[dg])
                    tmp.append(self.return_applications(self.parent[dg], b))
                else:
                    # print("Error in appgroup", a, "could not find", b, "adding name")
                    tmp.append(b)
            return tmp
        elif a != 'any':
            # print('I have single object:', a)
            if a in self.appgroup[dg].keys():
                self.appgroup[dg][a]['ref'] = self.appgroup[dg][a]['ref']+1
                tmp = []
                for m in self.appgroup[dg][a]['members']:
                    if m != ']' and m != '[':
                        tmp.append(self.return_applications(dg, m))
                return tmp
            elif dg != 'shared':
                return self.return_applications(self.parent[dg], a)
            else:
                return a
        else:
            return a


    def all_rules_print(self):
        # self.rule[dg][rname][attr] = value
        start = time.time()
        print('Starting all rules_print')
        f = open('I_rules.txt', 'w')
        for dg in self.devicegroups:
            # print('dg:', dg)
            for rule in self.rule[dg].keys():
                try:
                    fzones = get_members(self.rule[dg][rule]['from'])
                    tzones = get_members(self.rule[dg][rule]['to'])
                    rtype = self.rule[dg][rule]['rtype']
                    action = self.rule[dg][rule]['action']
                    services = self.return_service_value(dg, self.rule[dg][rule]['service'])
                    applications = self.return_applications(dg, self.rule[dg][rule]['application'])
                    source = self.return_address_value(dg, self.rule[dg][rule]['source'])
                    destination = self.return_address_value(dg, self.rule[dg][rule]['destination'])
                except KeyError:
                    g = open('E_rules_with_missing_attributes.txt', 'a')
                    print('dg:', dg, 'rule:', rule, 'has missing attribute', file=g)
                    g.close()
                    print("Exception:", sys.exc_info())
                if source == 'unknown':
                    print('source unknown for dg:', dg, 'rule:', rule, 's:', self.rule[dg][rule]['source'], 'd:', destination)
                if destination == 'unknown':
                    print('dest unknown for dg:', dg, 'rule:', rule, 's:', source, 'd:', self.rule[dg][rule]['destination'])
                print('{ dg:', dg, ', rule:', rule, ', from zones:', fzones, ', to zones:', tzones, ', type:', rtype, ', source:', source, ', destination', destination, ', action:', action, ', service:', services, ', application', applications, '}', file=f)
        f.close()
        print('Completed rules_print in', time.time()-start)


    def rules_for_dg(self, dg, f):
        for rule in self.rule[dg].keys():
            try:
                fzones = get_members(self.rule[dg][rule]['from'])
                tzones = get_members(self.rule[dg][rule]['to'])
                rtype = self.rule[dg][rule]['rtype']
                action = self.rule[dg][rule]['action']
                services = self.return_service_value(dg, self.rule[dg][rule]['service'])
                applications = self.return_applications(dg, self.rule[dg][rule]['application'])
                source = self.return_address_value(dg, self.rule[dg][rule]['source'])
                destination = self.return_address_value(dg, self.rule[dg][rule]['destination'])
            except KeyError:
                g = open('E_rules_with_missing_attributes.txt', 'a')
                print('dg:', dg, 'rule:', rule, 'has missing attribute', file=g)
                g.close()
                print("Exception:", sys.exc_info())
            if source == 'unknown':
                print('source unknown for dg:', dg, 'rule:', rule, 's:', self.rule[dg][rule]['source'], 'd:', destination)
            if destination == 'unknown':
                print('dest unknown for dg:', dg, 'rule:', rule, 's:', source, 'd:', self.rule[dg][rule]['destination'])
            print('{ dg:', dg, ', rule:', rule, ', from zones:', fzones, ', to zones:', tzones, ', type:', rtype, ', source:', source, ', destination', destination, ', action:', action, ', service:', services, ', application', applications, '}', file=f)
        if dg != 'shared':
            self.rules_for_dg(self.parent[dg], f)


    def devices_ips(self):
        f = open('I_devices_IPs.txt', 'w')
        start = time.time()
        for d in self.deviceid.keys():
            self.deviceid[d]['zone_ip'] = {}
            self.deviceid[d]['zone_ref'] = {}
            for t in self.deviceid[d]['t']:
                # print('D:', d, 't:', t)
                for z in self.zone[t].keys():
                    # print('D:', d, 't:', t, 'z:', z)
                    x = self.zone_to_ip(t, z)
                    self.deviceid[d]['zone_ip'][z] = []
                    self.deviceid[d]['zone_ref'][z] = 0
                    print(x)
                    if x:
                        self.deviceid[d]['zone_ip'][z].append(x)
                for t2 in self.tmembers[t]:
                    for z in self.zone[t2].keys():
                        if z not in self.deviceid[d]['zone_ip'].keys():
                            self.deviceid[d]['zone_ip'][z] = []
                            self.deviceid[d]['zone_ref'][z] = 0
                        x = self.zone_to_ip(t2, z)
                        # print('checking d:', d, 't:', t, 't2:', t2, 'z:', z, 'x:', x)
                        if x:
                            if isinstance(x, list):
                                for x2 in x:
                                    self.deviceid[d]['zone_ip'][z].append(x2)
                            else:
                                self.deviceid[d]['zone_ip'][z].append(x)
            print('Device:', d, 'IPs:', self.deviceid[d]['zone_ip'], file=f)
        f.close()
        print('Completed devices_ips in', time.time()-start)


    def rules_for_devices_print(self):
        f = open('I_rules2.txt', 'w')
        start = time.time()
        print('Starting rules_for_devices_print')
        for d in self.deviceid.keys():
            print(' { device:', d, file=f)
            for d2 in self.deviceid[d]['dg']:
                # print('device', d, 'is assigned to DG:', d2, 'parent:', self.dg_obj[d2]['parent-dg'], 'and t:', devices_id[d]['t'])
                self.rules_for_dg(d2, f)
            print('}', file=f)
        f.close()
        print('Completed rules_print in', time.time()-start)


    def template_interface_parser(self, t, line, regex, h):
        line = re.sub('layer3 ', '', line)
        line = re.sub('units ', '', line)
        # print("template_interface_parser: dostalem linie", line)
        match = regex.match(line)
        if match:
            attr = match.group('attr')
            value = match.group('value')
            if match.group('lintf') is None:
                if match.group('pintf') is None:
                    print('no interface detected, t:', t, '>', line)
                    return
                intf = match.group('pintf')
            else:
                intf = match.group('lintf')
            if attr is None or value is None:
                print('template_interface_parser:', t, 'cannot properly parse line >', line)
                return
            if intf not in self.interface_ip[t].keys():
                self.interface_ip[t][intf] = {}
            if attr not in self.interface_ip[t][intf].keys():
                self.interface_ip[t][intf][attr] = value
            elif self.interface_ip[t][intf][attr] != value:
                print("E: template interface conflict? t = ", t, "intf = ", intf, "attr = ", attr, "old value = ", self.interface_ip[t][intf][attr], "new value = ", value)
        else:
            print("template_interface_parser:", t, " not matched >", line, file=h)

    # config +network interface (ethernet |loopback |tunnel |aggregate-ethernet )((?P<pintf>[a-z0-9/]+) layer3 )?(units (?P<lintf>[a-z0-9/.]+))? ?(?P<attr>[a-z0-9-]+) (?P<value>.+)$
    # config  network interface ethernet ethernet1/2 layer3 ip 10.205.0.4/16
    # config  network interface ethernet ethernet1/4 layer3 units ethernet1/4.10 ip 10.255.1.4/20
    # config  network interface loopback units loopback.1 ip 10.59.255.1
    # config  network interface tunnel units tunnel.5 ip 169.254.200.10/30
    # config  network interface tunnel units tunnel.1 ipv6 enabled yes
    # config  network interface vlan ip 172.16.106.1/24
    # config  network interface aggregate-ethernet ae1 layer3 ip 192.168.0.29/27

    # set template GHF-Master config network interface ethernet ethernet1/4 layer3 units ethernet1/4.10 ip 10.255.1.4/20
    #  object   |    "object with space "  | [ list of objects ]  | [ list of "objects with space"]


    def template_zone_parser(self, t, line, regex, h):
        # config  vsys vsys1 zone DMZ network layer3 ethernet1/9.253
        # config  vsys vsys1 zone WRO network layer3 [ tunnel.5 tunnel.8 ]
        # print("template_zone_parser: dostalem t:", t, "linie", line)
        match = regex.match(line)
        if match:
            zname = match.group('zname')
            intf = get_members(match.group('intf'))
            if zname not in self.interface_zone[t].keys():
                self.interface_zone[t][zname] = []
            if self.interface_zone[t][zname] != []:
                print('possible conflict?')
            else:
                self.interface_zone[t][zname] = intf
        else:
            pass
            print('template_zone_parser: unmatched line:', line, file=h)


    def zone_to_ip(self, t, zone):
        """
        function gives a list of IPs for the interfaces bound to zone in template t, or None
        """
        if zone in self.interface_zone[t].keys():
            i = get_members(self.interface_zone[t][zone])
            if i != '':
                if isinstance(i, list):
                    tmp = []
                    for j in i:
                        if j not in self.interface_ip[t].keys():
                            #print ("t:",t,"interface:",j,"is in zone",zone,"but has no IP")
                            pass
                        elif 'ip' in self.interface_ip[t][j].keys():
                            tmp.append(self.interface_ip[t][j]['ip'])
                        else:
                            pass
                            # print('t:', t, 'z:', zone, 'i:', i, 'member:',j, 'no ip')
                    return tmp
                else:
                    if i not in self.interface_ip[t].keys():
                            # print ("t:",t,"interface:",i,"is in zone",zone,"but has no IP")
                            pass
                    elif 'ip' in self.interface_ip[t][i]:
                        return self.interface_ip[t][i]['ip']
                    else:
                        pass
                        # print('t:', t, 'z:', zone, 'i:', i, 'no ip')
            else:
                pass
                # print('interface list empty for zone', zone, 'in template', t)
        else:
            # print('no zone', zone, 'in template', t)
            pass
        return None

        # set template-stack KOE_Stack-2 templates [ koe-pa-ha2 KOE-Master "Hotels 3020 Shared B" "Four Seasons Shared" ]
        # set template-stack KOE_Stack-2 settings default-vsys vsys1
        # set template-stack KOE_Stack-2 devices 001801055503
        # set device-group koe-pa-ha devices 001801055503


    def zone_check(self):
        file_handle = open("I_zones_interfaces_IPs.txt", 'w')
        for t in self.interface_zone.keys():
            for z in self.interface_zone[t].keys():
                print('t:', t, 'z:', z, self.zone_to_ip(t, z), file=file_handle)
        file_handle.close()


    def parse_var(self, t, l, r):
        # variable $IVSCOL type ip-netmask 10.136.2.10
        # variable $(?P<var>[a-zA-Z0-9-]+) type (?P<attr>[a-z-]+) (?P<value>.+)
        m = r.match(l)
        if m:
            var = m.group(var)
            attr = m.group(attr)
            value = m.group(value)
            if t not in self.variable.keys():
                self.variable[t] = {}
            if var not in self.variable[t].keys():
                self.variable[t][var] = (attr, value)
            else:
                print('conflict for variable? t:', t, 'v:', var)
        else:
            pass
            # print('parse_var', t, l)


    def parentdg_parser(self, l, regex):
        k = regex.match(l)
        if k:
            dg = k.group('dgroup')
            self.parent[dg] = k.group('parentdg')
            # print(dg, 'has a parent of',k.group('parentdg'))
        else:
            print('parentdg_parser error for line', l)

    def main_parser(self, handle):
        line_counter = dg_line_counter = rule_counter = template_line_counter = other_counter = 0
        # devicegroups regexes:
        global_regex = re.compile('set (?P<type>[a-z-]+) +(?P<object>[a-zA-sZ0-9-_]+|\"[a-zA-Z0-9-_ ]+\") (?P<rest>.*)$')
        # dgroup_regex = re.compile('set device-group (?P<dgroup>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\") (?P<rest>.*)$')
        # shared_regex = re.compile('set shared (?P<rest>.*)$')
        rule_regex = re.compile('(?P<rtype>[a-z-]+) security rules (?P<rname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z-]+) (?P<value>.+)')
        nat_regex = re.compile('(?P<rtype>[a-z-]+) nat rules (?P<rname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z- ]+) (?P<value>.+)')
        address_regex = re.compile('address (?P<aname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z-]+) (?P<value>.+)')
        addrgrp_regex = re.compile('address-group (?P<agrp>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>static|tag|description) \\[? ?(?P<data>.*) ?\\]?')
        service_regex = re.compile('service (?P<sname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (protocol (?P<proto>tcp|udp) )?(?P<attr>[a-z-]+) (?P<value>.+)')
        srvgrp_regex_members = re.compile('service-group (?P<sgrp>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>members|tag|description) ?\\[? (?P<data>.*) ?\\]?')
        appgrp_regex_members = re.compile('application-group (?P<agrp>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>members|tag|description)( \\[)? (?P<data>.*)( \\])?')
        parent_dg_regex = re.compile('(?P<dgroup>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\") parent-dg (?P<parentdg>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\")')

        # template regexes:
        system_ip_regex = re.compile('config +deviceconfig system ip-address (?P<sysip>[0-9]+.[0-9+]+.[0-9]+.[0-9]+)')
        devices_regex = re.compile('devices (?P<device_id>[0-9 ]+)')
        template_regex = re.compile('set template (?P<tmpl>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\") (?P<rest>.*)$')
        ts_regex = re.compile('templates (?P<tmembers>.*)$')
        interface_zone_regex = re.compile('config +vsys vsys[0-9] zone (?P<zname>[a-zA-Z0-9_-]+) network layer3 (?P<intf>.*)')
        interface_ip_regex = re.compile('config +network interface (ethernet|loopback |tunnel |aggregate-ethernet )( (?P<pintf>[a-z0-9\/]+) )?(?P<lintf>[a-z0-9\/.]+)? (?P<attr>[a-z0-9- ]+) (?P<value>[0-9a-zA-Z-.\/]+)')
        stack_regex = re.compile('set template-stack (?P<stack>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z-]+) (?P<value>.+)')
        var_regex = re.compile('variable $(?P<var>[a-zA-Z0-9-]+) type (?P<attr>[a-z-]+) (?P<value>.+)')

        start = time.time()
        print('Starting main parser')
        self.add_dg('shared')
        g2 = open('W_unmatched_lines', 'a')
        l = handle.readline()
        while l != "":
            # print("wczytalem linie:", l)
            while l.count('"') % 2 != 0:
                l = l+handle.readline()
                l = l.strip('\r\n')
                # print("wczytalem dluga linie:", l)
            m = global_regex.match(l)
            if not m:
                # print("error global matching line:", l)
                l = handle.readline()
                continue
            type = m.group('type')
            object = m.group('object')
            r = m.group('rest')
            if type == 'device-group' or type == 'shared':
                dg_line_counter = dg_line_counter+1
                dg = (object if type == 'device-group' else 'shared')
                if type == 'shared':
                    r = object+' '+r
                    # print("wczytalem shared linie:", r)
                if dg not in self.devicegroups:
                    self.add_dg(dg)
                if " security rules " in r:
                    self.rules_parser(dg, r, rule_regex, g2)
                    rule_counter = rule_counter+1
                elif " nat rules " in r:
                    self.nat_parser(dg, r, nat_regex)
                elif r[0:8] == "address ":
                    self.address_parser(dg, r, address_regex)
                elif r[0:14] == "address-group ":
                    self.addrgroup_parser(dg, r, addrgrp_regex)
                elif r[0:8] == "service ":
                    self.service_parser(dg, r, service_regex)
                elif r[0:14] == "service-group ":
                    self.service_group_parser(dg, r, srvgrp_regex_members)
                elif r[0:18] == "application-group ":
                    self.app_group_parser(dg, r, appgrp_regex_members)
                elif r[0:8] == "devices ":
                    self.devices_parser(dg, '', r, devices_regex)
                else:
                    # print("I could not figure out DG line ", l)
                    # print(rest[0:7], "<<")
                    pass
            elif type == 'template' or type == 'template-stack':
                if object not in self.templates:
                    self.add_t(object)
                    # print("dodaje template", object)
                template_line_counter = template_line_counter+1
                if "config  network interface " in r:
                    self.template_interface_parser(object, r, interface_ip_regex, g2)
                elif "config  vsys vsys1 zone " in r:
                    self.template_zone_parser(object, r, interface_zone_regex, g2)
                # elif "deviceconfig system ip-address " in r:
                #    m = system_ip_regex.match(r)
                #    if m:
                #        self.dg_obj['shared']['address'][m.group('sysip')] = {}
                #        self.dg_obj['shared']['address'][m.group('sysip')]['ip-netmask'] = m.group('sysip')
                #        self.t_obj[t]['system_ip'] = m.group('sysip')
                #    else:
                #        print("error", t, r)
                elif "variable $" in r:
                    self.parse_var(object, r, var_regex)
                elif r[0:8] == "devices ":
                    self.devices_parser('', object, r, devices_regex)
                elif r[0:10] == "templates ":
                    m = ts_regex.match(r)
                    if m:
                        self.tmembers[object] = get_members(m.group('tmembers'))
                else:
                    pass
                    print("template(-stack):", object, "line without match:", r, file=g2)
            elif m.group('type') == 'readonly' and 'parent-dg' in m.group('rest'):
                self.parentdg_parser(m.group('rest'), parent_dg_regex)
            else:
                print('Line parsed but not yet processed:', l, file=g2)
                other_counter = other_counter+1
            line_counter = line_counter+1
            if line_counter > 5000000:
                print(self.address['shared'])
                sys.exit()
            l = handle.readline()
        g2.close()
        print('Completed main parser in', time.time()-start)
        # print(self.dg_obj)
        print("wczytalem", line_counter, " linii, z czego ", dg_line_counter, 'to devicegroups, ', rule_counter, "przypada na regulki, ", template_line_counter, "na template a ", other_counter, " na inne")
        print("znalazlem", len(self.devicegroups), "device groups", len(self.templates), "templates")

def main():
    pa = config()
    filename = "pano_28.log"
    handle = open(filename, 'r')
    pa.main_parser(handle)
    handle.close()
    # pa.load_config_ssh()
    pa.zone_check()
    pa.address_names_check()
    pa.all_rules_print()
    pa.rules_for_devices_print()
    pa.devices_ips()
    pa.object_count()
    # print(pa.devices_id)
    # print(pa.dg_obj['shared']['address']['Panorama-ELK_204.13.202.249'])
    # print(pa.return_service_value('atwso-pa-ha1', 'TCP-8006-8010'))
    # print(pa.return_service_value('gua-pa-ha', 'Softlayer-Services-1-SRV'))
    # print(pa.return_address_value('"Four Seasons"', 'LSVPN-GATEWAYS'))
    # print(pa.dg_obj['"World Sales Offices"'])
    # print(pa.return_address_value('atwso-pa-ha1', '[ "GoldLine - 172.16.116.0_24" VOIP-172.16.101.0_24 WRO-172.16.0.0_18 WRO-172.16.0.16 WRO-172.16.0.18 WRO-172.16.0.19 WRO-172.16.0.20 WRO-172.16.0.34 WRO-172.16.0.35 WRO-172.16.0.40 WRO-172.16.0.69 ]'))
    # print(pa.return_address_value('cfs-pa-ha', 'CFS-PMSDB-10.34.10.130'))
    # print(pa.return_applications('gua-pa-ha', 'BackupExectoMail-APP'))


if __name__ == "__main__":
    main_start = time.time()
    main()
    print("wykonanie zajelo", time.time()-main_start)
