# ideas: 
# 1) if there is any nat rule without at least one ip allowed through it
# 2) if there any rules with IPs not matching the zones interfaces IPs
# 3) if there any address objects with IP in name, and different IP in content
# 4) if there are rules with applications defined and "any" service
# 5) if there are any rules without logging
# 6) find overlapping rules
# 7) report on real ip rules
# 8) packet tracer
# 9) find vlan tags matching z in ethx/y.z

#co w dg: adresy, serwisy, grupy, rulki nat i security
#dg_obj[dg]['rule'][rulename][attr]=value
#dg_obj[dg]['address'][address][attr]=value
#co w template: interfejsy, zony, vpny, routing statyczny, routing per service, logowanie, panorama, network profiles, snmp, zmienne
#t_obj[t]['interface'][interface][attr]=value

import re,time,sys
#import string,re,pwd,sys,os.path,time,getopt,glob,errno
# data structures - dictionaries:
# address - description, disable-override, ip-netmask, fqdn, ip-range, tag 

def line_split(line):
    return re.findall(r'[^\"\s]\S*|\".+?\"', line)

def get_members(data):
    if '[' in data:
        a=line_split(data)
        a.remove('[')
        a.remove(']')
        return a
    else:
        return data

def line_split2(line):
    return re.findall("(?:\".*?\"|\S)+", line)

devicegroups = set()
dg_inv = {}
dg_obj = {}

#addresses = set()
#address_ip = {}
#address_fqdn = {}
#address_tags = {}
#address_desc = {}
#addressgroup - static [], tag
#addressgroups = set()
#addressgroup_members = {}
#addressgroup_tags = {}
#security rules - post/pre-rulebase, action, application, category, description, destination, disabled, from, group-tag, hip-profiles, rule type, service, source, source-user, tag, target, to
#rules = set()
#rule_type = {}
#rule_action = {}
#rule_app = {}
#rule_src = {}
#rule_dst = {}
#rule_cat = {}
#rule_fzones = {}
#rule_tzones = {}
#rule_services = {}

#services = set()
#service_proto={}
#service_port = {}
#service_desc = {}

#servicegroups = set()
#servicegroup_members = {}
#data structures - sets:

devicegroup_members = {}

#servicegroups = set()
#servicegroup_members = {}

#appgroups = set()
#appgroup_members = {}

templates = set()
t_obj = {}




def rules_parser(dg,line,regex,g):
    global dg_inv, dg_obj
    #g=open('W_unmatched_lines','a')
    # set device-group man-pa-ha post-rulebase security rules "GOLD IMAGE ID 016a-print-over-ms-smb" from Workstations
    # set device-group "AWS Singapore" pre-rulebase security rules "Softlayer and AWS-TGW - patch management" service [ TCP-8027 TCP-8031 TCP-8383 ]
    #rule_regex_global = re.compile('(?P<rtype>[a-z-]+) security rules (?P<rname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z-]+) (?P<value>.+)')
    #print("rules_parser: dostalem linie",line)
    match = regex.match(line)
    if match:
        rtype=match.group('rtype')
        rname=match.group('rname')
        attr=match.group('attr')
        value=match.group('value')
        #print ('dg=',dg,'rtype=',rtype,'rname=',rname,'attr=',attr,'value=',value)
        if rname not in dg_inv[dg]['rules']:
            dg_inv[dg]['rules'].add(rname)
            #print('adding rule',rname)
        if rname not in dg_obj[dg]['rule'].keys():
            dg_obj[dg]['rule'][rname]={}
            #print ('creating dict for ',rname)
        #print (dg_obj[dg]['rule'][rname])
        #try:
        if attr not in dg_obj[dg]['rule'][rname].keys():
            dg_obj[dg]['rule'][rname][attr]=value
            dg_obj[dg]['rule'][rname]['rtype']=rtype
        else:
            if attr=="target":
                dg_obj[dg]['rule'][rname][attr]=" "+value
            else:
                print("E: security rules conflict? dg=",dg,"rname=",rname,"attr=",attr,"old value=",dg_obj[dg]['rule'][rname][attr],"new value=",value)
        #except AttributeError:
        #    print(dg_obj)
        #    exit
    else:
        pass
        print("W: rules_parser: unmatched line",dg,line,file=g)
    #g.close()
    
def nat_parser(dg,line,regex):
    global dg_inv, dg_obj
    match = regex.match(line)
    if match:
        rtype=match.group('rtype')
        rname=match.group('rname')
        attr=match.group('attr')
        value=match.group('value')
        #print ('dg=',dg,'rtype=',rtype,'rname=',rname,'attr=',attr,'value=',value)
        if rname not in dg_inv[dg]['nats']:
            dg_inv[dg]['nats'].add(rname)
            #print('adding rule',rname)
        if rname not in dg_obj[dg]['nat'].keys():
            dg_obj[dg]['nat'][rname]={}
            #print ('creating dict for ',rname)
        #print (dg_obj[dg]['nat'][rname])
        #try:
        if attr not in dg_obj[dg]['nat'][rname].keys():
            dg_obj[dg]['nat'][rname][attr]=value
            dg_obj[dg]['nat'][rname]['rtype']=rtype
        else:
            if attr=="target devices":
                dg_obj[dg]['nat'][rname][attr]=" "+value
            else:
                print("E: NAT rules conflict? dg=",dg,"rname=",rname,"attr=",attr,"old value=",dg_obj[dg]['nat'][rname][attr],"new value=",value)
        #except AttributeError:
        #    print(dg_obj)
        #    exit
    else:
        print("W: NAT_parser: unmatched line",dg,line)

def address_parser(dg,line,regex):
    global dg_inv, dg_obj
    #print("D: ",dg,"addr_parser: dostalem linie",line)
    match = regex.match(line)
    if match:
        qaname=match.group('aname')
        qattr =match.group('attr')
        qvalue=match.group('value')
        #print("D: matched line:",line,"found name",qaname,"with attr",qattr,"and value",qvalue)
        if qaname not in dg_inv[dg]['addresses']:
            dg_inv[dg]['addresses'].add(qaname)
        if qaname not in dg_obj[dg]['address'].keys():
            dg_obj[dg]['address'][qaname]={}
        if qattr not in dg_obj[dg]['address'][qaname].keys():
            dg_obj[dg]['address'][qaname][qattr]=qvalue
        else:
            print("E: address conflict? dg=",dg,"aname=",qaname,"attr=",qattr,"old value=",dg_obj[dg]['address'][qaname][qattr],"new value=",qvalue)
        
    else:
        print("W: address_parser: unmatched line",dg,line)

def addrgroup_parser(dg,line,regex):
    global dg_inv, dg_obj
    match = regex.match(line)
    if match:
        agrp=match.group('agrp')
        attr=match.group('attr')
        if attr=='static': 
            attr='members'
            agrpmembers=line_split(match.group('data'))
        else:
            agrpmembers=match.group('data')
        #print("D: matched line:",line,"found name",agrp,'attr',attr,"with members",agrpmembers)
        if agrp not in dg_inv[dg]['addressgroups']:
            dg_inv[dg]['addressgroups'].add(agrp)
        if agrp not in dg_obj[dg]['addressgroup'].keys():
            dg_obj[dg]['addressgroup'][agrp]={}
        if attr not in dg_obj[dg]['addressgroup'][agrp].keys(): 
            dg_obj[dg]['addressgroup'][agrp][attr]=agrpmembers
        else:
            print("E: addgrp conflict? dg=",dg,"agrp=",agrp,"oldmembers=",dg_obj[dg]['addressgroup'][agrp]['members'],"new members=",agrpmembers)
        
    else:
        print("W: addrgroup_parser: unmatched line",dg,line)
    
def app_group_parser(dg,line,regex):
    global dg_inv, dg_obj
    match = regex.match(line)
    if match:
        agrp=match.group('agrp')
        attr=match.group('attr')
        if attr=='members': 
            agrpmembers=line_split(match.group('data'))
        else:
            agrpmembers=match.group('data')
        #print("matched line:",line,"found name",agrp,'attr',attr,"with members",agrpmembers)
        if agrp not in dg_inv[dg]['appgroups']:
            dg_inv[dg]['appgroups'].add(agrp)
        if agrp not in dg_obj[dg]['appgroup'].keys():
            dg_obj[dg]['appgroup'][agrp]={}
        if attr not in dg_obj[dg]['appgroup'][agrp].keys(): 
            dg_obj[dg]['appgroup'][agrp][attr]=agrpmembers
        else:
            print("appgrp conflict? dg=",dg,"agrp=",agrp,"oldmembers=",dg_obj[dg]['appgroup'][agrp]['members'],"new members=",agrpmembers)
        
    else:
        print("appgroup_parser: unmatched line",dg,line)
    
def service_parser(dg,line,regex):
    global dg_inv, dg_obj
    f=open('W_missing_attribute','a')
    g=open('W_unmatched_lines','a')
    #print("service_parser: dostalem linie",dg,line)
    match = regex.match(line)
    if match:
        sname=match.group('sname')
        proto=match.group('proto')
        attr =match.group('attr')
        value=match.group('value')
        if attr==None:
            print("no attr in line",line,file=f)
            attr='tag'
            value=match.group('tag')
        #print("matched line:",line,"found name",sname,"with attr",attr,"and value",value)
        if sname not in dg_inv[dg]['services']:
            dg_inv[dg]['services'].add(sname)
        if sname not in dg_obj[dg]['service'].keys():
            dg_obj[dg]['service'][sname]={}
        #print (dg_obj[dg]['service'][sname])
        if attr not in dg_obj[dg]['service'][sname].keys():
            dg_obj[dg]['service'][sname][attr]=value
            if proto!=None: dg_obj[dg]['service'][sname]['proto']=proto
        else:
            print("service conflict? dg=",dg,"sname=",sname,"attr=",attr,"old value=",dg_obj[dg]['service'][sname][attr],"new value=",value)
        #print (dg_obj[dg]['service'][sname])
    else:
        print("service_parser: unmatched line",dg,line,file=g)
    f.close()
    g.close()

def service_group_parser(dg,line,regex):
    global dg_inv, dg_obj
    match = regex.match(line)
    if match:
        sgrp=match.group('sgrp')
        attr=match.group('attr')
        if attr=='members': 
            sgrpmembers=line_split(match.group('data'))
        else:
            sgrpmembers=match.group('data')
        #print("matched line:",line,"found name",sgrp,'attr',attr,"with members",sgrpmembers)
        if sgrp not in dg_inv[dg]['servicegroups']:
            dg_inv[dg]['servicegroups'].add(sgrp)
        if sgrp not in dg_obj[dg]['servicegroup'].keys():
            dg_obj[dg]['servicegroup'][sgrp]={}
        if attr not in dg_obj[dg]['servicegroup'][sgrp].keys(): 
            dg_obj[dg]['servicegroup'][sgrp][attr]=sgrpmembers
        else:
            print("srvgrp conflict? dg=",dg,"sgrp=",sgrp,"oldmembers=",dg_obj[dg]['servicegroup'][sgrp]['members'],"new members=",sgrpmembers)
    else:
        print("srvgroup_parser: unmatched line",dg,line)
    
def devices_parser(dg,line,regex):
    global dg_inv, dg_obj
    match = regex.match(line)
    if match:
        device_id=match.group('device_id')
    
def address_names_check():
    #dg_obj[dg]['address'][qaname][qattr]=qvalue
    start=time.time()
    print ('Starting address_names_check')
    f=open('W_mismatch_name_and_content','w')
    name_regex = re.compile('\"?(?P<zero>[a-zA-Z0-9_ -]*[-_ ])?(?P<first>[0-9]+)[.-](?P<second>[0-9]+)[.-](?P<third>[0-9]+)[.-](?P<fourth>[0-9]+)[_-]?(?P<mask>[0-9]*)?.*\"?')
    netmask_regex=re.compile('(?P<first>[0-9]+)[.]+(?P<second>[0-9]+)[.]+(?P<third>[0-9]+)[.](?P<fourth>[0-9]+)/?(?P<mask>[0-9]*)')
    name_iprange_regex=re.compile('\"?(?P<zero>[a-zA-Z_ -]+|[a-zA-Z0-9_ -]+[-_ ])?(?P<f1>[0-9]+)[.](?P<f2>[0-9]+)[.](?P<f3>[0-9]+)[.](?P<f4>[0-9]+)[-](?P<t1>[0-9]+)[.](?P<t2>[0-9]+)[.](?P<t3>[0-9]+)[.](?P<t4>[0-9]+)')
    iprange_regex=re.compile('(?P<f1>[0-9]+)[.](?P<f2>[0-9]+)[.](?P<f3>[0-9]+)[.](?P<f4>[0-9]+)[-](?P<t1>[0-9]+)[.](?P<t2>[0-9]+)[.](?P<t3>[0-9]+)[.](?P<t4>[0-9]+)')
    global dg_obj
    for dg in dg_obj.keys():
        for obj in dg_obj[dg]['address'].keys():
            if "ip-netmask" in dg_obj[dg]['address'][obj].keys():
                ip_value=dg_obj[dg]['address'][obj]['ip-netmask']
                match2=netmask_regex.match(ip_value)
                if match2:
                    mask2=("32" if match2.group('mask')=='' else match2.group('mask'))
                    match = name_regex.match(obj)
                    if match: 
                        if match.group('mask')=='':
                            mask1="32"
                        else: 
                            mask1=match.group('mask')
                        if match.group('first')==match2.group('first') and \
                           match.group('second')==match2.group('second') and \
                           match.group('third')==match2.group('third') and \
                           match.group('fourth')==match2.group('fourth') and \
                           mask1==mask2:
                            pass
                            #print ("D:All clear with ip netmask!")
                        else: 
                            #print ("W:Something is not matched, please check")
                            print("W: DG:",dg,"addr:",obj,"octets:",match.group('first'),match.group('second'),match.group('third'),match.group('fourth'),"mask:",mask1,file=f)
                            print ("W: found ip netmask:",ip_value,"octets:",match2.group('first'),match2.group('second'),match2.group('third'),match2.group('fourth'),"with netmask",mask2,file=f)
                    else:
                        print ("I: DG:",dg,"found ip netmask, but the name",obj,"does not match IP, object is ",ip_value,file=f)    
                else:
                    print('E:cannot match IP from ip-netmask:',ip_value)
            elif "ip-range" in dg_obj[dg]['address'][obj].keys():
                #print ("D: obj:",obj,"ip-range: ",dg_obj[dg]['address'][obj]['ip-range'])
                ip_value=dg_obj[dg]['address'][obj]['ip-range']
                match2=iprange_regex.match(ip_value)
                if match2: 
                    if match2.group('f1')==match2.group('t1') and match2.group('f2')==match2.group('t2') and match2.group('f3')==match2.group('t3'): 
                        match=name_iprange_regex.match(obj)
                        if match:
                            if match.group('f1')==match2.group('f1') and \
                             match.group('f2')==match2.group('f2') and \
                             match.group('f3')==match2.group('f3') and \
                             match.group('f4')==match2.group('f4') and \
                             match.group('t1')==match2.group('t1') and \
                             match.group('t2')==match2.group('t2') and \
                             match.group('t3')==match2.group('t3') and \
                             match.group('t4')==match2.group('t4'):
                                pass
                                #print ("D:all clear with ip-range2!")
                            else:
                                #print ("W:Something is not matched with ip-range2, please check")
                                print("W:DG:",dg,"name:",obj,"octets:",match.group('f1'),match.group('f2'),match.group('f3'),match.group('f4')," - ",match.group('f1'),match.group('f2'),match.group('f3'),match.group('f4'),file=f)
                                print ("W:found ip range:",ip_value,"octets:",match2.group('f1'),match2.group('f2'),match2.group('f3'),match2.group('f4'),"end:",match2.group('t4'),file=f)
                        else:
                            match = name_regex.match(obj)
                            if match:
                                if match.group('first')==match2.group('f1') and \
                                   match.group('second')==match2.group('f2') and \
                                   match.group('third')==match2.group('f3') and \
                                   match.group('fourth')==match2.group('f4') and \
                                   match.group('mask')==match2.group('t4'):
                                    pass
                                    #print ("D:all clear with ip-range!")
                                else: 
                                    #print ("W:Something is not matched with ip-range, please check")
                                    print("W:DG:",dg,"addr:",obj,"octets:",match.group('first'),match.group('second'),match.group('third'),match.group('fourth'),"end:",mask1,file=f)
                                    print ("W:found ip range:",ip_value,"octets:",match2.group('f1'),match2.group('f2'),match2.group('f3'),match2.group('f4'),"end:",match2.group('t4'),file=f)
                            else: print("I: dg:",dg,"found ip-range,",obj,"but the name does not match",file=f)
                    else: print ("I: obj:",obj,"ip range bigger than /24") 
                else: print('E: cannot match IP range from ip-range:',ip_value) 
            elif "fqdn" in dg_obj[dg]['address'][obj].keys():
                if dg_obj[dg]['address'][obj]['fqdn'] not in obj: 
                    print ("D: dg: ",dg,"obj:",obj,"found fqdn:",dg_obj[dg]['address'][obj]['fqdn'])
            elif "ip-wildcard" in dg_obj[dg]['address'][obj].keys():
                pass
            else: 
                print("E: not match for IP - DG:",dg,"addr:",obj)
    f.close()
    print ('Completed address_names_check in',time.time()-start)

def return_address_value(dg,obj):
    global dg_obj
    a=get_members(obj)
    if isinstance(a,list):
        #print ('i have a list:',a)
        tmp=[]
        for b in a:
            if b in dg_obj[dg]['addressgroup'].keys():
                tmp.append(return_address_value(dg,b))
            elif b in dg_obj[dg]['address'].keys(): 
                tmp.append(return_address_value(dg,b))
            elif dg!='shared':
                #print ('did not find member',b,'in',dg,'going to:',dg_obj[dg]['parent-dg'])
                tmp.append(return_address_value(dg_obj[dg]['parent-dg'],b))
            else:
                print ("Error in",a,"could not find",b,"adding name")
                tmp.append(b)
        return tmp
    elif a!='any':
        #print ('I have single object:',a)
        if a in dg_obj[dg]['address'].keys():
            if "ip-netmask" in dg_obj[dg]['address'][a].keys():
                return dg_obj[dg]['address'][a]['ip-netmask']
            elif "ip-range" in dg_obj[dg]['address'][a].keys():
                return dg_obj[dg]['address'][a]['ip-range']
            elif "fqdn" in dg_obj[dg]['address'][a].keys():
                return dg_obj[dg]['address'][a]['fqdn']
            elif "ip-wildcard" in dg_obj[dg]['address'][a].keys():
                return dg_obj[dg]['address'][a]['ip-wildcard']
        elif a in dg_obj[dg]['addressgroup'].keys():
            tmp=[]
            for m in dg_obj[dg]['addressgroup'][a]['members']:
                if m != ']' and m !='[':
                    tmp.append(return_address_value(dg,m))
            return tmp
        elif dg!='shared':
            #print ('did not find in',dg,'going to:',dg_obj[dg]['parent-dg'])
            return return_address_value(dg_obj[dg]['parent-dg'],a)
        else:
            print ("E: could not find object for",a,"adding name as value")
            #exit()
            return a
    else:
        return a

def return_service_value(dg,obj):
    global dg_obj
    a=get_members(obj)
    if isinstance(a,list):
        #print ('i have a list:',a)
        tmp=[]
        for b in a:
            if b in dg_obj[dg]['servicegroup'].keys():
                tmp.append(return_service_value(dg,b))
            elif b in dg_obj[dg]['service'].keys(): 
                tmp.append(return_service_value(dg,b))
            elif dg!='shared':
                #print ('did not find member',b,'in',dg,'going to:',dg_obj[dg]['parent-dg'])
                tmp.append(return_service_value(dg_obj[dg]['parent-dg'],b))
            else:
                print ("Error in servicegroup",a,"could not find",b,"adding name")
                tmp.append(b)
        return tmp
    elif a!='any' and a!='application-default' and a!='service-http' and a!='service-https':
        #print ('I have single object:',a)
        if a in dg_obj[dg]['service'].keys():
            if 'port' in dg_obj[dg]['service'][a].keys():
                return str(dg_obj[dg]['service'][a]['port']+'/'+dg_obj[dg]['service'][a]['proto'])
            else:
                print ("cannot find port for dg:",dg,"service:",a)
        elif a in dg_obj[dg]['servicegroup'].keys():
            tmp=[]
            for m in dg_obj[dg]['servicegroup'][a]['members']:
                if m != ']' and m !='[':
                    tmp.append(return_service_value(dg,m))
            return tmp
        elif dg!='shared':
            #print ('did not find in',dg,'going to:',dg_obj[dg]['parent-dg'])
            return return_service_value(dg_obj[dg]['parent-dg'],a)
        else:
            print ("E: could not find service for",a,"adding name as value")
            #exit()
            return a
    else:
        return a


def return_applications(dg,obj):
    global dg_obj
    a=get_members(obj)
    if isinstance(a,list):
        #print ('i have a list:',a)
        tmp=[]
        for b in a:
            if b in dg_obj[dg]['appgroup'].keys():
                tmp.append(return_applications(dg,b))
        #    elif b in dg_obj[dg]['application'].keys(): 
        #        tmp.append(return_applications(dg,b))
            elif dg!='shared':
                #print ('did not find member',b,'in',dg,'going to:',dg_obj[dg]['parent-dg'])
                tmp.append(return_applications(dg_obj[dg]['parent-dg'],b))
            else:
                #print ("Error in appgroup",a,"could not find",b,"adding name")
                tmp.append(b)
        return tmp
    elif a!='any':
        #print ('I have single object:',a)
        if a in dg_obj[dg]['appgroup'].keys():
            tmp=[]
            for m in dg_obj[dg]['appgroup'][a]['members']:
                if m != ']' and m !='[':
                    tmp.append(return_applications(dg,m))
            return tmp
        elif dg!='shared':
            return return_applications(dg_obj[dg]['parent-dg'],a)
        else:
            return a
    else:
        return a


def rules_print():
#dg_obj[dg]['rule'][rname][attr]=value
    global devicegroups,dg_obj,line_split
    start=time.time()
    print ('Starting rules_print')
    f=open('I_rules.txt','w')
    for dg in dg_obj.keys():
        print ('dg:',dg)
        for rule in dg_obj[dg]['rule'].keys():
            try:
                fzones=get_members(dg_obj[dg]['rule'][rule]['from'])
                tzones=get_members(dg_obj[dg]['rule'][rule]['to'])
                rtype=dg_obj[dg]['rule'][rule]['rtype']
                action=dg_obj[dg]['rule'][rule]['action']
                services=return_service_value(dg,dg_obj[dg]['rule'][rule]['service'])
                applications=return_applications(dg,dg_obj[dg]['rule'][rule]['application'])
                source=return_address_value(dg,dg_obj[dg]['rule'][rule]['source'])
                destination=return_address_value(dg,dg_obj[dg]['rule'][rule]['destination'])
            except KeyError:
                g=open('E_rules_with_missing_attributes.txt','a')
                print ('dg:',dg,'rule:',rule,'has missing attribute',file=g)
                g.close()
                print ("Exception:",sys.exc_info())
            if source=='unknown':
                print('source unknown for dg:',dg,'rule:',rule,'s:',dg_obj[dg]['rule'][rule]['source'], 'd:',destination)
            if destination=='unknown':
                print('dest unknown for dg:',dg,'rule:',rule,'s:',source, 'd:',dg_obj[dg]['rule'][rule]['destination'])
            print ('dg:',dg,'rule:',rule,'from zones:',fzones,'to zones:',tzones,'type:',rtype,'source:',source,'destination',destination,'action:',action,'service:',services,'application',applications,file=f)
    f.close()
    print ('Completed rules_print in',time.time()-start)


def template_interface_parser(t,line,regex):
    global templates, template_members
    line=re.sub('layer3 ','',line)
    #print("template_interface_parser: dostalem linie",line)
    match = regex.match(line)
    if match:
        attr=match.group('attr')
        value=match.group('value')
        if match.group('lintf')==None:
            if match.group('pintf')==None: 
                print('no interface detected, t:',t,'>',line)
                return
            else:
                intf=match.group('pintf')
        else:
            intf=match.group('lintf')
        if attr==None or value==None:
            print('template_interface_parser:',t,'cannot properly parse line >',line)
            return
        else:
            if intf not in t_obj[t]['interface'].keys():
                t_obj[t]['interface'][intf]={}
            if attr not in t_obj[t]['interface'][intf].keys():
                t_obj[t]['interface'][intf][attr]=value
            else:
                print("E: template interface conflict? t=",t,"intf=",intf,"attr=",attr,"old value=",t_obj[t]['interface'][intf][attr],"new value=",value)
    else:
        print("template_interface_parser: not matched >",line)
    
#config +network interface (ethernet |loopback |tunnel |aggregate-ethernet )((?P<pintf>[a-z0-9/]+) layer3 )?(units (?P<lintf>[a-z0-9/.]+))? ?(?P<attr>[a-z0-9-]+) (?P<value>.+)$
#config  network interface ethernet ethernet1/2 layer3 ip 10.205.0.4/16
#config  network interface ethernet ethernet1/4 layer3 units ethernet1/4.10 ip 10.255.1.4/20
#config  network interface loopback units loopback.1 ip 10.59.255.1
#config  network interface tunnel units tunnel.5 ip 169.254.200.10/30
#config  network interface tunnel units tunnel.1 ipv6 enabled yes
#config  network interface vlan ip 172.16.106.1/24 
#config  network interface aggregate-ethernet ae1 layer3 ip 192.168.0.29/27

#set template GHF-Master config network interface ethernet ethernet1/4 layer3 units ethernet1/4.10 ip 10.255.1.4/20 
#  object   |    "object with space "  | [ list of objects ]  | [ list of "objects with space"]
 
def template_zone_parser(t,line,regex):
#set template GHF-Master config  vsys vsys1 zone DMZ network layer3 ethernet1/9.253
#set template SAB-Master 

    global templates, t_obj
    #print("template_zone_parser: dostalem linie",line)
    pass

def add_dg(dg):
    devicegroups.add(dg)
    dg_inv[dg]={}
    dg_inv[dg]['addresses']=set()
    dg_inv[dg]['rules']=set()
    dg_inv[dg]['nats']=set()
    dg_inv[dg]['services']=set()
    dg_inv[dg]['addressgroups']=set()
    dg_inv[dg]['servicegroups']=set()
    dg_inv[dg]['appgroups']=set()
    dg_obj[dg]={}
    dg_obj[dg]['address']={}
    dg_obj[dg]['rule']={}
    dg_obj[dg]['nat']={}
    dg_obj[dg]['service']={}
    dg_obj[dg]['addressgroup']={}
    dg_obj[dg]['servicegroup']={}
    dg_obj[dg]['appgroup']={}
    dg_obj[dg]['device_id']=set()
    dg_obj[dg]['parent-dg']='shared'
    #print('adding dg',dg)


def main():
    filename = "pano_28.log"
    global devicegroups,dg_obj,dg_inv,t_obj
    handle = open(filename, 'r')
    line_counter=dg_line_counter=rule_counter=template_counter=other_counter=0
    #devicegroup regexes:
    dgroup_regex = re.compile('set device-group (?P<dgroup>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\") (?P<rest>.*)$')
    shared_regex = re.compile('set shared (?P<rest>.*)$')
    rule_regex = re.compile('(?P<rtype>[a-z-]+) security rules (?P<rname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z-]+) (?P<value>.+)')
    nat_regex = re.compile('(?P<rtype>[a-z-]+) nat rules (?P<rname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z- ]+) (?P<value>.+)' )
    address_regex = re.compile('address (?P<aname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>[a-z-]+) (?P<value>.+)')
    addrgrp_regex = re.compile('address-group (?P<agrp>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>static|tag|description) \\[? ?(?P<data>.*) ?\\]?')
    service_regex = re.compile('service (?P<sname>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (protocol (?P<proto>tcp|udp) )?(?P<attr>[a-z-]+) (?P<value>.+)')
    srvgrp_regex_members = re.compile('service-group (?P<sgrp>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>members|tag|description) ?\\[? (?P<data>.*) ?\\]?')
    appgrp_regex_members = re.compile('application-group (?P<agrp>[a-zA-Z0-9-._]+|\"[a-zA-Z0-9- ._]+\") (?P<attr>members|tag|description)( \\[)? (?P<data>.*)( \\])?')
    parent_dg_regex = re.compile('set readonly  device-group (?P<dgroup>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\") parent-dg (?P<parentdg>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\")')
    
    #template regexes:
    system_ip_regex = re.compile('config +deviceconfig system ip-address (?P<sysip>[0-9]+.[0-9+]+.[0-9]+.[0-9]+)')
    devices_regex = re.compile('devices (?P<device_id>0-9)+')
    template_regex = re.compile('set template (?P<tmpl>[a-zA-sZ0-9-]+|\"[a-zA-Z0-9- ]+\") (?P<rest>.*)$')
    interface_regex = re.compile('config +vsys vsys1 zone DMZ network layer3 ethernet1/9.253')
    interface_zone_regex=re.compile('config +vsys vsys[0-9] zone (?P<zname>[a-zA-Z0-9_]+) network layer3 (?P<intf>.*)')
    interface_ip_regex=re.compile('config +network interface (ethernet |loopback |tunnel |aggregate-ethernet )((?P<pintf>[a-z0-9/]+) )?(units (?P<lintf>[a-z0-9/.]+))? ?(?P<attr>[a-z0-9-]+) (?P<value>.+)')
    
    start=time.time()
    print ('Starting main parser')
    add_dg('shared')
    g2=open('W_unmatched_lines','a')
    for l in handle.readlines():
        #print("wczytalem linie:",l)
        m=dgroup_regex.match(l)
        s=shared_regex.match(l)
        #the line is for device group
        if m or s:
            dg_line_counter=dg_line_counter+1
            dg=(m.group('dgroup') if m else 'shared')
            #if s:
            #    print("wczytalem shared linie:",l)
            rest=(m.group('rest') if m else s.group('rest'))
            if dg not in devicegroups:
                add_dg(dg)
            if " security rules " in rest:
                rules_parser(dg,rest,rule_regex,g2)
                rule_counter=rule_counter+1
            elif " nat rules " in rest: 
                nat_parser (dg,rest,nat_regex)
            elif rest[0:8]=="address ":
                address_parser(dg,rest,address_regex)
            elif rest[0:14]=="address-group ":
                addrgroup_parser(dg,rest,addrgrp_regex)
            elif rest[0:8]=="service ":
                service_parser(dg,rest,service_regex)
            elif rest[0:14]=="service-group ":
                service_group_parser(dg,rest,srvgrp_regex_members)
            elif rest[0:18]=="application-group ":
                app_group_parser(dg,rest,appgrp_regex_members)
            elif rest[0:8]=="devices ":
                devices_parser(dg,rest,devices_regex)
            else: 
                #print("I could not figure out DG line ",l)
                #print(rest[0:7],"<<")
                pass
        else:
            m=template_regex.match(l)
            if m:
                t=m.group('tmpl')
                r=m.group('rest')
                if t not in templates: templates.add(t)
                if t not in t_obj:
                    t_obj[t]={}
                    t_obj[t]['interface']={}
                    t_obj[t]['zone']={}
                    t_obj[t]['system_ip']=''
                template_counter=template_counter+1
                if "config  network interface " in r:
                    template_interface_parser(t,r,interface_ip_regex)
                elif "config  vsys vsys1 zone " in r: 
                    template_zone_parser(t,r,interface_zone_regex)
                elif "deviceconfig system ip-address " in r:
                    m=system_ip_regex.match(r)
                    if m:
                        dg_obj['shared']['address'][m.group('sysip')]={}
                        dg_obj['shared']['address'][m.group('sysip')]['ip-netmask']=m.group('sysip')
                        t_obj[t]['system_ip']=m.group('sysip')
                    else:
                        print("error",t,r)
                else: 
                    pass
                    #print ("template:",t,"line without match:",r)
            else:
                k=parent_dg_regex.match(l)
                if k:
                    dg=k.group('dgroup')
                    dg_obj[dg]['parent-dg']=k.group('parentdg')
                    #print(dg,'has a parent of',k.group('parentdg'))
                else: 
                    other_counter=other_counter+1
        line_counter = line_counter+1
        if line_counter>5000000:
            print(dg_obj['shared']['address'])
            sys.exit()
    handle.close()
    g2.close()
    print ('Completed main parser in',time.time()-start)
    #print(dg_obj)
    print("wczytalem",line_counter," linii, z czego ",dg_line_counter,'to devicegroups,',rule_counter,"przypada na regulki, ",template_counter,"na template a ",other_counter," na inne")
    print("znalazlem",len(devicegroups),"device groups",len(templates),"templates")
    #address_names_check()
    rules_print()
    #print(return_service_value('chwso-pa-ha1','UDP-49252-65535'))
    #print(return_service_value('gua-pa-ha','Softlayer-Services-1-SRV'))
    #print(return_address_value('"Four Seasons"','LSVPN-GATEWAYS'))
    #print (dg_obj['"World Sales Offices"'])
    #print (dg_obj['shared']['address']['10.210.72.100'])
    #print(return_address_value('atwso-pa-ha1','[ "GoldLine - 172.16.116.0_24" VOIP-172.16.101.0_24 WRO-172.16.0.0_18 WRO-172.16.0.16 WRO-172.16.0.18 WRO-172.16.0.19 WRO-172.16.0.20 WRO-172.16.0.34 WRO-172.16.0.35 WRO-172.16.0.40 WRO-172.16.0.69 ]'))
    #print (return_applications('gua-pa-ha','BackupExectoMail-APP'))

if __name__ == "__main__":
    start=time.time()
    main()
    print ("wykonanie zajelo",time.time()-start)