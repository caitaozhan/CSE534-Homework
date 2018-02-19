import sys
import dns.query
import dns.message
import re
import ipaddress
import time
import datetime
import random
from enum import Enum

cache = {}

root_servers = {}

root_servers['a'] = '198.41.0.4'
root_servers['b'] = '199.9.14.201'
root_servers['c'] = '192.33.4.12'
root_servers['d'] = '199.7.91.13'
root_servers['e'] = '192.203.230.10'
root_servers['f'] = '192.5.5.241'
root_servers['g'] = '192.112.36.4'
root_servers['h'] = '198.97.190.53'
root_servers['i'] = '192.36.148.17'
root_servers['j'] = '192.58.128.30'
root_servers['k'] = '193.0.14.129'
root_servers['l'] = '199.7.83.42'
root_servers['n'] = '202.12.27.33'


def output(hostname, rdtype, myresponse, elapsed, cnames):
    '''The output of the program
    
    Args:
        hostname (str): host to be queried
        rdtype (str): type A, NS, or MX
        myresponse (dns.message.Message): reponse from the DNS query
        elapsed (float): time elapsed
        cnames (list): cnames during a dns query
    '''
    
    #rdtype_dic = {1:'A', 2:'NS', 5:'CNAME'}
    
    
    answers = []
    for rrset in myresponse.answer:
        for item in rrset.items:
            answers.append(item.to_text())
            
    hostname_ = hostname + '.'
    
    number = str(30)
    for answer in answers:
        re_number = '(\d+)(.*)' + answers[0]
        match = re.search(re_number, myresponse.to_text())
        if match:
            number = match.group(1)
        number = str(number)
        break
    
    
    first_line = 'QUESTION SECTION:\n'
    second_line = hostname_.ljust(39) + 'IN'.ljust(5) + rdtype.ljust(5) + '\n\n'
    third_line = 'ANSWER SECTION:\n'
    forth_line = ''
    
    if len(cnames) > 0:
        left = hostname_
        for cname in cnames:
            forth_line = forth_line + left.ljust(33) + number.ljust(6) + 'IN'.ljust(5) + 'CNAME'.ljust(7) + cname + '\n'
            left = cname
        for answer in answers:
            forth_line = forth_line + left.ljust(33) + number.ljust(6) + 'IN'.ljust(5) + rdtype.ljust(7) + answer + '\n'
    else:    
        for answer in answers:
            forth_line = forth_line + hostname_.ljust(33) + number.ljust(6) + 'IN'.ljust(5) + rdtype.ljust(7) + answer + '\n'
    
    string = first_line + second_line + third_line + forth_line
    
    print('\n')
    print(string)
    
    cache[hostname + ' ' + rdtype] = string  # insert into global cache
    
    msg_size = str(len(string.replace(' ', '')))
    print('Query time: ' + str(int(elapsed * 1000)) + ' msec')
    print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
    print('MSG SIZE rcvd: ', msg_size, '\n')


def get_cname_from_rrset(rrset):
    '''Get CNAME from a RRset (from ANSWER section)
    
    Args:
        rrset (A DNS RRset): contains an CNAME to be extracted
        
    Returns:
        CNAME (str): the CNAME in the RRset
    '''
    try:
        item = rrset.items[0]
        return item.to_text()
    except Exception as e:
        print('Oops! Some issue with cname: ', e)


def get_ip_from_rrset(rrset):
    ''' Get IP address from a RRset (from ADDITIONAL section)
    
    Args:
        rrset (A DNS RRset ): contains an IP address to be extracted
        
    Return:
        ip (str): the IP address in the RRset
    '''
    try:
        item = rrset.items[0]
        return item.to_text()
    except Exception as e:
        print('Oops! Some issue with ip: ', e)


def get_ns_from_authority(response):
    '''Get a name server from AUTHORITY.
    In some cases, there is no ADDITIONAL section, just AUTHORITY section!
    
    Args:
        response (dns.message.Message)
        
    Return:
        string: A name of ns server
    '''
    rrsets = response.authority[0].items
    index = random.randint(0, len(rrsets)-1)
    return rrsets[index].to_text() 


def check_hostname(hostname):
    '''Check whether a host is valid.
    
    Args:
        hostname (str): a hostname
        
    Return:
        True or False
    '''
    re_domain = '^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}.$'
    match = re.match(re_domain, hostname)
    if match:
        return True
    else:
        return False


def single_iterate(hostname, rdtype, where, timeout=1, dnssec=False):
    ''' A single iterative DNS query
    
    Args:
        hostname (str): host to be queried
        rdtype (str): type A, NS, or MX
        where (str):  IP address of query destination
    	dnssec (bool): whether use DNSSEC protocal or not
    Return: 
        response (dns.message.Message): the response of a single query
        
    Exception:
        May raise an exception
    '''
    a_query = dns.message.make_query(hostname, rdtype, want_dnssec=dnssec) 
    try:
        #print('single iterate: ', hostname, rdtype, where)
        response = dns.query.udp(a_query, where, timeout)
        return response
    except Exception as e:
        raise e  # Let the block who call this function catch the exception


def check_response(response, rdtype):
    '''Check whether the response has a valid IP address in its ANSWER section.
    
    Args:
        response (dns.message.Message): the response of a single query
        rdtype (str): type A=1, NS=2, CNAME=5, MX=15
    
    Return:
        True or False
    '''
    try:
        if rdtype == 'A':
            ip = get_ip_from_rrset(response.answer[0])
            ipaddress.ip_address(ip)
            return True
        elif rdtype == 'NS':                           # return NS when 'dig cnn.com NS'
            answer_type = response.answer[0].rdtype    # return all the CNAMEs when 'dig www.cnn.com NS'
            if answer_type == 2:
                return True                            # if NS, then return the answer
            elif answer_type == 5:
                return False                           # if CNAME, then keep looking for its NS
            else:
                return False                           # not sure if this condtion exist
        elif rdtype == 'MX':
            answer_type = response.answer[0].rdtype    # if MX, then return the answer
            if answer_type == 15:
                return True
            elif answer_type == 5:                     # if CNAME, then keep looking for its MX
                return False
            else:
                return False                           # not sure if this condtion exist
    except Exception as e:
        return False     


def dns_resolver_3(hostname, rdtype, cnames):
    ''' My DNS resolver version 0.3
    
    Args:
        hostname (str): target hostname
        rdtype (str):   type A, NS, or MX
        cnames (list):  a list of CNAMES during a dns query
        
    Return:
        response (dns.message.Message): response of this dns query
    '''
    for root in root_servers.values():
        try:
            response = single_iterate(hostname, rdtype, root, timeout=0.5)
            if len(response.additional) == 0:
                continue                           # root doesn't have top level domain information
            while(len(response.answer)==0 ):       # if ANSWER section is empty, then keep iterating
                if len(response.additional) > 0:   # use the IP in ADDITIONAL section
                    for rrset in response.additional:
                        next_ip = get_ip_from_rrset(rrset)
                        try:
                            response2 = single_iterate(hostname, rdtype, next_ip, timeout=0.5)
                            response = response2
                            break
                        except Exception as e:
                            pass  # print('Oops! Authoratative server timeout, try next one. ', e)
                else:             # if both ANSWER and ADDITIONAL is empty, then find the IP of AUTHORITY  
                    ns = get_ns_from_authority(response)
                    if check_hostname(ns):
                        response2 = dns_resolver_3(ns, 'A', cnames)
                        authority_answer = response2.answer[0]
                        response.additional.append(authority_answer)  # add rrset that contains IP of a AUTHORITY to response
                    else:
                         return response   # hostname in AUTHORITY is not valid
            if check_response(response, rdtype):  # ip is in the response
                return response
            else:                         # CNAME is in the response
                for rrset in response.answer:
                    cname = get_cname_from_rrset(rrset)
                    cnames.append(cname)
                    return dns_resolver_3(cname, rdtype, cnames)
            break
        except Exception as e:
            pass   # print('Oops! Some error, start from a new root server.', e)

### DNSSEC #############################################################################################

trust_anchors = [
    # KSK-2017:
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU='),
    # KSK-2010:
    dns.rrset.from_text('.', 15202, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0='),
]


rdtype_dic = {
    'A': 1      ,
    'NS':2      ,
    'DS':43     ,
    'RRSIG': 46 ,
    'DNSKEY':48 ,
}


def output_sec(hostname, rdtype, response, elapsed, cnames):
    '''The output of the program
    
    Args:
        hostname (str): host to be queried
        rdtype (str): type A, NS, or MX
        myresponse (dns.message.Message): reponse from the DNS query
        elapsed (float): time elapsed
        cnames (list): cnames during a dns query
    '''
  
    print('\n', 'QUESTION:')
    for i in response.question:
        print(i.to_text())
    
    print('\n', 'ANSWER:')
    for i in response.answer:
        print(i.to_text())
        
    print('\n')
    
    msg_size = str(len(myresponse.to_text()))
    print('Query time: ' + str(int(elapsed * 1000)) + ' msec')
    print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
    print('MSG SIZE rcvd: ', msg_size, '\n')


def get_anchor(year):
    ''' There are two anchors, get one of the anchors
    
    Args:
        year (int): 2017 or 2010
        
    Return:
        trusted root key singing key (str)
    '''
    if year == 2017:
        return trust_anchors[0].items[0].to_text()
    elif year == 2010:
        return trust_anchors[1].items[0].to_text()
    else:
        raise Exception('Parameter is neither 2017 nor 2010')


def get_pubksk(response):
    '''Get public key signing key from response
    
    Args:
        response (dns.message.Message) that contains DNSKEY information
        
    Return:
        a (dns.rdtypes.ANY.DNSKEY.DNSKEY) that contains public key signing key
    '''
    dnskey, rrsig_key, name_key = get_rrset(response, 'DNSKEY')
    for item in dnskey:
        if item.flags == 257:
            return item


def get_trust_ds(response):
    '''Get trust ds digest from parent's response
    
    Args:
        response (dns.message.Message) from parent that contains child's DS information
        
    Return:
        trusted ds digest from parent (dns.rdtypes.ANY.DS.DS), and its name (dns.name.Name)
    '''
    ds, rrsig_ds, name_ds = get_rrset(response, 'DS')
    return ds.items[0], name_ds


def check_ds_exist(response):
    '''Check whether DS record exist in the response
    
    Args:
        response (dns.message.Message): a response
        
    Return:
        (bool) True or False
    '''
    flag = False
    for rrset in response.authority:
        if rrset.rdtype == rdtype_dic['DS']:
            flag = True
            break
    return flag


def get_rrset(response, rdtype):
    '''Get the desired rrset (DNSKEY, DS, A, NS), RRSIG and name from the response, their RRSIG
    
    Args:
        response (dns.message.Message): a response of a single iterative DNS query
        rdtype (str): rrset type
        
    Return:
        (rrset, rrsig, name) of desired rdtype
    '''
    try:
        if rdtype == 'DNSKEY' or rdtype == 'A':
            dnskey_or_a, rrsig, name = '', '', ''
            for rrset in response.answer:      # from observation, DNSKEY and A record is in ANSWER section
                if rrset.rdtype == rdtype_dic['RRSIG']:
                    rrsig = rrset
                else:   # rrset.rdtype == rdtype_dic['DNSKEY'] or ['A']:
                    dnskey_or_a = rrset
                    name = rrset.name
            return dnskey_or_a, rrsig, name
        if rdtype == 'DS' or rdtype == 'NS':
            ds_or_ns, rrsig, name = '', '', ''
            for rrset in response.authority:   # from observation, DS and NS record is in AUTHORITY section
                if rrset.rdtype == rdtype_dic['RRSIG']:
                    rrsig = rrset
                else:
                    ds_or_ns = rrset
                    name = rrset.name
            return ds_or_ns, rrsig, name
    except Exception as e:
        print('Oops! Bug in get_rrset')
        raise e  


def verify_dnskey(response):
    '''Verify the dnskey in response. If success, return name_key and dnskey
    
    Args:
        response (dns.message.Message): a response that contains DNSKEY record
        
    Return:
        (name, dnskey) if success
    '''
    try:
        dnskey, rrsig_key, name_key = get_rrset(response, 'DNSKEY')
        dns.dnssec.validate(dnskey, rrsig_key, {name_key:dnskey})
    except Exception as e:
        raise e
    else:
        print('Congrats!',name_key, 'DNSKEYs are verified')
        return name_key, dnskey


def verify_ds(response, name_key, dnskey):
    '''Verify the ds in the response.
    
    Args:
        response (dns.message.Message): a response that contains DS record
        name_key (dns.name.Name): name of zone that contains the DNSKEY
        dnskey (dns.rrset.RRset): rrset that contains public zone signing key
    '''
    try:
        ds, rrsig_ds, name_ds = get_rrset(response, 'DS')
        dns.dnssec.validate(ds, rrsig_ds, {name_key:dnskey})
    except Exception as e:
        raise e
    else:
        print('Congrats!', name_ds, 'DS is verified')


def verify_a(response, name_key, dnskey):
    '''Verify the A record in the response.
    
    Args:
        response (dns.message.Message): a response that contains A record
        name_key (dns.name.Name): name of zone that contains the DNSKEY
        dnskey (dns.rrset.RRset): rrset that contains public zone signing key
    '''
    try:
        a, rrsig_a, name_a = get_rrset(response, 'A')
        dns.dnssec.validate(a, rrsig_a, {name_key:dnskey})
    except Exception as e:
        raise e
    else:
        print('Congrats! A records are verified')


def verify_ns(response, name_key, dnskey):
    '''Verify the NS record in the response.
    
    Args:
        response (dns.message.Message): a response that contains NS record
        name_key (dns.name.Name): name of zone that contains the DNSKEY
        dnskey (dns.rrset.RRset): rrset that contains public zone signing key
    '''
    try:
        ns, rrsig_ns, name_ns = get_rrset(response, 'NS')
        dns.dnssec.validate(ns, rrsig_ns, {name_key:dnskey})
    except Exception as e:
        print('Oops! Validation failure:', e)
    else:
        print('Congrats! NS records are verified')


def verify_root(dnskeys):
    '''Verify the root by comparing the pubksk in the response and the trusted pubksk
    
    Args:
        dnskey (dns.rrset.RRset)
    '''
    for dnskey in dnskeys:
        if dnskey.flags == 257:
            if dnskey.to_text() == get_anchor(2017):
                continue
            elif dnskey.to_text() == get_anchor(2010):
                continue
            else:
                raise Exception('Does not match trusted pubksk')
    else:
        print('Congrats! Root verified')


def verify_zone(response, response_parent):
    '''Verify the zone: do a hash on the zone's public key signing key, then see if equals to the DS in parent
    
    Args:
        response (dns.message.Message): a response that contains pubksk to verify
        response_parent (dns.message.Message): a parent response that has the trusted DS
    '''
    trust_ds, name = get_trust_ds(response_parent)
    algorithm = 'SHA256' if trust_ds.digest_type ==2 else 'SHA1'
    pubksk = get_pubksk(response)
    ds = dns.dnssec.make_ds(name, pubksk, algorithm)
    
    if ds != trust_ds:
        raise Exception('Sorry! None of the 2 public key signing keys of {} can be verified by its DS in parent\'s zone! Thus, zone {} is NOT verified'.format(name.to_text(), name.to_text()))
    print('Congrats! Zone', name, 'verified')


def get_name_from_response(response):
    '''Get the next name(zone) in the dns query chain
    
    Args:
        response (dns.message.Message): a response that contains the next name or zone in the query chain
        
    Return:
        (str): next name
    '''
    name = ''
    try:
        rrset = response.authority[0]
        name = rrset.name.to_text()
    except Exception as e:
        raise e
    else:
        return name


def verify_org_dnskey(ip):
    '''Zone org. has to query dnskey and rrsig separately. 
       There are 4 DNSKEYs for org, but you can not get all 4 of them in a single query.
       You have to query multiple times and union them until you get all the four. Shit!!!
    
    Args:
        ip (str): one ip of an org name server
        
    Return:
        (dnskey, name) if success
    '''
    dnskey_org = None
    name_org = None
    query_org = dns.message.make_query('org.', 'DNSKEY')
    response_org = dns.query.udp(query_org, ip)
    while len(response_org.answer) == 0:
        response_org = dns.query.udp(query_org, ip)
    dnskey_org = response_org.answer[0]
    name_org = dnskey_org.name
    while len(dnskey_org) != 4:
        query_org = dns.message.make_query('org.', 'DNSKEY')
        response_org = dns.query.udp(query_org, ip)
        try:
            dnskey_org.union_update(response_org.answer[0])
        except:
            pass
    
    rrsig_dnskey_org = None
    query_org = dns.message.make_query('org.', 'RRSIG')
    response_org = dns.query.udp(query_org, ip)
    while len(response_org.answer) == 0:
        response_org = dns.query.udp(query_org, ip)
    rrsig_dnskey_org = response_org.answer[0]
    
    try:
        dns.dnssec.validate(dnskey_org, rrsig_dnskey_org, {name_org:dnskey_org})
    except Exception as e:
        raise e
    else:
        print('Congrats!', name_org, 'DNSKEYs are verified')
        return name_org, dnskey_org


def verify_org_zone(dnskey_org, response_parent):
    '''Verify the zone: do a hash on the zone's public key signing key, then see if equals to the DS in parent
    
    Args:
        response (dns.message.Message): a response that contains pubksk to verify
        response_parent (dns.message.Message): a parent response that has the trusted DS
    '''
    trust_ds, name = get_trust_ds(response_parent)
    algorithm = 'SHA256' if trust_ds.digest_type ==2 else 'SHA1'
    
    dnskey_backup = dnskey_org
    
    for dnskey in dnskey_backup:
        if dnskey.flags == 256:
            dnskey_org.remove(dnskey)   # remove the public zone signing keys, so the public key signing keys are left
    
    ds2 = dns.dnssec.make_ds(name, dnskey_org.items[0], algorithm)
    ds1 = dns.dnssec.make_ds(name, dnskey_org.items[1], algorithm)
    if (ds1 == trust_ds or ds2 == trust_ds) == 0:
        raise Exception('DS does not match!', name)
    print('Congrats! Zone', name, 'verified')


class Flag(Enum):
    NO_ANSWER = 0
    HAVE_ANSWER = 1
    NO_DNSSEC = 2
    VERIFY_FAIL = 3


def dns_resolver_sec(hostname, rdtype, cnames):
    ''' My DNS resolver version sec
    
    Args:
        hostname (str): target hostname
        rdtype (str):   type A, NS, or MX
        cnames (list):  a list of CNAMES during a dns query
        parent_response (dns.message.Message): a parent response that contains child's DS rrset
    Return:
        response (dns.message.Message): response of this dns query
    '''
    for root in root_servers.values():
        try:
            response = single_iterate(hostname, rdtype, root, timeout=0.5, dnssec=True)
            response_dnskey = single_iterate('.', 'DNSKEY', root, timeout=0.5, dnssec=True)
            name_key, dnskey = verify_dnskey(response_dnskey)
            verify_ds(response, name_key, dnskey)
            verify_root(dnskey)
            response2 = None
            response_dnskey2 = None
            if len(response.additional) == 0:
                continue                           # root doesn't have top level domain information
            flag = Flag.NO_ANSWER            # flag traces whether ANSWER section is empty or not
            while flag == Flag.NO_ANSWER:                            
                if len(response.additional) > 0:   # use the IP in ADDITIONAL section
                    nextname = get_name_from_response(response)
                    for rrset in response.additional:
                        next_ip = get_ip_from_rrset(rrset)
                        try:
                            response2 = single_iterate(hostname, rdtype, next_ip, timeout=0.5, dnssec=True)
                            response_dnskey2 = single_iterate(nextname, 'DNSKEY', next_ip, timeout=0.5, dnssec=True)

                            if len(response2.answer) != 0:
                                flag = Flag.HAVE_ANSWER
                                break
                            if check_ds_exist(response2) == False:
                                flag = Flag.NO_DNSSEC
                                break
                            if nextname == 'org.': # for org. zone, when dnssec=True, DNSKEY response is empty
                                name_key, dnskey = verify_org_dnskey(next_ip) # so I wrote special functions for org.
                                verify_ds(response2, name_key, dnskey)
                                verify_org_zone(dnskey, response)
                            else:
                                name_key, dnskey = verify_dnskey(response_dnskey2)
                                verify_ds(response2, name_key, dnskey)
                                verify_zone(response_dnskey2, response)
                            
                            response = response2
                            response_dnskey = response_dnskey2
                            break
                        except Exception as e:
                            pass  #print('Oops!', e)
                else:             # if both ANSWER and ADDITIONAL is empty, then find the IP of AUTHORITY  
                    ns = get_ns_from_authority(response)
                    if check_hostname(ns):
                        response2 = dns_resolver_3(ns, 'A', cnames)
                        authority_answer = response2.answer[0]
                        response.additional.append(authority_answer)  # add rrset that contains IP of a AUTHORITY to response
                    else:
                         return response   # hostname in AUTHORITY is not valid
            if flag == Flag.NO_DNSSEC:
                return flag, response2
            
            if check_response(response2, rdtype):  # ip is in the response
                try:
                    name_key, dnskey = verify_dnskey(response_dnskey2)
                    verify_a(response2, name_key, dnskey)
                    verify_zone(response_dnskey2, response)
                except Exception as e:
                    print(e)
                    flag = Flag.VERIFY_FAIL
                    return flag, response2
                else:
                    return flag, response2
            else:                         # CNAME is in the response
                for rrset in response.answer:
                    cname = get_cname_from_rrset(rrset)
                    cnames.append(cname)
                    return dns_resolver_sec(cname, rdtype, cnames)
            break
        except Exception as e:
            print(e)

########################################################################################################



if __name__ == '__main__':
	print()
	if len(sys.argv) == 3:
		hostname = sys.argv[1]
		rdtype   = sys.argv[2]
		cnames = []
		start = time.time()
		myresponse = dns_resolver_3(hostname, rdtype, cnames)
		elapsed = time.time() - start
		output(hostname, rdtype, myresponse, elapsed, cnames)
	elif len(sys.argv) == 4:
		hostname = sys.argv[1]
		rdtype   = sys.argv[2]
		dnssec   = sys.argv[3]
		cnames = []
		if dnssec == '+dnssec':
			start = time.time()
			flag, myresponse = dns_resolver_sec(hostname, rdtype, cnames)
			elapsed = time.time() - start
			if flag == Flag.HAVE_ANSWER:
				output_sec(hostname, rdtype, myresponse, elapsed, cnames)
			elif flag == Flag.NO_DNSSEC:
				print('\nQuery time: ' + str(int(elapsed * 1000)) + ' msec')
				print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
				print('\nDNSSEC not supported')
			elif flag == Flag.VERIFY_FAIL:
				print('\nQuery time: ' + str(int(elapsed * 1000)) + ' msec')
				print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
				print('\nDNSSec Verification failed')
	print()
