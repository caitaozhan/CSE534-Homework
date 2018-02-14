import sys
import dns.query
import dns.message
import re
import ipaddress
import time
import datetime
import random

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


def single_iterate(hostname, rdtype, where, timeout=1):
    ''' A single iterative DNS query
    
    Args:
        hostname (str): host to be queried
        rdtype (str): type A, NS, or MX
        where (str):  IP address of query destination
    
    Return: 
        response (dns.message.Message): the response of a single query
        
    Exception:
        May raise an exception
    '''
    a_query = dns.message.make_query(hostname, rdtype)
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


if __name__ == '__main__':
	hostname = sys.argv[1]
	rdtype   = sys.argv[2]
	cnames = []
	start = time.time()

	myresponse = dns_resolver_3(hostname, rdtype, cnames)

	elapsed = time.time() - start
	output(hostname, rdtype, myresponse, elapsed, cnames)
