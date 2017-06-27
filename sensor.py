#!/usr/bin/env python
# -*- coding:utf-8 -*-
from __future__ import print_function  # Requires: Python >= 2.6
# remove print and use print function
import sys
#from aifc import data

sys.dont_write_bytecode = True

import core.versioncheck # only support python 2.6 and 2.7
import core.ipgetter
import inspect
import math
import mmap
import csv
import os
import platform
import re
import socket
import subprocess
import struct
import threading
import time
import traceback
import urllib
import urlparse
from scapy.all import srp, Ether, ARP, conf

from core.addr import inet_ntoa6
from core.attribdict import AttribDict
from core.common import check_connection
from core.common import check_sudo

from core.enums import BLOCK_MARKER
from core.enums import PROTO
from core.enums import TRAIL
from core.log import create_log_directory

from core.log import get_error_log_handle
from core.log import log_error
from core.log import log_event
from core.parallel import worker

from core.parallel import write_block
from core.parallel import Check_Local_Hosts
from core.settings import check_memory
from core.settings import config

from core.settings import CAPTURE_TIMEOUT
from core.settings import CHECK_CONNECTION_MAX_RETRIES
from core.settings import CONFIG_FILE
from core.settings import CONSONANTS
from core.settings import DAILY_SECS
from core.settings import DLT_OFFSETS
from core.settings import DNS_EXHAUSTION_THRESHOLD
from core.settings import IGNORE_DNS_QUERY_SUFFIXES
from core.settings import IPPROTO_LUT
from core.settings import LOCALHOST_IP
from core.settings import MMAP_ZFILL_CHUNK_LENGTH
from core.settings import MAX_RESULT_CACHE_ENTRIES
from core.settings import NAME
from core.settings import NO_SUCH_NAME_COUNTERS
from core.settings import NO_SUCH_NAME_PER_HOUR_THRESHOLD
from core.settings import PORT_SCANNING_THRESHOLD
from core.settings import read_config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SNAP_LEN
from core.settings import SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS
from core.settings import SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD
from core.settings import SUSPICIOUS_HTTP_PATH_REGEXES
from core.settings import SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION
from core.settings import SUSPICIOUS_HTTP_REQUEST_REGEXES
from core.settings import SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS
from core.settings import SUSPICIOUS_UA_REGEX
#from core.settings import trails
from core.settings import VALID_DNS_CHARS
from core.settings import VERSION
from core.settings import WHITELIST
from core.settings import WHITELIST_DIRECT_DOWNLOAD_KEYWORDS
from core.settings import WHITELIST_LONG_DOMAIN_NAME_KEYWORDS
from core.settings import WHITELIST_HTTP_REQUEST_PATHS
from core.settings import WHITELIST_UA_KEYWORDS
from core.common import retrieve_content
from core.settings import TRAILS_FILE
from core.settings import USERS_DIR
_host_ip=''
_outer_ip=''
_buffer = None
_caps = []
_connect_sec = 0
_connect_src_dst = {}
_connect_src_details = {}
_count = 0
_locks = AttribDict()
_multiprocessing = None
_n = None
_result_cache = {}
_last_syn = None
_last_logged_syn = None
_last_udp = None
_last_logged_udp = None
_last_dns_exhaustion = None
_subdomains = {}
_subdomains_sec = None
_dns_exhausted_domains = set()

try:
    import pcapy
except ImportError:
    if subprocess.mswindows:
        exit("[!] please install 'WinPcap' (e.g. 'http://www.winpcap.org/install/') and Pcapy (e.g. 'https://breakingcode.wordpress.com/?s=pcapy')")
    else:
        msg, _ = "[!] please install 'Pcapy'", platform.linux_distribution()[0].lower()
        for distro, install in {("fedora", "centos"): "sudo yum install pcapy", ("debian", "ubuntu"): "sudo apt-get install python-pcapy"}.items():
            if _ in distro:
                msg += " (e.g. '%s')" % install
                break
        exit(msg)


def invalid_ip(address):
    try:
        socket.inet_aton(address)
        return False
    except:
        return True

def _check_domain_member(query, domains):
    parts = query.lower().split('.')

    for i in xrange(0, len(parts)):
        domain = '.'.join(parts[i:])
        if domain in domains:
            return True

    return False

def _check_domain_whitelisted(query):
    return _check_domain_member(query, WHITELIST)

def _check_domain(query, sec, usec, src_ip, src_port, dst_ip, dst_port, proto, HostInfo, DomainInfo, BrowserInfo, packet=None):
    if _result_cache.get(query) == False:
        return

    result = False
    if not _check_domain_whitelisted(query) and all(_ in VALID_DNS_CHARS for _ in query):
        parts = query.lower().split('.')

        for i in xrange(0, len(parts)):
            domain = '.'.join(parts[i:])
            #if domain in trails:
            if domain == query:
                trail = domain
            else:
                _ = ".%s" % domain
                trail = "(%s)%s" % (query[:-len(_)], _)

            result = True
            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, "", "", HostInfo, DomainInfo, BrowserInfo), packet)
            break

        if not result and config.USE_HEURISTICS:
            if len(parts[0]) > SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD and '-' not in parts[0]:
                trail = None

                if len(parts) > 2:
                    trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                elif len(parts) == 2:
                    trail = "(%s).%s" % (parts[0], parts[1])
                else:
                    trail = query

                if trail and not any(_ in trail for _ in WHITELIST_LONG_DOMAIN_NAME_KEYWORDS):
                    result = True
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, "long domain (suspicious)", "(heuristic)", HostInfo, DomainInfo, BrowserInfo), packet)

            elif "sinkhole" in query:
                result = True
                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, query, "potential sinkhole domain (suspicious)", "(heuristic)", HostInfo, DomainInfo, BrowserInfo), packet)

    if result == False:
        _result_cache[query] = False
#------------------add by qkf

def IsInner(host_ip):
    tmp=host_ip.split(".");
    if tmp[0]==_host_ip_set[0] and tmp[1]==_host_ip_set[1]:
        return True;
    else:
        return False;
#-------------------------
import socket
import fcntl
import struct
 
def _get_host_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
    s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
#----------------------
class mip:
    data= "-"
    version= "-"
    header= "-"
    length= "-"
    HostInfo = "-"
    DomainInfo = "-"
    BrowserInfo = "-"
    protocol= "-"
    localhost_ip= "-"
    src_ip= "-"
    dst_ip= "-"
    def init(self,packet,sec, usec, ip_offset):
        self.data=packet[ip_offset:]
        self.version=ord(self.data[0])>>4
        self.localhost_ip = LOCALHOST_IP[self.version]
    def is_ipv4(self):
        if self.version==0x04:
            self.header = struct.unpack("BBHHHBBH4s4s", self.data[:20])#
            self.length = (self.header[0] & 0xf) << 2
            self.protocol =self.header[6]  
            self.src_ip = socket.inet_ntoa(self.header[8])#转换32位打包的IPV4地址为IP地址的标准点号分隔字符串表示。12.1.1
            self.dst_ip = socket.inet_ntoa(self.header[9])
            return True
        else:
            return False
    def solveTCP(self,packet,sec,usec,ip_offset,_connect_sec,_last_syn,_last_logged_syn,_last_udp,_last_logged_udp,_last_dns_exhaustion,_subdomains_sec):
        src_port, dst_port, _, _, doff_reserved, flags = struct.unpack("!HHLLBB", self.data[self.length:self.length+14])
        if flags != 2 and config.plugin_functions:
            log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.IP, "", "", "", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet, skip_write=True)

        if flags == 2:  # SYN set (only)
            # update last syn
            _ = _last_syn
            _last_syn = (sec, self.src_ip, src_port, self.dst_ip, dst_port)
            if _ == _last_syn:  # skip bursts
                return

            # update last logged syn
            _ = _last_logged_syn
            _last_logged_syn = _last_syn
            if _ != _last_logged_syn:
                log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.IP, "", "", "", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)

            if config.USE_HEURISTICS:
                if self.dst_ip != self.localhost_ip:
                    key = "%s~%s" % (self.src_ip, self.dst_ip)
                    if key not in _connect_src_dst:
                        _connect_src_dst[key] = set()
                        _connect_src_details[key] = set()
                    _connect_src_dst[key].add(dst_port)
                    _connect_src_details[key].add((sec, usec, src_port, dst_port))

        else:
            tcph_length = doff_reserved >> 4
            h_size = self.length + (tcph_length << 2)
            tcp_data = self.data[h_size:]
            

            if tcp_data.startswith("GET "):
                Http_message = tcp_data.split("\r\n")
                for Http_line in Http_message:
                    if "Host: " in Http_line:
                        tmpHostInfo = Http_line.split(": ")
                        if len(tmpHostInfo) > 1:
                            HostInfo = tmpHostInfo[1]
                           
                    if "User-Agent: " in Http_line:
                        tmpHostInfo = Http_line.split(": ")
                        if len(tmpHostInfo) > 1:
                            self.BrowserInfo = tmpHostInfo[1].split(" ", 1)[0]
                            

            if config.USE_DEEP_HEURISTICS:
                if tcp_data.startswith("HTTP/"):
                    if any(_ in tcp_data[:tcp_data.find("\r\n\r\n")] for _ in ("X-Sinkhole:", "X-Malware-Sinkhole:", "Server: You got served", "Server: Apache 1.0/SinkSoft", "sinkdns.org")) or "\r\n\r\nsinkhole" in tcp_data:

                        log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.IP, self.src_ip, "sinkhole response (malware)", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)

                    else:
                        index = tcp_data.find("<title>")
                        if index >= 0:
                            title = tcp_data[index + len("<title>"):tcp_data.find("</title>", index)]
                            if all(_ in title.lower() for _ in ("this domain", "has been seized")):

                                log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.IP, title, "seized domain (suspicious)", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)


            method, path = None, None
            index = tcp_data.find("\r\n")
            if index >= 0:
                line = tcp_data[:index]
                if line.count(' ') == 2 and " HTTP/" in line:
                    method, path, _ = line.split(' ')

            if method and path:
                post_data = None
                host = self.dst_ip
                first_index = tcp_data.find("\r\nHost:")

                if first_index >= 0:
                    first_index = first_index + len("\r\nHost:")
                    last_index = tcp_data.find("\r\n", first_index)
                    if last_index >= 0:
                        host = tcp_data[first_index:last_index]
                        host = host.strip()
                        if host.endswith(":80"):
                            host = host[:-3]
                        if host and host[0].isalpha():
                            log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.IP, "%s (%s)" % (self.dst_ip, host.split(':')[0]), "", "", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)
                elif config.USE_HEURISTICS and config.CHECK_MISSING_HOST:
                    log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, "%s%s" % (host, path), "missing host header (suspicious)", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)

                index = tcp_data.find("\r\n\r\n")
                if index >= 0:
                    post_data = tcp_data[index + 4:]

                if "://" in path:
                    url = path.split("://", 1)[1]

                    if '/' not in url:
                        url = "%s/" % url

                    host, path = url.split('/', 1)
                    if host.endswith(":80"):
                        host = host[:-3]
                    path = "/%s" % path
                    proxy_domain = host.split(':')[0]
                    _check_domain(proxy_domain, sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, self.HostInfo, self.DomainInfo, self.BrowserInfo,packet)
                elif method == "CONNECT":
                    if '/' in path:
                        host, path = path.split('/', 1)
                        path = "/%s" % path
                    else:
                        host, path = path, '/'
                    if host.endswith(":80"):
                        host = host[:-3]
                    url = "%s%s" % (host, path)
                    proxy_domain = host.split(':')[0]
                    _check_domain(proxy_domain, sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, self.HostInfo, self.DomainInfo, self.BrowserInfo, packet)
                else:
                    url = "%s%s" % (host, path)

                if config.USE_HEURISTICS:
                    user_agent, result = None, None

                    first_index = tcp_data.find("\r\nUser-Agent:")
                    if first_index >= 0:
                        first_index = first_index + len("\r\nUser-Agent:")
                        last_index = tcp_data.find("\r\n", first_index)
                        if last_index >= 0:
                            user_agent = tcp_data[first_index:last_index]
                            user_agent = urllib.unquote(user_agent).strip()

                    if user_agent:
                        result = _result_cache.get(user_agent)
                        if result is None:
                            if not any(_ in user_agent for _ in WHITELIST_UA_KEYWORDS):
                                match = re.search(SUSPICIOUS_UA_REGEX, user_agent)
                                if match:
                                    def _(value):
                                        return value.replace('(', "\\(").replace(')', "\\)")

                                    if match.group(0):
                                        parts = user_agent.split(match.group(0), 1)

                                        if len(parts) > 1 and parts[0] and parts[-1]:
                                            result = _result_cache[user_agent] = "%s (%s)" % (_(match.group(0)), _(user_agent))
                                        else:
                                            result = _result_cache[user_agent] = _(match.group(0)).join(("(%s)" if part else "%s") % _(part) for part in parts)
                            if not result:
                                _result_cache[user_agent] = False

                        if result:
                            log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.UA, result, "user agent (suspicious)", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)

                checks = [path.rstrip('/')]
                if '?' in path:
                    checks.append(path.split('?')[0].rstrip('/'))

                _ = os.path.splitext(checks[-1])
                if _[1]:
                    checks.append(_[0])

                if checks[-1].count('/') > 1:
                    checks.append(checks[-1][:checks[-1].rfind('/')])

                for check in filter(None, checks):
                    for _ in ("", host):
                        check = "%s%s" % (_, check)
                        #if check in trails:
                        parts = url.split(check)
                        other = ("(%s)" % _ if _ else _ for _ in parts)
                        trail = check.join(other)
                        log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "", "", self.HostInfo, self.DomainInfo, self.BrowserInfo))
                        return

                if config.USE_HEURISTICS:
                    unquoted_path = urllib.unquote(path)
                    unquoted_post_data = urllib.unquote(post_data or "")
                    for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS:
                        replacement = SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS[char]
                        path = path.replace(char, replacement)
                        if post_data:
                            post_data = post_data.replace(char, replacement)

                    if not _check_domain_whitelisted(host):
                        if not any(_ in unquoted_path.lower() for _ in WHITELIST_HTTP_REQUEST_PATHS):
                            if any(_ in unquoted_path for _ in SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION):
                                found = _result_cache.get(unquoted_path)
                                if found is None:
                                    for desc, regex in SUSPICIOUS_HTTP_REQUEST_REGEXES:
                                        if re.search(regex, unquoted_path, re.I | re.DOTALL):
                                            found = desc
                                            break
                                    _result_cache[unquoted_path] = found or ""
                                if found:
                                    trail = "%s(%s)" % (host, path)
                                    log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "%s (suspicious)" % found, "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)
                                    return

                            if any(_ in unquoted_post_data for _ in SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION):
                                found = _result_cache.get(unquoted_post_data)
                                if found is None:
                                    for desc, regex in SUSPICIOUS_HTTP_REQUEST_REGEXES:
                                        if re.search(regex, unquoted_post_data, re.I | re.DOTALL):
                                            found = desc
                                            break
                                    _result_cache[unquoted_post_data] = found or ""
                                if found:
                                    trail = "%s(%s \(%s %s\))" % (host, path, method, post_data.strip())
                                    log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, trail, "%s (suspicious)" % found, "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)
                                    return

                        if '.' in path:
                            _ = urlparse.urlparse("http://%s" % url)  # dummy scheme
                            filename = _.path.split('/')[-1]
                            name, extension = os.path.splitext(filename)
                            trail = "%s(%s)" % (host, path)
                            if extension and extension in SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS and not any(_ in path for _ in WHITELIST_DIRECT_DOWNLOAD_KEYWORDS) and not _.query and len(name) < 10:
                                log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "direct %s download (suspicious)" % extension, "(heuristic)",self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)
                            else:
                                for desc, regex in SUSPICIOUS_HTTP_PATH_REGEXES:
                                    if re.search(regex, filename, re.I):
                                        log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "%s (suspicious)" % desc, "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo,), packet)
                                        break
    def solveUDP(self,packet,sec,usec,ip_offset,_connect_sec,_last_syn,_last_logged_syn,_last_udp,_last_logged_udp,_last_dns_exhaustion,_subdomains_sec): 
        _ = self.data[self.length:self.length + 4]
        if len(_) < 4:
            return

        src_port, dst_port = struct.unpack("!HH", _)

        _ = _last_udp
        _last_udp = (sec, self.src_ip, src_port, self.dst_ip, dst_port)
        if _ == _last_udp:  # skip bursts
            return

        if src_port != 53 and dst_port != 53:  # not DNS
            _ = _last_logged_udp
            _last_logged_udp = _last_udp
            if _ != _last_logged_udp:
                log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, TRAIL.IP, "", "", "", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)

        else:
            dns_data = self.data[self.length + 8:]

            # Reference: http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
            if len(dns_data) > 6:
                qdcount = struct.unpack("!H", dns_data[4:6])[0]
                if qdcount > 0:
                    offset = 12
                    query = ""

                    while len(dns_data) > offset:
                        length = ord(dns_data[offset])
                        if not length:
                            query = query[:-1]
                            break
                        query += dns_data[offset + 1:offset + length + 1] + '.'
                        offset += length + 1

                    query = query.lower()
                    DomainInfo = query
                    

                    if not query or '.' not in query or not all(_ in VALID_DNS_CHARS for _ in query) or any(_ in query for _ in (".intranet.",)) or any(query.endswith(_) for _ in IGNORE_DNS_QUERY_SUFFIXES):
                        return

                    parts = query.split('.')

                    if ord(dns_data[2]) == 0x01:  # standard query
                        type_, class_ = struct.unpack("!HH", dns_data[offset + 1:offset + 5])

                        if len(parts) > 2:
                            domain = '.'.join(parts[-2:])

                            if not _check_domain_whitelisted(domain):  # e.g. <hash>.hashserver.cs.trendmicro.com
                                if (sec - (_subdomains_sec or 0)) > DAILY_SECS:
                                    _subdomains.clear()
                                    _dns_exhausted_domains.clear()
                                    _subdomains_sec = sec

                                subdomains = _subdomains.get(domain)

                                if not subdomains:
                                    subdomains = _subdomains[domain] = set()

                                if len(subdomains) < DNS_EXHAUSTION_THRESHOLD:
                                    subdomains.add('.'.join(parts[:-2]))
                                else:
                                    if (sec - (_last_dns_exhaustion or 0)) > 60:
                                        trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                                        log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, "potential dns exhaustion (suspicious)", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)
                                        _dns_exhausted_domains.add(domain)
                                        _last_dns_exhaustion = sec

                                    return

                        # Reference: http://en.wikipedia.org/wiki/List_of_DNS_record_types
                        if type_ not in (12, 28) and class_ == 1:  # Type not in (PTR, AAAA), Class IN
                           
                            log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, TRAIL.IP, "", "", "", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)

                            _check_domain(query, sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, self.HostInfo, self.DomainInfo, self.BrowserInfo, packet)

                    elif config.USE_HEURISTICS:
                        if ord(dns_data[2]) & 0x80:  # standard response
                            if ord(dns_data[3]) == 0x80:  # recursion available, no error
                                if (ord(dns_data[offset + 5]) & 0xc0) and (dns_data[offset + 15] == "\x00") and (dns_data[offset + 16] == "\x04"):  # QNAME compression, IPv4 result address
                                    answer = socket.inet_ntoa(dns_data[offset + 17:offset + 21])
                                    if answer:
                                        trail = "(%s).%s" % ('.'.join(parts[:-1]), '.'.join(parts[-1:]))
                                        log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, "", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)  # (e.g. kitro.pl, devomchart.com, jebena.ananikolic.su, vuvet.cn)
                            elif ord(dns_data[3]) == 0x83:  # recursion available, no such name
                                if '.'.join(parts[-2:]) not in _dns_exhausted_domains and not _check_domain_whitelisted(query):
                                    if parts[-1].isdigit():
                                        return

                                    if not (len(parts) > 4 and all(_.isdigit() and int(_) < 256 for _ in parts[:4])):  # generic check for DNSBL IP lookups
                                        for _ in filter(None, (query, "*.%s" % '.'.join(parts[-2:]) if query.count('.') > 1 else None)):
                                            if _ not in NO_SUCH_NAME_COUNTERS or NO_SUCH_NAME_COUNTERS[_][0] != sec / 3600:
                                                NO_SUCH_NAME_COUNTERS[_] = [sec / 3600, 1, set()]
                                            else:
                                                NO_SUCH_NAME_COUNTERS[_][1] += 1
                                                NO_SUCH_NAME_COUNTERS[_][2].add(query)

                                                if NO_SUCH_NAME_COUNTERS[_][1] > NO_SUCH_NAME_PER_HOUR_THRESHOLD:
                                                    if _.startswith("*."):
                                                        log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, "%s%s" % ("(%s)" % ','.join(item.replace(_[1:], "") for item in NO_SUCH_NAME_COUNTERS[_][2]), _[1:]), "excessive no such domain (suspicious)", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)
                                                        for item in NO_SUCH_NAME_COUNTERS[_][2]:
                                                            try:
                                                                del NO_SUCH_NAME_COUNTERS[item]
                                                            except KeyError:
                                                                pass
                                                    else:
                                                        log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, _, "excessive no such domain (suspicious)", "(heuristic)", self.HostInfo, self.DomainInfo, self.BrowserInfo), packet)

                                                    try:
                                                        del NO_SUCH_NAME_COUNTERS[_]
                                                    except KeyError:
                                                        pass

                                                    break

                                        if len(parts) > 2:
                                            part = parts[0] if parts[0] != "www" else parts[1]
                                            trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                                        elif len(parts) == 2:
                                            part = parts[0]
                                            trail = "(%s).%s" % (parts[0], parts[1])
                                        else:
                                            part = query
                                            trail = query

                                        if part and '-' not in part:
                                            result = _result_cache.get(part)

                                            if result is None:
                                                # Reference: https://github.com/exp0se/dga_detector
                                                probabilities = (float(part.count(c)) / len(part) for c in set(_ for _ in part))
                                                entropy = -sum(p * math.log(p) / math.log(2.0) for p in probabilities)
                                                if entropy > SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD:
                                                    result = "entropy threshold no such domain (suspicious)"

                                                if not result:
                                                    if sum(_ in CONSONANTS for _ in part) > SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD:
                                                        result = "consonant threshold no such domain (suspicious)"

                                                _result_cache[part] = result or False

                                            if result:
                                                log_event((sec, usec, self.src_ip, src_port, self.dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, result, "(heuristic)", self.HostInfo, self.DomainInfo,self.BrowserInfo), packet)

                                  
#----------------------
def _process_packet(packet, sec, usec, ip_offset):
    """
    Processes single (raw) IP layer data
    """
    global _connect_sec
    global _last_syn
    global _last_logged_syn
    global _last_udp
    global _last_logged_udp
    global _last_dns_exhaustion
    global _subdomains_sec

    try:
        if len(_result_cache) > MAX_RESULT_CACHE_ENTRIES:
            _result_cache.clear()
        ip=mip()
        ip.init(packet,sec,usec,ip_offset)
        if not ip.is_ipv4():
            return 

        if IsInner(ip.src_ip):
            ip.src_ip=core.ipgetter.myip()
        if IsInner(ip.dst_ip):
            ip.dst_ip=core.ipgetter.myip()
        if invalid_ip(ip.src_ip) or invalid_ip(ip.dst_ip):
            return

        if ip.protocol == socket.IPPROTO_TCP:  # TCP
            ip.solveTCP(packet, sec, usec, ip_offset,_connect_sec,_last_syn,_last_logged_syn,_last_udp,_last_logged_udp,_last_dns_exhaustion,_subdomains_sec)
        elif ip.protocol == socket.IPPROTO_UDP:  # UDP
            ip.solveUDP(packet, sec, usec, ip_offset,_connect_sec,_last_syn,_last_logged_syn,_last_udp,_last_logged_udp,_last_dns_exhaustion,_subdomains_sec)
        elif ip.protocol in IPPROTO_LUT:  # non-TCP/UDP (e.g. ICMP)
            if ip.protocol == socket.IPPROTO_ICMP:
                if ord(ip.data[ip.length]) != 0x08:  # Non-echo request
                    return
            elif ip.protocol == socket.IPPROTO_ICMPV6:
                if ord(ip.data[ip.length]) != 0x80:  # Non-echo request
                    return
            log_event((sec, usec, ip.src_ip, '-', ip.dst_ip, '-', IPPROTO_LUT[ip.protocol], TRAIL.IP, "", "", "", ip.HostInfo, ip.DomainInfo, ip.BrowserInfo), packet)
    except struct.error:
        pass
    except SystemError, ex:
        print(ex)
    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
#--------------------
def create_trails_directory():
    if not os.path.isdir(USERS_DIR):   
        os.makedirs(USERS_DIR)
    print("[i] using '%s' for trails storage" % USERS_DIR)
#---------------------------
def init():
    """
    Performs sensor initialization
    """

    global _multiprocessing

    try:
        import multiprocessing

        if config.PROCESS_COUNT > 1:
            _multiprocessing = multiprocessing
    except (ImportError, OSError, NotImplementedError):
        pass
    create_trails_directory()#创建路径目录
    create_log_directory()#创建日志目录
    get_error_log_handle()

    check_memory()  #检查内存是否足够
    get_trails_from_server(str(config.UPDATE_SERVER))
    
    interfaces = set(_.strip() for _ in config.MONITOR_INTERFACE.split(','))

    if (config.MONITOR_INTERFACE or "").lower() == "any":
        if subprocess.mswindows or "any" not in pcapy.findalldevs():
            print("[x] virtual interface 'any' missing. Replacing it with all interface names")
            interfaces = pcapy.findalldevs()
        else:
            print("[?] in case of any problems with packet capture on virtual interface 'any', please put all monitoring interfaces to promiscuous mode manually (e.g. 'sudo ifconfig eth0 promisc')")

    for interface in interfaces:
        if interface.lower() != "any" and interface not in pcapy.findalldevs():
            hint = "[?] available interfaces: '%s'" % ",".join(pcapy.findalldevs())
            exit("[!] interface '%s' not found\n%s" % (interface, hint))

        print("[i] opening interface '%s'" % interface)
        try:
            # open device
            # Arguments here are:
            #   device
            #   snaplen (maximum number of bytes to capture _per_packet_)
            #   promiscious mode (1 for true)
            #   timeout (in milliseconds)
                _caps.append(pcapy.open_live(interface, SNAP_LEN, True, CAPTURE_TIMEOUT))
        except (socket.error, pcapy.PcapError):
            if "permitted" in str(sys.exc_info()[1]):
                exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)
            elif "No such device" in str(sys.exc_info()[1]):
                exit("[!] no such device '%s'" % interface)
            else:
                raise

   # if config.LOG_SERVER and not len(config.LOG_SERVER.split(':')) == 2:
   #     exit("[!] invalid configuration value for 'LOG_SERVER' ('%s')" % config.LOG_SERVER)

    if config.CAPTURE_FILTER:
        print("[i] setting capture filter '%s'" % config.CAPTURE_FILTER)
        for _cap in _caps:
            _cap.setfilter(config.CAPTURE_FILTER)

    if _multiprocessing:
        _init_multiprocessing()

    
    #-----------------------------------------

def _init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    global _buffer
    global _n

    if _multiprocessing:
        print("[i] preparing capture buffer...")
        try:
            _buffer = mmap.mmap(-1, config.CAPTURE_BUFFER)  # http://www.alexonlinux.com/direct-io-in-python

            _ = "\x00" * MMAP_ZFILL_CHUNK_LENGTH
            for i in xrange(config.CAPTURE_BUFFER / MMAP_ZFILL_CHUNK_LENGTH):
                _buffer.write(_)
                #print(i)
            _buffer.seek(0)
        except KeyboardInterrupt:
            raise
        except:
            exit("[!] unable to allocate network capture buffer. Please adjust value of 'CAPTURE_BUFFER'")

        print("[i] creating %d more processes (out of total %d)" % (config.PROCESS_COUNT - 1, config.PROCESS_COUNT))
        _n = _multiprocessing.Value('L', lock=False)

        for i in xrange(config.PROCESS_COUNT - 1):
            process = _multiprocessing.Process(target=worker, name=str(i), args=(_buffer, _n, i, config.PROCESS_COUNT - 1, _process_packet))
            process.daemon = True
            process.start()

def monitor():
    """
    Sniffs/monitors given capturing interface
    """

    print("[o] running...")

    def packet_handler(datalink, header, packet):
        global _count

        ip_offset = None
        dlt_offset = DLT_OFFSETS[datalink]

        try:
            if datalink == pcapy.DLT_RAW:
                ip_offset = dlt_offset

            elif datalink == pcapy.DLT_PPP:
                if packet[2:4] in ("\x00\x21", "\x00\x57"):  # (IPv4, IPv6)
                    ip_offset = dlt_offset

            elif dlt_offset >= 2:
                if packet[dlt_offset - 2:dlt_offset] == "\x81\x00":  # VLAN
                    dlt_offset += 4
                if packet[dlt_offset - 2:dlt_offset] in ("\x08\x00", "\x86\xdd"):  # (IPv4, IPv6)
                    ip_offset = dlt_offset

        except IndexError:
            pass

        if ip_offset is None:
            return
        #print(struct.unpack("16s", packet[0:16]))

        try:
            sec, usec = header.getts()
            if _multiprocessing:
                if _locks.count:
                    _locks.count.acquire()

                write_block(_buffer, _count, struct.pack("=III", sec, usec, ip_offset) + packet)
                _n.value = _count = _count + 1

                if _locks.count:
                    _locks.count.release()
            else:
                _process_packet(packet, sec, usec, ip_offset)
        except socket.timeout:
            pass
        except SystemError, ex:
            print(ex)

    #Create a thread checking IP-MAC-HOST regularly
    Check_Local_Hosts()

    try:
        def _(_cap):
            datalink = _cap.datalink()
            while True:
                try:
                    (header, packet) = _cap.next()
                    if header is None:
                        _caps.remove(_cap)
                        break
                    packet_handler(datalink, header, packet)
                except (pcapy.PcapError, socket.timeout):
                    pass

        if len(_caps) > 1:
            if _multiprocessing:
                _locks.count = threading.Lock()
            _locks.connect_sec = threading.Lock()

        for _cap in _caps:
            threading.Thread(target=_, args=(_cap,)).start()

        while _caps:
            time.sleep(1)

        print("[i] finished")
    except SystemError, ex:
        if "error return without" in str(ex):
            print("\r[x] stopping (Ctrl-C pressed)")
        else:
            raise
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")
    finally:
        print("\r[i] please wait...")
        if _multiprocessing:
            try:
                for _ in xrange(config.PROCESS_COUNT - 1):
                    write_block(_buffer, _n.value, "", BLOCK_MARKER.END)
                    _n.value = _n.value + 1
                while _multiprocessing.active_children():
                    time.sleep(REGULAR_SENSOR_SLEEP_TIME)
            except KeyboardInterrupt:
                pass
#--------get trails from server--------------------
def get_trails_from_server(server):
    __url__ = server
    content = retrieve_content(__url__)
    if(content):
        fp=file(TRAILS_FILE,'w+')
        fp.write(content)
        fp.close()
    thread = threading.Timer(config.UPDATE_PERIOD, get_trails_from_server)
    thread.daemon = True
    thread.start()

#---------------
def main():
    
    global _host_ip_set
    print("%s #v%s\n" % (NAME, VERSION))

    if not check_sudo():
        exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)

   
    read_config(os.path.split(CONFIG_FILE)[-1])
    
    _host_ip=_get_host_ip(config.MONITOR_INTERFACE)
    _host_ip_set=_host_ip.split('.')

    
    try:
        init()
        #get_trails_from_server("http://222.30.48.22:8338/trails")
        monitor()
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    show_final = True

    try:
        main()
    except SystemExit, ex:
        show_final = False

        print(ex)
    except IOError:
        show_final = False
        log_error("\n\n[!] session abruptly terminated\n[?] (hint: \"https://stackoverflow.com/a/20997655\")")
    except Exception:
        msg = "\r[!] unhandled exception occurred ('%s')" % sys.exc_info()[1]
        log_error("\n\n%s" % msg.replace("\r", ""))

        print(msg)
    finally:
        if show_final:
            print("[i] finished")

        os._exit(0)
