import gzip
import json
import re
import sys
from collections import namedtuple

import pendulum
from user_agents import parse as ua_parse

Record = namedtuple("AccessLog", [
    "ip",
    "time",
    "method",
    "path",
    "status",
    "bandwidth",
    "referrer",
    "user_agent",
    "unix_time",
    "device",
    "os",
    "browser"
])

LOG_PATTERN = (
    r''
    '(\d+.\d+.\d+.\d+)\s-\s-\s'  # IP address
    '\[(.+)\]\s'  # datetime
    # '"GET\s(.+)\s\w+/.+"\s'  # requested file GET method
    '"(.+)\s(.+)\s\w+/.+"\s'  # method and requested file. output add 1 field
    '(\d+)\s'  # status
    '(\d+)\s'  # bandwidth
    # '"(.+)"\s'  # referrer not allow empty
    '"(.*)"\s'  # referrer allow empty
    '"(.+)"'  # user agent
)


def nginx_log_parse(log_str):
    match = re.findall(LOG_PATTERN, log_str)
    if not match:
        return []

    return list(match[0])


def get_ipv6(log_str):
    IPV4SEG = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
    IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
    IPV6SEG = r'(?:(?:[0-9a-fA-F]){1,4})'
    IPV6GROUPS = (
        '(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
        '(?:' + IPV6SEG + r':){1,7}:',                           # 1::                                 1:2:3:4:5:6:7::
        '(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
        '(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
        '(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
        '(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
        '(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
        IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',            # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
        ':(?:(?::' + IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
        'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
        '::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,     # ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
        '(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,          # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
    )
    IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # Reverse rows for greedy match

    match = re.findall(IPV6ADDR, log_str)

    if match:
        return match[0]

    return ''


def parsing_log(log_str):
    parsed = nginx_log_parse(log_str)
    if parsed:
        return parsed

    ipv6 = get_ipv6(log_str)
    if not ipv6:
        print(log_str)
        raise ValueError("Parsing ipv6 error")

    new_log_str = log_str.replace(ipv6, '0.0.0.0')
    parsed = nginx_log_parse(new_log_str)
    if not parsed:
        print(new_log_str)
        raise RuntimeError("failed parsing")

    parsed[0] = ipv6

    return parsed


def main(file_path):
    with gzip.open(file_path, 'rt') as ifp, open('access_log.json', 'a') as ofp:
        line_num = 0
        print("=====", file_path, "=====")
        for log_line in ifp:
            line_num += 1
            print(line_num)
            if not log_line.strip():
                continue

            result = parsing_log(log_line)

            user_agent = ua_parse(result[-1])
            parsed_time = pendulum.from_format(result[1], "DD/MMM/YYYY:HH:mm:ss ZZ")
            result.append(parsed_time.int_timestamp)
            result.append(user_agent.get_device())
            result.append(user_agent.get_os())
            result.append(user_agent.get_browser())
            try:
                log_record = Record._make(result)  # Record(*log_parsed)
            except IndexError as e:
                print(log_line)
                raise IndexError(e)

            json_record = json.dumps(log_record._asdict())
            ofp.write("{}\n".format(json_record))


if __name__ == "__main__":
    LOG_FILE_PATH = sys.argv[1]
    main(LOG_FILE_PATH)
