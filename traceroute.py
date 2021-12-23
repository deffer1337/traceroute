import sys
import time
from typing import List
from collections import namedtuple

from scapy.all import sr1
from scapy.layers.inet import IP, TCP, UDP, ICMP
from prettytable import PrettyTable, PLAIN_COLUMNS

from modules.argparser import TracerouteArgParse


def start_traceroute(ttl: int, maximum_ttl: int, destination: str, timeout: float,
                     function_create_package, function_handler_last_packet) \
        -> List[namedtuple('Route', ['ip', 'time'])]:
    """
    Start traceroute
    :param ttl: ttl for ip package
    :param maximum_ttl: Maximum ttl that can be
    :param destination: IP address you need to show the route
    :param timeout: Response timeout
    :param function_create_package: A function that should create a package that contains destination IP and protocol
    UDP, TCP or ICMP. UDP and TCP packages should be have port
    :param function_handler_last_packet: Function that processes the last package.
    For the ICMP protocol, she should simply return True, for the UDP protocol, check whether an ICMP package
    with type and code 3 has come to us, for the TCP protocol,
    it should check whether a TCP package with SYN ACK or RST flags has come to us.
    :return: List[namedtuple] where namedtuple have ip and time. ip - ip is the router's ip or destination address,
    time is the response time from the router or destination address.
    """
    try_count = 0
    routes = []
    Route = namedtuple('Route', ['ip', 'time'])
    while ttl <= maximum_ttl:
        package = function_create_package(ttl, destination)
        start = time.time()
        answer = sr1(package, timeout=timeout, verbose=0)
        end = time.time()
        if answer:
            routes.append(Route(answer.src, round((end - start) * 1000)))
            if answer.src == destination:
                if function_handler_last_packet(answer):
                    return routes
        elif try_count < 2:
            try_count += 1
            continue
        else:
            routes.append(Route('*', 0))

        ttl += 1
        try_count = 0

    return routes


if __name__ == '__main__':
    traceroute_arg_parse = TracerouteArgParse(sys.argv[1:])
    try:
        traceroute_args = traceroute_arg_parse.parse()
    except ValueError as e:
        print(str(e))
        sys.exit()

    result = None
    if traceroute_args.protocol == 'ICMP':
        result = start_traceroute(1, traceroute_args.n, traceroute_args.ip, traceroute_args.timeout,
                                  lambda ttl, destination: IP(ttl=ttl, dst=destination) / ICMP(),
                                  lambda answer: True
                                  )
    elif traceroute_args.protocol == 'UDP':
        result = start_traceroute(1, traceroute_args.n, traceroute_args.ip, traceroute_args.timeout,
                                  lambda ttl, destination: IP(ttl=ttl, dst=destination) / UDP(
                                      dport=traceroute_args.port),
                                  lambda answer: answer['ICMP'].type == 3 and answer['ICMP'].code == 3
                                  )
    elif traceroute_args.protocol == 'TCP':
        result = start_traceroute(1, traceroute_args.n, traceroute_args.ip, traceroute_args.timeout,
                                  lambda ttl, destination:
                                  IP(ttl=ttl, dst=destination) / TCP(flags='S', dport=traceroute_args.port),
                                  lambda answer: 'TCP' in answer and (
                                              answer['TCP'].flags == 'SA' or answer['TCP'].flags == 'R')
                                  )
    traceroute_table = PrettyTable()
    traceroute_table.set_style(PLAIN_COLUMNS)
    traceroute_table.field_names = ['NUM', 'IP', '[TIME,ms]']

    for i in range(len(result)):
        traceroute_table.add_row([i + 1, result[i].ip, result[i].time if result[i].time else ''])

    print(traceroute_table)
