import argparse
from dataclasses import dataclass


@dataclass
class _DataArgs:
    ip: str
    protocol: str
    timeout: float
    port: int
    n: int


class TracerouteArgParse:
    """Console parser for traceroute"""

    def __init__(self, args):
        self.parser = argparse.ArgumentParser(description='This is traceroute.\n')
        self.args = args
        self._add_options()

    def _add_options(self):
        self.parser.add_argument('ip', type=str,
                                 help='IP address')

        self.parser.add_argument('protocol', type=str,
                                 help='ICMP, UDP or TCP protocol')

        self.parser.add_argument('-t', type=float, default=2.0,
                                 help='Timeout waiting for a response')

        self.parser.add_argument('-p', type=int, default=-1,
                                 help='Port for tcp or udp')

        self.parser.add_argument('-n', type=int, default=30,
                                 help='Maximum number of requests')

    def _is_correct_ip(self, ip: str):
        """
        Checking to correct ip
        :param ip: IP address
        """
        numbers = ip.split('.')
        if len(numbers) != 4:
            return False

        for number in numbers:
            if not (0 <= int(number) <= 255 and number):
                raise False

        return True

    def parse(self) -> _DataArgs:
        """
        Parsing console arguments
        :return: DataArgs
        """
        parameters = self.parser.parse_args(self.args)
        port = 0
        if not self._is_correct_ip(parameters.ip):
            raise ValueError(
                f'IP address {parameters.ip} not correct. IP address should be is written as four decimal numbers '
                'with a value from 0 to 255, separated by dots.'
            )

        if parameters.protocol.upper() not in ['UDP', 'TCP', 'ICMP']:
            raise ValueError(f'Protocol {parameters.protocol} not UDP, TCP or ICMP')
        if parameters.protocol.upper() == 'TCP' and parameters.p == -1:
            port = 80
        elif parameters.protocol.upper() == 'UDP' and parameters.p == -1:
            port = 33434
        elif parameters.protocol.upper() == 'ICMP':
            if parameters.p > -1:
                raise ValueError('ICMP protocol cannot have port')

        if not port:
            if not (0 < parameters.p < 65536):
                raise ValueError('Port should be less 65536 and more 0')

        return _DataArgs(parameters.ip, parameters.protocol.upper(), parameters.t, port if port else parameters.p,
                         parameters.n)
