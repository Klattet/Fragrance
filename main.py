"""

Fragrance: A simple-to-use network interface sniffer.

Uses the libpcap library to record network packets on the network.
Very handy for monitoring and detecting security breaches on your computer or home network.

"""

from argparse import ArgumentParser, Namespace

from pyshark.packet import packet


from lib import *

def main():
    parser: ArgumentParser = ArgumentParser(
        prog = "Fragrance"
    )
    parser.add_argument("-i", "--interface", type = str, default = None, nargs = "?")
    parser.add_argument("-m", "--monitor", action = "store_true")
    parser.add_argument("-c", "--count", type = int, default = 0, nargs = "?")
    parser.add_argument("-t", "--timeout", type = float, default = 0.0, nargs = "?")

    args: Namespace = parser.parse_args()

    with Sniffer(**args.__dict__) as sniffer:
        for pack in sniffer:
            print(pack)

if __name__ == '__main__':
    main()
