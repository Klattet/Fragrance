"""

Fragrance: A simple-to-use network interface sniffer.

Uses the libpcap library to record network packets on the network.
Very handy for monitoring and detecting security breaches on your computer or home network.

"""

from argparse import ArgumentParser, Namespace

from cypcap import findalldevs


from lib import *

def main():
    parser: ArgumentParser = ArgumentParser(
        prog = "Fragrance"
    )
    parser.add_argument("device", type = str)
    parser.add_argument("-d", "--devices", action = "store_true")
    parser.add_argument("-p", "--promiscuous", action = "store_true")
    parser.add_argument("-m", "--monitor", action = "store_true")
    parser.add_argument("-c", "--count", type = int, default = 0, nargs = "?")
    parser.add_argument("-t", "--timeout", type = float, default = 0.0, nargs = "?")

    device_names: list[str] = [device.name for device in findalldevs()]
    if parser.parse_args(("devices",)).devices:
        print("Devices:", ", ".join(device_names))

    args: Namespace = parser.parse_args()
    args.__dict__.pop("devices")

    if args.device not in device_names:
        raise ValueError(f"{args.device} is not a valid device interface name.")

    with Sniffer(**args.__dict__) as sniffer:

        #print([DatalinkType(t) for t in sniffer.datalink_types()])

        for header, data in sniffer:

            try:
                frame = Frame.from_bytes(data)
                print(frame)
                print()

            except ValueError:
                pass

if __name__ == '__main__':
    main()
