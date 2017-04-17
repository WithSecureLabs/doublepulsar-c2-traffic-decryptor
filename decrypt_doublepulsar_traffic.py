import argparse
from itertools import cycle, izip

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket


# Arguments
parser = argparse.ArgumentParser(description="Decrypt DOUBLEPULSAR network traffic from PCAP file. Supply a PCAPNG format file with just one command run for best results. Tested with DLL injection command.\n\nAuthor: Luke Jennings\nWebsite: https://countercept.com\nTwitter: @countercept", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--pcapng', help='File name of PCAPNG format packet capture to process', required=True)
parser.add_argument('--output', help="File name to write decrypted output too", required=True)

args = parser.parse_args()
pcap_filename = args.pcapng
write_filename = args.output


def xor_decrypt(message, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(message, cycle(key)))


xor_key = None
with open(pcap_filename, 'rb') as read_fp, open(write_filename, 'wb') as write_fp:
    scanner = FileScanner(read_fp)
    for block in scanner:
        if isinstance(block, EnhancedPacket):

            # Check for SMB packet signature and reserved word plus SESSION_SETUP bytes
            if "\xffSMB" in block.packet_data and "\x00\x0e\x00" in block.packet_data:
                offset = block.packet_data.index("\x00\x0e\x00") + 6
                header = block.packet_data[offset:offset+12]
                data = block.packet_data[offset+12:]

                # Filter out blank ping packets
                if header != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00":
                    # Set XOR key based on NULL bytes revealing key in first header packet
                    if xor_key is None:
                        xor_key = header[8:12]

                    decrypted_data = xor_decrypt(data, xor_key)
                    write_fp.write(decrypted_data)

    write_fp.close()
