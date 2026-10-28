"""Bounded PE32 CRT calls scheduled through the existing guest CPU loop.

No nested emu_start, native callback, or host library is involved. A private
return thunk continues the table walk after each ordinary guest function returns.
"""
import struct
from dataclasses import dataclass


@dataclass
class Initializers:
    esp: int
    cursor: int
    end: int
    checked: bool
    awaiting_return: bool = False


class GuestCallbacks:
    MAX_TABLE_BYTES = 16384
    MAX_DEPTH = 16
    MAX_CALLS = 4096
    RETURN_NAME = '<unpacker:crt-return>'

    def __init__(self, model):
        self.model = model
        self.frames = []
        self.address = None
        self.calls = 0
        self.completed = 0

    def _reject(self, reason):
        self.model.reject('_initterm', reason)

    def _thunk(self, uc):
        if self.address is None:
            regions = list(uc.mem_regions())
            for address in range(0x7f000000, 0x7f100000, 4096):
                if not any(lo < address + 4096 and address <= hi for lo, hi, _ in regions):
                    uc.mem_map(address, 4096, 5)
                    # The backend's API stubs load the return value from HOOK_ADDR.
                    uc.mem_write(address, b'\x8b\x04\x25' + struct.pack('<I', self.model.engine.HOOK_ADDR) + b'\xc3')
                    self.address = address
                    self.model.handler.hooks[address] = self.RETURN_NAME
                    break
            else:
                self._reject('No free bounded guest callback thunk page')
        return self.address

    def start(self, uc, esp, begin, end, checked=False):
        if begin % 4 or end % 4 or end < begin or end - begin > self.MAX_TABLE_BYTES:
            self._reject('Invalid initializer-table bounds')
        if len(self.frames) >= self.MAX_DEPTH:
            self._reject('Guest callback nesting budget exceeded')
        self.frames.append(Initializers(esp, begin, end, checked))
        return self._advance(uc)

    def resume(self, uc, esp, result):
        if not self.frames or not self.frames[-1].awaiting_return or self.frames[-1].esp != esp:
            self._reject('Guest callback returned with an invalid stack')
        frame = self.frames[-1]
        frame.awaiting_return = False
        if frame.checked and result:
            self.frames.pop()
            self.completed += 1
            return result, esp
        return self._advance(uc)

    def _advance(self, uc):
        frame = self.frames[-1]
        while frame.cursor < frame.end:
            raw = uc.mem_read(frame.cursor, 4)
            if len(raw) != 4:
                self._reject('Truncated initializer-table entry')
            callback = struct.unpack('<I', raw)[0]
            frame.cursor += 4
            if not callback:
                continue
            if self.calls >= self.MAX_CALLS:
                self._reject('Aggregate guest callback budget exceeded')
            if callback == self.address or not any(lo <= callback <= hi and permissions & 4 for lo, hi, permissions in uc.mem_regions()):
                self._reject('Initializer target is not mapped executable guest memory')
            if frame.esp < 8:
                self._reject('Invalid guest callback stack bounds')
            continuation = self._thunk(uc)
            # The current API stub RET consumes callback, then the callback RET
            # consumes continuation. Original cdecl arguments/return stay intact.
            uc.mem_write(frame.esp - 8, struct.pack('<II', callback, continuation))
            frame.awaiting_return = True
            self.calls += 1
            return None, frame.esp - 8
        self.frames.pop()
        self.completed += 1
        return (0 if frame.checked else None), frame.esp
