"""Bounded guest byte/string primitives; no host addresses or library calls."""


class CRTBuffers:
    def __init__(self, model):
        self.model = model

    def _size(self, name, size):
        if not 0 <= size <= self.model.limit:
            self.model.reject(name, 'Guest buffer exceeds model budget')

    def string(self, uc, address, bound=None):
        limit = min(self.model.limit, 1048576) if bound is None else bound
        self._size('string', limit)
        data = bytearray()
        while len(data) < limit:
            position = address+len(data)
            # Read only to a page boundary: a terminator on the last mapped
            # page must not require speculative reads from the following page.
            count = min(limit-len(data), 4096-position % 4096)
            block = bytes(uc.mem_read(position, count))
            if len(block) != count:
                self.model.reject('string', 'Truncated guest string memory')
            end = block.find(b'\0')
            if end >= 0:
                return bytes(data)+block[:end]
            data.extend(block)
        if bound is not None:
            return bytes(data)
        self.model.reject('strlen', 'Unterminated guest string exceeds model budget')

    def strlen(self, uc, address):
        return len(self.string(uc, address))

    def copy(self, uc, destination, source, size, overlap=False):
        self._size('memmove' if overlap else 'memcpy', size)
        if not overlap and size and destination < source+size and source < destination+size:
            self.model.reject('memcpy', 'Overlapping guest buffers are undefined')
        if size:
            data = bytes(uc.mem_read(source, size))
            if len(data) != size:
                self.model.reject('memcpy', 'Truncated source memory')
            uc.mem_write(destination, data)
        return destination

    def memset(self, uc, destination, value, size):
        self._size('memset', size)
        if size:
            uc.mem_write(destination, bytes([value & 255])*size)
        return destination

    def compare(self, left, right):
        return 0 if left == right else (1 if left > right else 0xffffffff)

    def memcmp(self, uc, left, right, size):
        self._size('memcmp', size)
        if not size:
            return 0
        a, b = bytes(uc.mem_read(left, size)), bytes(uc.mem_read(right, size))
        if len(a) != size or len(b) != size:
            self.model.reject('memcmp', 'Truncated comparison memory')
        return self.compare(a, b)

    def strcmp(self, uc, left, right):
        return self.compare(self.string(uc, left), self.string(uc, right))

    def strcpy(self, uc, destination, source):
        data = self.string(uc, source)+b'\0'
        return self.copy(uc, destination, source, len(data))

    def lstrcat_a(self, uc, destination, source):
        """Append ANSI bytes in guest memory, preserving Win32 NULL failure.

        All memory reads and writes address the guest. Overlapping buffers and
        operations beyond the model budget stop explicitly; neither gets an
        invented success result. A guest access fault returns NULL as specified
        for lstrcatA, without claiming the destination remains terminated.
        """
        from unicorn import UcError
        if not destination or not source:
            return 0
        try:
            left, right = self.string(uc, destination), self.string(uc, source)
            total = len(left)+len(right)+1
            self._size('lstrcatA', total)
            if destination+total > 2**32 or source+len(right)+1 > 2**32:
                self.model.reject('lstrcatA', 'Guest string address exceeds PE32 range')
            if destination < source+len(right)+1 and source < destination+total:
                self.model.reject('lstrcatA', 'Overlapping guest strings are unsupported')
            uc.mem_write(destination+len(left), right+b'\0')
        except UcError:
            return 0
        return destination

    def strncpy(self, uc, destination, source, size):
        self._size('strncpy', size)
        if size and destination < source+size and source < destination+size:
            self.model.reject('strncpy', 'Overlapping guest buffers are undefined')
        if size:
            data = self.string(uc, source, size)
            uc.mem_write(destination, data+bytes(size-len(data)))
        return destination
