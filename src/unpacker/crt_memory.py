"""Bounded PE32 CRT allocations in guest memory; never host malloc pointers."""


class CRTMemory:
    def __init__(self, model):
        self.model = model
        self.allocations = {}

    def _failure(self, uc):
        if self.model.crt_startup.newmode:
            self.model.reject('malloc', 'CRT new-handler allocation failure is not modeled')
        import struct
        cell = self.model.crt_cell(uc, 'errno', 0)
        uc.mem_write(cell, struct.pack('<I', 12))  # ENOMEM, guest CRT state only.
        return 0

    def malloc(self, uc, size):
        # Reserve errno before the requested allocation can exhaust the quota.
        self.model.crt_cell(uc, 'errno', 0)
        allocated = (max(1, size)+4095) & ~4095
        used = sum(self.model.globals.values())+sum(v[0] for v in self.model.views.values())
        if size > self.model.limit or used+allocated > max(4096, self.model.limit):
            return self._failure(uc)
        address = self.model.global_alloc(uc, 0, max(1, size))
        self.allocations[address] = size
        return address

    def free(self, uc, address):
        if address:
            if address not in self.allocations:
                self.model.reject('free', 'Pointer is not owned by the guest CRT')
            self.model.global_free(uc, address)
            del self.allocations[address]
        return None

    def calloc(self, uc, count, size):
        total = count*size
        if total > 0xffffffff:
            return self._failure(uc)
        address = self.malloc(uc, total)
        if address and total:
            uc.mem_write(address, bytes(total))
        return address

    def realloc(self, uc, address, size):
        if not address:
            return self.malloc(uc, size)
        if address not in self.allocations:
            self.model.reject('realloc', 'Pointer is not owned by the guest CRT')
        if not size:
            self.free(uc, address)
            return 0
        if size <= self.model.globals[address]:
            self.allocations[address] = size
            return address
        new = self.malloc(uc, size)
        if not new:
            return 0  # The old allocation stays valid on failure.
        old_size = self.allocations[address]
        uc.mem_write(new, bytes(uc.mem_read(address, min(old_size, size))))
        self.free(uc, address)
        return new
