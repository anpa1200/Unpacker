"""Guest-only MSVCRT PE32 startup state for the declared C locale/profile."""
import struct


class CRTStartup:
    def __init__(self, model):
        self.model = model
        self.locale_address = None
        self.locale_initialized = False
        self.arguments = None
        self.newmode = 0
        self.exit_callbacks = []

    def register_exit(self, uc, address):
        if len(self.exit_callbacks) >= 1024:
            return 0
        if not address or not any(lo <= address <= hi and permissions & 4 for lo, hi, permissions in uc.mem_regions()):
            self.model.reject('_onexit', 'Callback is not mapped executable guest memory')
        self.exit_callbacks.append(address)
        return address

    def localeconv(self, uc):
        if self.locale_address is None:
            # Legacy MSVCRT: ten char pointers and eight unsigned char fields.
            # A single owned allocation also stores the two immutable strings.
            base = self.model.global_alloc(uc, 0x40, 51)
            pointers = [base+48] + [base+50]*9
            uc.mem_write(base, struct.pack('<10I', *pointers))
            uc.mem_write(base+40, bytes([255 if self.locale_initialized else 127])*8)
            uc.mem_write(base+48, b'.\0\0')
            self.locale_address = base
        return self.locale_address

    def initialize_locale(self, uc):
        self.locale_initialized = True
        address = self.localeconv(uc)
        uc.mem_write(address+40, bytes([255])*8)
        return 0

    def getmainargs(self, uc, argc, argv, environ, expand_wildcards, startup):
        if not argc or not argv or not environ or not startup or expand_wildcards not in {0, 1}:
            self.model.reject('__getmainargs', 'Invalid guest pointers or wildcard mode')
        newmode = struct.unpack('<I', uc.mem_read(startup, 4))[0]
        if newmode not in {0, 1}:
            self.model.reject('__getmainargs', 'Unsupported startup allocation mode')
        if self.arguments is None:
            # The fixed virtual command line has one argument and no wildcard.
            # Its argv and environment have stable, writable, guest-owned cells.
            vector = self.model.global_alloc(uc, 0x40, 12)
            uc.mem_write(vector, struct.pack('<III', self.model.command_line(uc, False), 0, 0))
            self.arguments = (vector, vector+8)
            cell=self.model.crt_cells.get('initenv')
            if cell:uc.mem_write(cell,struct.pack('<I',vector+8))
        self.newmode = newmode
        uc.mem_write(argc, struct.pack('<I', 1))
        uc.mem_write(argv, struct.pack('<I', self.arguments[0]))
        uc.mem_write(environ, struct.pack('<I', self.arguments[1]))
        return 0
