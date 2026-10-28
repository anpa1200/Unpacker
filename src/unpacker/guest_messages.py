"""Bounded registered-message names inside one isolated emulated guest session.

No host atom table, window, IPC endpoint or native library is accessed.
The supported name profile is explicitly ASCII for both ANSI and UTF-16 calls.
"""
import hashlib


class RegisteredMessages:
    MAX_NAMES = 1024
    MAX_CHARACTERS = 255

    def __init__(self, model):
        self.model = model
        self.names = {}

    def register(self, uc, address, wide=False):
        api = 'RegisterWindowMessageW' if wide else 'RegisterWindowMessageA'
        if not address:
            self.model.reject(api, 'Null registered-message name is outside the supported profile')
        name = bytearray()
        width = 2 if wide else 1
        for index in range(self.MAX_CHARACTERS + 1):
            try:
                part = bytes(uc.mem_read(address + index * width, width))
            except Exception:
                self.model.reject(api, 'Registered-message name is not readable guest memory')
            if len(part) != width:
                self.model.reject(api, 'Truncated registered-message name')
            if part == bytes(width):
                break
            if part[0] > 127 or wide and part[1]:
                self.model.reject(api, 'Only ASCII registered-message names are modeled')
            name.append(part[0])
        else:
            self.model.reject(api, 'Registered-message name exceeds 255 characters')
        if not name:
            self.model.reject(api, 'Empty registered-message name is outside the supported profile')
        key = bytes(name).lower()
        if key.startswith(b'#') and key[1:].isdigit():
            self.model.reject(api, 'Integer-atom spelling is not modeled for registered messages')
        if key not in self.names:
            if len(self.names) >= self.MAX_NAMES:
                self.model.reject(api, 'Guest registered-message name budget exceeded')
            self.names[key] = 0xc000 + len(self.names)
        identifier = self.names[key]
        if len(self.model.events) < 32:
            self.model.events.append({'operation': api, 'message_id': identifier,
                'name_sha256': hashlib.sha256(key).hexdigest(), 'scope': 'isolated_guest_session'})
        return identifier
