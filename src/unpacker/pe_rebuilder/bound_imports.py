"""Recover a declared PE32 import table whose lookup thunks were resolved.

The retained descriptors identify IAT locations. Symbols require unambiguous,
module-scoped observed bindings; neither byte-search order nor reference files
selects an IAT. All writes target a detached image after complete validation.
"""
import re
import struct
from types import SimpleNamespace as N
from unpacker.pe_rebuilder.imports import file_backed_data, c_string


def rebuild_bound_imports(uc, base, size, sections, observed, directory_rva):
    if not 0 < size <= 32 * 1024 * 1024:
        raise ValueError('Bound-import image budget exceeded')
    memory = bytes(uc.mem_read(base, size))
    if len(memory) != size:
        raise ValueError('Truncated bound-import image snapshot')
    mapped = []
    for section in sections:
        start = section.VirtualAddress
        length = max(section.VirtualSize, section.SizeOfRawData)
        if not length:
            continue
        if start < 4096 or start + length > size:
            raise ValueError('Invalid bound-import section range')
        mapped.append(N(VirtualAddress=start, Misc_VirtualSize=length, SizeOfRawData=length))
    spans = sorted((s.VirtualAddress, s.VirtualAddress + s.SizeOfRawData) for s in mapped)
    if not spans or any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError('Missing or overlapping bound-import sections')
    if type(directory_rva) is not int or directory_rva % 4 or directory_rva <= 0:
        raise ValueError('Invalid declared import directory')
    if len(observed) > 128:
        raise ValueError('Observed module budget exceeded')
    bindings = {}
    epochs = {}
    total_observed = 0
    for module, functions in observed.items():
        epoch=str(module);module=epoch.split('#')[0].lower();epoch_bindings=set()
        table = bindings.setdefault(module, {})
        for name, address in functions:
            total_observed += 1
            if total_observed > 4096 or type(address) is not int or not 0 < address < 2**32:
                raise ValueError('Invalid or excessive observed bindings')
            name = str(name)
            if '/' in name:
                ordinal = int(name.rsplit('/', 1)[-1])
                if not 0 < ordinal < 65536:
                    raise ValueError('Invalid observed ordinal')
                symbol = ordinal
            else:
                symbol = name.encode('ascii')
                if not 1 <= len(symbol) < 512 or any(c < 0x21 or c > 0x7e for c in symbol):
                    raise ValueError('Invalid observed symbol')
            table.setdefault(address, set()).add(symbol)
            epoch_bindings.add((address,symbol))
        epochs.setdefault(module,{})[epoch]=epoch_bindings
    pe = N(get_data=lambda rva, count: memory[rva:rva + count])
    read = lambda rva, count: file_backed_data(pe, rva, count, mapped)
    groups = []
    protected = []
    used_bindings = {}
    symbol_count = 0
    for index in range(129):
        descriptor_rva = directory_rva + index * 20
        raw = read(descriptor_rva, 20)
        protected.append((descriptor_rva, 20))
        if raw == bytes(20):
            break
        if index == 128:
            raise ValueError('Bound-import descriptor budget exceeded')
        lookup, timestamp, forwarder, name_rva, iat = struct.unpack('<IIIII', raw)
        if not iat or iat % 4 or (lookup and lookup % 4) or timestamp or forwarder:
            raise ValueError('Unsupported bound-import descriptor state')
        dll = c_string(pe, name_rva, mapped, 128)
        if not re.fullmatch(rb'[A-Za-z0-9_.-]+\.(?:dll|ocx|drv)', dll, re.I):
            raise ValueError('Invalid bound-import module')
        module = dll.decode('ascii').lower()
        if module not in bindings:
            raise ValueError('Retained module has no observed bindings')
        protected.append((name_rva, len(dll) + 1))
        symbols = []
        for slot in range(4097 - symbol_count):
            live = struct.unpack('<I', read(iat + slot * 4, 4))[0]
            other = struct.unpack('<I', read((lookup or iat) + slot * 4, 4))[0]
            if live != other:
                raise ValueError('Retained lookup and IAT bindings disagree')
            if live == 0:
                break
            if symbol_count + len(symbols) >= 4096:
                raise ValueError('Bound-import symbol budget exceeded')
            names = bindings[module].get(live, set())
            if len(names) != 1:
                raise ValueError('Missing or ambiguous observed import identity')
            symbol = next(iter(names))
            symbols.append(symbol)
            used_bindings.setdefault(module, set()).add((live, symbol))
        else:
            raise ValueError('Unterminated bound-import thunks')
        if not symbols:
            raise ValueError('Empty bound-import descriptor')
        symbol_count += len(symbols)
        width = 4 * (len(symbols) + 1)
        protected.extend([(iat, width), (lookup or iat, width)])
        groups.append({'dll': dll, 'module': module, 'iat': iat, 'lookup': lookup or iat, 'symbols': symbols})
    if not groups:
        raise ValueError('Empty declared bound-import directory')
    matched_epochs={}
    for module, used in used_bindings.items():
        expected = {(address, symbol) for address, names in bindings[module].items() for symbol in names}
        matches=[epoch for epoch,values in epochs[module].items() if values==used]
        if used != expected and not matches:
            raise ValueError('Declared table omits observed module bindings')
        matched_epochs[module]=matches
    arrays = sorted((g['iat'], g['iat'] + 4 * (len(g['symbols']) + 1)) for g in groups)
    if any(a[1] > b[0] for a, b in zip(arrays, arrays[1:])):
        raise ValueError('Declared IAT arrays overlap')
    # A directory, name, or distinct lookup array must not alias a patched IAT.
    for group in groups:
        start, end = group['iat'], group['iat'] + 4 * (len(group['symbols']) + 1)
        if any(lo < end and start < lo + length for lo, length in protected
               if (lo, length) != (start, end - start)):
            raise ValueError('Declared IAT overlaps retained metadata')
    payload = bytearray((len(groups) + 1) * 20)
    def reserve(data, alignment=1):
        payload.extend(bytes((-len(payload)) % alignment))
        offset = len(payload)
        if offset + len(data) > 65536:
            raise ValueError('Bound-import metadata budget exceeded')
        payload.extend(data)
        return offset
    for group in groups:
        group['name_offset'] = reserve(group['dll'] + b'\0')
        group['lookup_offset'] = reserve(bytes(4 * (len(group['symbols']) + 1)), 4)
        group['values'] = [symbol | 0x80000000 if type(symbol) is int
                           else reserve(b'\0\0' + symbol + b'\0', 2) for symbol in group['symbols']]
    after_sections = (spans[-1][1] + 4095) & ~4095
    workspace = next((rva for rva in range(after_sections, size - len(payload) + 1, 4096)
                      if not any(memory[rva:rva + len(payload)])), None)
    if workspace is None:
        raise ValueError('No zeroed non-image bound-import workspace')
    patches = []
    for index, group in enumerate(groups):
        values = [value if value & 0x80000000 else workspace + value for value in group['values']]
        array = struct.pack('<' + 'I' * (len(values) + 1), *values, 0)
        offset = group['lookup_offset']
        payload[offset:offset + len(array)] = array
        struct.pack_into('<IIIII', payload, index * 20, workspace + offset, 0, 0,
                         workspace + group['name_offset'], group['iat'])
        patches.append((base + group['iat'], array))
    for address, data in [(base + workspace, bytes(payload)), *patches]:
        uc.mem_write(address, data)
    return {'rva': workspace, 'descriptor_bytes': (len(groups) + 1) * 20,
            'modules': len(groups), 'symbols': symbol_count,
            'method': 'declared_descriptor_observed_bindings',
            'source_directory_rva': directory_rva, 'metadata_bytes': len(payload),
            'iat_rvas': [g['iat'] for g in groups],
            'matched_observation_epochs':matched_epochs,
            'unrepresented_observed_epochs':sorted(epoch for module,rows in epochs.items() for epoch in rows
                if module not in used_bindings or (matched_epochs[module] and epoch not in matched_epochs[module])),
            'unrepresented_observed_modules': sorted(set(bindings) - set(used_bindings))}
