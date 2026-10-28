"""Recover zeroed import names only from unambiguous observed guest IAT bindings.

This recognizes a retained PE32 descriptor/lookup skeleton. It does not search
external libraries, consult a reference file, or guess unresolved functions.
"""
import re
import struct
from types import SimpleNamespace as N

from unpacker.pe_rebuilder.imports import c_string, file_backed_data, retained_import_table


def find_erased_import_names(memory, sections, observed, max_scan_bytes=1048576):
    bindings = {}
    for module, functions in observed.items():
        dll = str(module).split('#')[0].lower()
        for name, address in functions:
            symbol = str(name)
            if '/' in symbol:
                try:
                    symbol = '#' + str(int(symbol.rsplit('/', 1)[-1]))
                except ValueError:
                    return None
            bindings.setdefault((dll, address), set()).add(symbol)
    if not bindings:
        return None
    mapped = [N(VirtualAddress=s.VirtualAddress,
                Misc_VirtualSize=max(s.VirtualSize, s.SizeOfRawData),
                SizeOfRawData=max(s.VirtualSize, s.SizeOfRawData)) for s in sections]
    pe = N(OPTIONAL_HEADER=N(Magic=0x10b), FILE_HEADER=N(Machine=0x14c),
           get_data=lambda rva, size: memory[rva:rva+size])
    matches = []
    for offset in range(0, min(len(memory)-19, max_scan_bytes), 4):
        lookup, stamp, forwarder, name, iat = struct.unpack_from('<IIIII', memory, offset)
        if not 0 < lookup < len(memory) or not 0 < iat < len(memory) or not 0 < name < len(memory):
            continue
        module = memory[name:min(name+128, len(memory))].split(b'\0', 1)[0]
        if not re.fullmatch(rb'[A-Za-z0-9_.-]+\.(?:dll|ocx|drv)', module, re.I):
            continue
        patches = []
        protected = []
        names = []
        total = 0
        try:
            for index in range(129):
                raw = file_backed_data(pe, offset+index*20, 20, mapped)
                protected.append((offset+index*20, 20))
                if raw == bytes(20):
                    if not index or not patches:
                        raise ValueError('No erased names in retained table')
                    break
                if index == 128:
                    raise ValueError('Descriptor budget exceeded')
                lookup, stamp, forwarder, name, iat = struct.unpack('<IIIII', raw)
                if not lookup or not iat:
                    raise ValueError('Separate retained lookup and IAT required')
                dll = c_string(pe, name, mapped, 128)
                if not re.fullmatch(rb'[A-Za-z0-9_.-]+\.(?:dll|ocx|drv)', dll, re.I):
                    raise ValueError('Invalid module')
                protected.append((name, len(dll)+1))
                for position in range(4097-total):
                    value = struct.unpack('<I', file_backed_data(pe, lookup+position*4, 4, mapped))[0]
                    live = struct.unpack('<I', file_backed_data(pe, iat+position*4, 4, mapped))[0]
                    protected.extend([(lookup+position*4, 4), (iat+position*4, 4)])
                    if value == 0:
                        if live or not position:
                            raise ValueError('Invalid IAT termination')
                        break
                    if total >= 4096:
                        raise ValueError('Symbol budget exceeded')
                    symbols = bindings.get((dll.decode('ascii').lower(), live), set())
                    if len(symbols) != 1:
                        raise ValueError('Missing or ambiguous observed IAT binding')
                    symbol = next(iter(symbols))
                    if value & 0x80000000:
                        if value & 0x7fff0000 or symbol != '#'+str(value & 0xffff) or not value & 0xffff:
                            raise ValueError('Ordinal does not match observation')
                    else:
                        encoded = symbol.encode('ascii')
                        if symbol.startswith('#') or not 1 <= len(encoded) < 512 or any(c < 0x21 or c > 0x7e for c in encoded):
                            raise ValueError('Invalid observed import name')
                        existing = file_backed_data(pe, value, len(encoded)+3, mapped)
                        if existing[2:] == bytes(len(encoded)+1):
                            patches.append((value+2, encoded+b'\0'))
                        elif existing[2:] != encoded+b'\0':
                            raise ValueError('Name is neither corroborated nor fully erased')
                        names.append((value, len(encoded)+3))
                    total += 1
                else:
                    raise ValueError('Unterminated lookup')
            # Name writes must not alias descriptors, thunks, modules or each
            # other. Avoid silently converting instructions or control data.
            if any(start < other+length and other < start+size
                   for start, size in names for other, length in protected):
                raise ValueError('Import names overlap control data')
            ordered = sorted(set(names))
            if any(a+size > b for (a, size), (b, _) in zip(ordered, ordered[1:])):
                raise ValueError('Overlapping import names')
            unique_patches = {}
            for start, payload in patches:
                if start in unique_patches and unique_patches[start] != payload:
                    raise ValueError('Conflicting shared import names')
                unique_patches[start] = payload
            patches = sorted(unique_patches.items())
            repaired = bytearray(memory)
            for start, payload in patches:
                repaired[start:start+len(payload)] = payload
            strict = N(OPTIONAL_HEADER=pe.OPTIONAL_HEADER, FILE_HEADER=pe.FILE_HEADER,
                       get_data=lambda rva, size: repaired[rva:rva+size])
            table = retained_import_table(strict, offset, mapped)
            table['name_patches'] = patches
            matches.append(table)
            if len(matches) > 128:
                return None
        except (ValueError, UnicodeError, struct.error):
            continue
    if not matches:
        return None
    # Parseable suffixes are not independent evidence. Prefer one unique
    # maximal table, with every retained IAT binding corroborated above.
    largest = max(table['symbol_count'] for table in matches)
    matches = [table for table in matches if table['symbol_count'] == largest]
    return matches[0] if len(matches) == 1 else None
