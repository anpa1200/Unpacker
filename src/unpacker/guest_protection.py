"""Private guest-page VirtualProtect profile, enforced by Unicorn.

No host protection calls. Initial Unicorn mappings and tracked later allocations
are the modeled reservations. This does not add Windows reserve/commit, shared
mapping copy-on-write, guard-page or cache semantics to Unipacker's allocator.
"""
import struct


class GuestProtection:
    # Unicorn permissions: read=1, write=2, execute=4.
    PERMISSIONS = {1: 0, 2: 1, 4: 3, 0x10: 4, 0x20: 5, 0x40: 7}
    WINDOWS = {value: key for key, value in PERMISSIONS.items()}
    PAGE = 4096

    def __init__(self, model):
        self.model = model
        uc = getattr(model.engine, "uc", None)
        self.initial_reservations = [(lo, hi + 1) for lo, hi, _ in uc.mem_regions()] if uc is not None else []
        self.calls = 0
        self.return_state = None
        self.pending = None

    @staticmethod
    def _cover(regions, address, end, permission=0):
        cursor = address
        for lo, hi, permissions in sorted(regions):
            if hi < cursor: continue
            if lo > cursor or permissions & permission != permission: return False
            cursor = min(end, hi + 1)
            if cursor == end: return True
        return False

    def protect(self, uc, address, size, protection, old_pointer):
        model = self.model
        if protection not in self.PERMISSIONS:
            model.reject("VirtualProtect", "Protection modifiers or copy-on-write semantics are outside the private guest-page profile")
        if not size or address + size > 0x100000000 or not 0 <= address < 0x100000000 or size < 0:
            model.last_error = 87
            return 0
        if size > model.limit:
            model.reject("VirtualProtect", "Protection span exceeds guest memory budget")
        start = address & -self.PAGE
        end = (address + size + self.PAGE - 1) & -self.PAGE
        reservations = self.initial_reservations + [(lo, lo + length) for lo, length in model.handler.alloc_sizes.items()]
        if not any(lo <= start and end <= hi for lo, hi in reservations):
            model.last_error = 487
            return 0
        regions = list(uc.mem_regions())
        if not self._cover(regions, start, end):
            model.last_error = 487
            return 0
        if not old_pointer or old_pointer + 4 > 0x100000000 or not self._cover(regions, old_pointer, old_pointer + 4, 2):
            model.last_error = 998
            return 0
        previous = next(permissions for lo, hi, permissions in regions if lo <= start <= hi)
        if previous not in self.WINDOWS:
            model.reject("VirtualProtect", "Existing guest-page permissions have no supported Windows protection value")
        plan = (start, end, protection, old_pointer, self.WINDOWS[previous])
        if self.return_state is not None:
            if self.pending is not None:
                model.reject("VirtualProtect", "Nested deferred protection transition")
            self.pending = (plan, self.return_state)
            # mem_protect inside a Unicorn code hook can invalidate/re-enter the
            # current API block after stdcall stack cleanup. Apply it only after
            # emu_start returns, then resume at the caller with one completed call.
            uc.emu_stop()
            return 1
        return self._apply(uc, plan)

    def _apply(self, uc, plan):
        start, end, protection, old_pointer, previous = plan
        model = self.model
        old_bytes = bytes(uc.mem_read(old_pointer, 4))
        try:
            # Write through the old valid mapping before making it read-only.
            uc.mem_write(old_pointer, struct.pack("<I", previous))
            uc.mem_protect(start, end - start, self.PERMISSIONS[protection])
        except Exception:
            # Any unexpected emulator error stops this attempt. It cannot report
            # success after an incomplete state transition.
            try: uc.mem_write(old_pointer, old_bytes)
            except Exception: pass
            model.reject("VirtualProtect", "Emulator could not apply the validated guest protection transition")
        self.calls += 1
        # Unipacker's section dump exposes one tuple per section. Update from
        # that section's first actual page rather than an overlapping last page.
        current = list(uc.mem_regions())
        for (lo, _), name in getattr(model.handler, "atn", {}).items():
            if start <= lo < end:
                flags = next((p for first, last, p in current if first <= lo <= last), None)
                if flags is not None:
                    model.handler.ntp[name] = (bool(flags & 4), bool(flags & 1), bool(flags & 2))
        if len(model.events) < 32:
            model.events.append(dict(operation="VirtualProtect", pages=(end-start)//self.PAGE,
                                     previous=previous, protection=protection))
        return 1

    def take_resume(self, uc):
        if self.pending is None:
            return None
        plan, (address, stack_after_return) = self.pending
        self.pending = None
        self._apply(uc, plan)
        from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_EIP
        uc.reg_write(UC_X86_REG_EAX, 1)
        uc.reg_write(UC_X86_REG_ESP, stack_after_return)
        uc.reg_write(UC_X86_REG_EIP, address)
        return address

    def metadata(self):
        return dict(scope="private_committed_guest_pages", transitions=self.calls,
                    enforced_by="unicorn", initial_permissions="backend_mappings",
                    reserve_commit="not_modeled", guard_pages="not_implemented",
                    shared_copy_on_write="not_implemented")
