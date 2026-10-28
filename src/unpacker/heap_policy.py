"""Declared single-process heap policy, never host heap/security operations."""
class GuestHeapCorruption(RuntimeError):pass


class HeapPolicy:
    MAX_RECENT_FREES=128
    def __init__(self,model):self.model=model;self.enabled=False;self.recent_frees={}

    def set_information(self,uc,heap,information_class,information,length):
        if (heap,information_class,information,length)!=(0,1,0,0):
            self.model.reject('HeapSetInformation','Only process-wide terminate-on-corruption with NULL/zero payload is modeled')
        self.enabled=True  # Irreversible for this guest process, including future heaps.
        return 1

    def allocated(self,heap,address):self.recent_frees.pop((heap,address),None)

    def freed(self,heap,address):
        key=(heap,address);self.recent_frees.pop(key,None);self.recent_frees[key]=None
        while len(self.recent_frees)>self.MAX_RECENT_FREES:self.recent_frees.pop(next(iter(self.recent_frees)))

    def invalid_free(self,uc,heap,address):
        if not self.enabled:return
        if (heap,address) in self.recent_frees:
            self.model.exit(uc,0xc0000374)
            raise GuestHeapCorruption('Recorded guest heap double free: STATUS_HEAP_CORRUPTION')
        self.model.reject('HeapFree','Corruption-sensitive pointer provenance is outside the bounded guest heap model')

    def facts(self):
        return {'terminate_on_corruption':self.enabled,'irreversible':True,
          'detection':'recorded_double_frees_only','recent_free_limit':self.MAX_RECENT_FREES,
          'unknown_corruption_paths':'unsupported','full_windows_heap_metadata_lfh_wer':'not_modeled'}
