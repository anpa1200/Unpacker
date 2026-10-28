"""Mapped HMODULE identities for the explicitly modeled guest loader list.

No host library is loaded. Abstract import tokens cannot stand in for a mapped
HMODULE; general LoadLibrary, unloading and concurrency are outside this profile.
"""
import ntpath


class GuestModules:
    def __init__(self,model):self.model=model;self.resolved_queries=0;self.resolutions=[]

    def lookup(self,uc,pointer):
        if not pointer:return None
        value=self.model.string(uc,pointer,operation='GetModuleHandleA')
        try:name=value.decode('ascii').lower()
        except UnicodeDecodeError:return None
        if '/' in name:return None
        basename=ntpath.basename(name)
        if '.' not in basename:name+='.dll'
        qualified=bool(ntpath.dirname(name))
        table=getattr(self.model.engine,'_unpacker_loader_lists',{}).get('module_images',[])
        matches=[row for row in table if name==(row['full_name'] if qualified else row['name']).lower()]
        if len(matches)>1:self.model.reject('GetModuleHandleA','Ambiguous loaded guest module identity')
        return matches[0] if matches else None

    def handle(self,uc,pointer):
        row=self.lookup(uc,pointer)
        if row is None:return self.unmapped(uc,pointer)
        base=row['base']
        if not any(lo<=base and base+63<=hi and flags&1 for lo,hi,flags in uc.mem_regions()):
            self.model.reject('GetModuleHandleA','Recorded guest module is no longer mapped readable')
        self.bind(row)
        if len(self.model.events)<32:
            self.model.events.append({'operation':'GetModuleHandleA','name':row['name'],'base':base,
                                      'source':'validated_loaded_guest_image','reference_count_change':False})
        self.resolved_queries+=1
        if len(self.resolutions)<16:self.resolutions.append({'name':row['name'],'base':base})
        return base

    def bind(self,row):
        if row not in getattr(self.model.engine,'_unpacker_loader_lists',{}).get('module_images',[]):
            self.model.reject('GuestModule','Module identity was not validated in loader metadata')
        base=row['base']
        if base!=self.model.engine.sample.BASE_ADDR:
            handler=self.model.handler;sample=self.model.engine.sample
            handles=getattr(handler,'module_handles',None);counters=getattr(handler,'load_library_counter',None)
            groups=getattr(sample,'dllname_to_functionlist',None)
            if not all(isinstance(x,dict) for x in [handles,counters,groups]):
                self.model.reject('GetModuleHandleA','Backend module tracking is unavailable')
            canonical=row['name'].lower()
            if base in handles and handles[base].lower()!=canonical:
                self.model.reject('GetModuleHandleA','Mapped guest base collides with a different backend module')
            aliases=[name for name in counters if name.lower()==canonical]
            key=aliases[0] if aliases else canonical
            # The pinned backend counter selects an observed lookup sequence;
            # it is not an OS loader reference count. A fresh query can start
            # another IAT sequence for the same stable HMODULE. Combining two
            # such sequences makes its contiguous-IAT finder omit a real table.
            index=counters.get(key,0)
            if groups.get(key+'#'+str(index)):
                index+=1
                if key+'#'+str(index) in groups:
                    self.model.reject('GetModuleHandleA','Backend symbol sequence index collides')
            counters[key]=index;handles[base]=key
            groups.setdefault(key+'#'+str(index),[])
        return base

    def unmapped(self,uc,pointer):
        raw=self.model.string(uc,pointer,operation='GetModuleHandleA')
        try:name=ntpath.basename(raw.decode('ascii').lower())
        except UnicodeDecodeError:name=''
        if name and '.' not in name:name+='.dll'
        mapped={row['name'].lower() for row in getattr(self.model.engine,'_unpacker_loader_lists',{}).get('module_images',[])}
        handler=self.model.handler
        handles=getattr(handler,'module_handles',{});counters=getattr(handler,'load_library_counter',{})
        if len(handles)>128 or len(counters)>128:
            self.model.reject('GetModuleHandleA','Backend module identity budget exceeded')
        labels={ntpath.basename(str(value).lower()) for value in [*handles.values(),*counters]}
        labels={value if '.' in value else value+'.dll' for value in labels}
        if name and name not in mapped and name in labels:
            self.model.reject('GetModuleHandleA',f'Guest module {name} has abstract import tracking but no mapped PE image; real HMODULE base unavailable')
        self.model.last_error=126  # ERROR_MOD_NOT_FOUND: no loaded profile image matches.
        if len(self.model.events)<32:
            self.model.events.append({'operation':'GetModuleHandleA','result':'module_not_found','name':name[:128]})
        return 0

    def facts(self):
        return {'scope':'already_mapped_guest_images','resolved_queries':self.resolved_queries,
                'resolutions':list(self.resolutions),'reference_count_change':False,
                'other_modules':'unmapped_abstract_modules_rejected; unknown_modules_return_null'}
