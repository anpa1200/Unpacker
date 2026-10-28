"""Resident PE export views for a declared, bounded named-API guest profile.

Only metadata and emulator dispatch thunks are mapped. No native DLL code,
initializers, TLS or host loader is used. Unknown API execution fails closed.
"""
import ntpath
import struct
from unpacker.desktop_catalog import EXPORT_NAMES,DATA_EXPORT_NAMES,SOURCE_COMMIT
from unpacker.guest_export_image import build_export_image
from unpacker.loader_lists import install_loader_lists


class DesktopModules:
    def __init__(self,model):
        self.model=model;self.engine=model.engine;self.uc=self.engine.uc
        self.views={};self.by_base={};self.symbols={};self.refs={};self.lookups=0;self.loads=0
        self.tokens={};self.trap_calls=0;self.copied_trap_calls=0;self.trap_hook=None
        prepared=[]
        for index,name in enumerate(sorted(EXPORT_NAMES)):
            data={key:bytes(4) for key in ['_acmdln','_adjust_fdiv','__initenv','__winitenv']} if name=='msvcrt.dll' else {}
            private=model.PATH+b'\0'+(model.PATH.decode('ascii')+'\0').encode('utf-16le') if name=='msvcrt.dll' else b''
            identifiers={symbol:len(self.tokens)+number+1 for number,symbol in enumerate(EXPORT_NAMES[name])}
            for symbol,identifier in identifiers.items():self.tokens[identifier]=(name,symbol)
            view=build_export_image(name,EXPORT_NAMES[name],0x61000000+index*0x100000,self.engine.HOOK_ADDR,data,private,identifiers)
            if any(lo<view['base']+view['size'] and view['base']<=hi for lo,hi,_ in self.uc.mem_regions()):
                model.reject('GuestModules','Export-view address range is already mapped')
            prepared.append((name,view))
        old_hooks=dict(model.handler.hooks);old_names=dict(model.handler.module_for_function)
        old_loader=self.engine._unpacker_loader_lists;old_extra=getattr(self.engine,'_unpacker_extra_modules',())
        ldr=self.engine.PEB_BASE+0x1000;old_bytes=bytes(self.uc.mem_read(ldr,0x3000));mapped=[]
        try:
            for name,view in prepared:
                base=view['base'];self.uc.mem_map(base,view['size']);mapped.append((base,view['size']))
                self.uc.mem_write(base,view['image'])
                self.uc.mem_protect(base,view['size'],1)
                self.uc.mem_protect(base+view['text_rva'],view['text_size'],5)
                if view['globals_size']:self.uc.mem_protect(base+view['globals_rva'],view['globals_size'],3)
                self.views[name]=view;self.by_base[base]=name;self.refs[base]=1
                for symbol,address in view['exports'].items():
                    if symbol in view['data_exports']:continue
                    model.handler.module_for_function[symbol]=name
                    self.symbols[address]=(name,symbol)
            self.engine._unpacker_extra_modules=tuple((name,view['base'],'C:\\Windows\\System32\\'+name) for name,view in self.views.items())
            self.engine._unpacker_loader_lists=install_loader_lists(self.engine)
            for row in self.engine._unpacker_loader_lists['module_images']:
                self.refs.setdefault(row['base'],1)
            crt_view=self.views['msvcrt.dll'];crt=crt_view['data_exports'];pointer=crt_view['base']+crt_view['private_data_rva']
            model.command_lines[False]=pointer;model.command_lines[True]=pointer+len(model.PATH)+1
            self.uc.mem_write(crt['_acmdln'],struct.pack('<I',pointer));model.crt_cells['acmdln']=crt['_acmdln']
            model.crt_cells['initenv']=crt['__initenv'];model.crt_cells['winitenv']=crt['__winitenv']
            from unicorn import UC_HOOK_INSN_INVALID
            self.trap_hook=self.uc.hook_add(UC_HOOK_INSN_INVALID,self._trap)
            model.protection.initial_reservations.extend((view['base'],view['base']+view['size']) for name,view in prepared)
        except BaseException:
            if self.trap_hook is not None:self.uc.hook_del(self.trap_hook)
            model.handler.hooks.clear();model.handler.hooks.update(old_hooks)
            model.handler.module_for_function.clear();model.handler.module_for_function.update(old_names)
            for address,size in reversed(mapped):self.uc.mem_unmap(address,size)
            self.engine._unpacker_extra_modules=old_extra;self.engine._unpacker_loader_lists=old_loader
            self.uc.mem_write(ldr,old_bytes)
            raise

    def _decode_trap(self,uc,address):
        try:raw=bytes(uc.mem_read(address,5))
        except Exception:return None
        if raw[:2]!=b'\x0f\x0b' or raw[4:]!=b'\xc3':return None
        return self.tokens.get(struct.unpack('<H',raw[2:4])[0])

    def is_dispatch_site(self,uc,address,size):
        # Pinned Unicorn 1.x reports an invalid size for UD2. Avoid a memory
        # read on every ordinary guest instruction; relocated traps are checked
        # only on this invalid-instruction path and again before dispatch.
        return any(view['base']+view['text_rva']<=address<view['base']+view['text_rva']+view['text_size'] for view in self.views.values()) or (not 1<=size<=15 and self._decode_trap(uc,address) is not None)

    def _trap(self,uc,user_data):
        from unicorn.x86_const import UC_X86_REG_EIP,UC_X86_REG_ESP,UC_X86_REG_EAX
        address=uc.reg_read(UC_X86_REG_EIP);binding=self._decode_trap(uc,address)
        if binding is None:return False
        try:
            if self.trap_calls>=65536:self.model.reject(binding[1],'Model API dispatch budget exceeded')
            self.trap_calls+=1
            if address not in self.symbols:self.copied_trap_calls+=1
            value,esp=self.model.handler.apicall(address,binding[1],uc,uc.reg_read(UC_X86_REG_ESP),False)
            if value is not None:
                uc.reg_write(UC_X86_REG_EAX,value&0xffffffff)
                uc.mem_write(self.engine.HOOK_ADDR,struct.pack('<I',value&0xffffffff))
            # Complete the modeled RET here. This also supports CRT callback
            # scheduling and avoids classifying a relocated RET as a payload
            # handoff. The complete marker remains five bytes when copied.
            destination=struct.unpack('<I',uc.mem_read(esp,4))[0]
            uc.reg_write(UC_X86_REG_ESP,esp+4);uc.reg_write(UC_X86_REG_EIP,destination)
            counters=self.engine.apicall_counter;counters[binding[1]]=counters.get(binding[1],0)+1
            return True
        except Exception as exc:
            self.engine._unpacker_callback_error=f'{type(exc).__name__}: {str(exc)[:240]}'
            self.engine.stop();uc.emu_stop();return False

    def _name(self,uc,pointer,wide=False):
        if not pointer:return None
        if wide:
            raw=bytearray()
            for index in range(512):
                part=bytes(uc.mem_read(pointer+index*2,2))
                if part==bytes(2):break
                raw.extend(part)
            else:self.model.reject('GuestModules','Unicode module name exceeds model limit')
            try:value=raw.decode('utf-16le')
            except UnicodeError:self.model.reject('GuestModules','Invalid Unicode module name')
        else:value=self.model.string(uc,pointer,operation='GuestModules').decode('cp1252')
        value=value.lower()
        if '/' in value:return None
        name=ntpath.basename(value)
        if '.' not in name:name+='.dll'
        if value=='c:\\sample.bin':return 'sample.bin'
        if ntpath.dirname(value) and value!='c:\\windows\\system32\\'+name:return None
        return name

    def _row(self,name):
        return next((row for row in self.engine._unpacker_loader_lists['module_images'] if row['name'].lower()==name),None)

    def _finish(self,uc,esp,count,value):
        ret=bytes(uc.mem_read(esp,4));new=esp+count*4;uc.mem_write(new,ret);return value,new

    def dispatch(self,address,name,uc,esp,log):
        binding=self._decode_trap(uc,address) or self.symbols.get(address)
        if binding:
            module,symbol=binding
            if address in self.symbols and self._decode_trap(uc,address)!=self.symbols[address]:
                self.model.reject(name,'Modified model API entry/interposition is not implemented')
            if name not in self.model.functions:
                words=[]
                for index in range(6):
                    try:words.append(struct.unpack('<I',uc.mem_read(esp+4+index*4,4))[0])
                    except Exception:break
                self.model.current_call={'name':name,'stack_words':words,'signature':'not_modeled'}
                try:self.model.reject(name,'Export is known, but API execution semantics are not implemented')
                finally:self.model.current_call=None
        if name in {'LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW'}:
            count=3 if 'Ex' in name else 1
            args=struct.unpack('<'+'I'*count,uc.mem_read(esp+4,4*count))
            if count==3 and (args[1] or args[2] not in {0,0x800}):
                self.model.reject(name,'Only ordinary resident-code loads/System32 lookup are modeled')
            module=self._name(uc,args[0],name.endswith('W'));row=self._row(module)
            if row is None:
                self.model.last_error=126
                if len(self.model.events)<32:self.model.events.append({'operation':name,'result':'module_not_found','module':str(module)[:128]})
                return self._finish(uc,esp,count,0)
            base=row['base']
            if self.refs[base]>=65535:self.model.reject(name,'Module reference budget exceeded')
            self.model.modules.bind(row);self.refs[base]+=1;self.loads+=1
            return self._finish(uc,esp,count,base)
        if name=='GetModuleHandleW':
            pointer=struct.unpack('<I',uc.mem_read(esp+4,4))[0]
            if not pointer:return self._finish(uc,esp,1,self.engine.sample.BASE_ADDR)
            row=self._row(self._name(uc,pointer,True))
            if row:self.model.modules.bind(row);value=row['base']
            else:self.model.last_error=126;value=0
            return self._finish(uc,esp,1,value)
        if name=='FreeLibrary':
            base=struct.unpack('<I',uc.mem_read(esp+4,4))[0]
            if base not in self.refs or self.refs[base]<=1:
                self.model.reject(name,'Resident/pinned or unknown module cannot be unloaded in this profile')
            self.refs[base]-=1;return self._finish(uc,esp,1,1)
        if name=='GetProcAddress':
            base,pointer=struct.unpack('<II',uc.mem_read(esp+4,8))
            if not base:
                self.model.last_error=126;return self._finish(uc,esp,2,0)
            if base not in self.by_base:return None  # Existing core DLL resolver.
            if pointer<=65535:self.model.reject(name,'Native DLL ordinal contract is not modeled')
            try:symbol=self.model.string(uc,pointer,operation=name).decode('ascii')
            except UnicodeError:self.model.reject(name,'Invalid ASCII export name')
            module=self.by_base[base];view=self.views[module]
            if symbol not in view['exports']:
                if symbol in DATA_EXPORT_NAMES[module]:self.model.reject(name,'Data export has no modeled storage: '+module+'!'+symbol)
                self.model.last_error=127
                return self._finish(uc,esp,2,0)
            self.lookups+=1
            if self.lookups>8192:self.model.reject(name,'Export lookup budget exceeded')
            handler=self.model.handler;key=handler.module_handles.get(base,module)
            handler.module_handles[base]=key;handler.load_library_counter.setdefault(key,0)
            group=key+'#'+str(handler.load_library_counter[key])
            self.engine.sample.dllname_to_functionlist.setdefault(group,[]).append((symbol,view['exports'][symbol]))
            return self._finish(uc,esp,2,view['exports'][symbol])
        return None

    def facts(self):
        return {'profile':'resident_named_export_views','metadata_source_commit':SOURCE_COMMIT,
                'modules':{name:{'base':v['base'],'bytes':v['size'],'named_exports':len(v['exports']),
                                   'references':self.refs[v['base']]} for name,v in self.views.items()},
                'native_dll_code_execution':False,'initializers_tls_resources':'not_modeled',
                'native_ordinals':'unsupported','unknown_api_execution':'unsupported',
                'api_dispatch':'relocatable_model_traps','trap_calls':self.trap_calls,'copied_trap_calls':self.copied_trap_calls,
                'lookups':self.lookups,'loads':self.loads,'resident_reference_floor':1}
