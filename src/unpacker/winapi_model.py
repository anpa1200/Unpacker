"""Small, explicit PE32 API model for read-only self-file access.

This is an emulator-side byte model. Guest paths are never opened on the host.
Unsupported calls fail instead of returning invented success values.
"""
import struct
import time
from pathlib import Path


class UnsupportedAPI(RuntimeError):pass


class SelfFileModel:
    PATH=b'C:\\sample.bin'
    def __init__(self,engine,data,max_bytes):
        self.engine=engine;self.handler=engine.apicall_handler;self.data=data;self.limit=max_bytes
        self.handles={};self.views={};self.globals={};self.next_handle=0x70000000;self.events=[];self.warnings=[];self.unsupported=[]
        self.clock=time.monotonic;self.boot_time=self.clock();self.tls={};self.last_error=0;self.critical={};self.heap_allocations={}
        self.guest_exit_code=None;self.last_message=None;self.yesno_answer="no"
        from unpacker.guest_messages import RegisteredMessages
        self.registered_messages=RegisteredMessages(self)
        # Explicit guest configuration, independent of the analyst's display.
        # Scrollbar thickness and large-icon size for a fixed 96-DPI guest.
        self.desktop_metrics={0:1920,1:1080,2:17,3:17,11:32,12:32}
        from unpacker.guest_display import GuestDisplay
        self.display=GuestDisplay(self)
        from unpacker.guest_paths import GuestPaths
        self.paths=GuestPaths(self)
        from unpacker.guest_modules import GuestModules
        self.modules=GuestModules(self)
        self.desktop_modules=None
        from unpacker.guest_file_io import GuestFileIO
        self.file_io=GuestFileIO(self)
        from unpacker.file_attributes import VirtualFileAttributes
        self.file_attributes=VirtualFileAttributes(self)
        from unpacker.guest_mutex import GuestMutexes
        self.mutexes=GuestMutexes(self)
        from unpacker.guest_callbacks import GuestCallbacks
        from unpacker.codepage_model import CodePages
        from unpacker.floating_point import FloatingPoint
        self.codepages=CodePages(self)
        self.floating_point=FloatingPoint(self)
        from unpacker.guest_protection import GuestProtection
        self.protection=GuestProtection(self)
        from unpacker.crt_startup import CRTStartup
        self.crt_startup=CRTStartup(self)
        from unpacker.crt_memory import CRTMemory
        self.crt_memory=CRTMemory(self)
        from unpacker.crt_buffers import CRTBuffers
        self.crt_buffers=CRTBuffers(self)
        from unpacker.guest_format import GuestFormat
        self.guest_format=GuestFormat(self)
        self.callbacks=GuestCallbacks(self);self.process_heap_handle=None;self.application_type=0;self.crt_cells={};self.command_lines={};self.environment_copies={};self.exception_filter=0
        from unpacker.heap_policy import HeapPolicy
        self.heap_policy=HeapPolicy(self)
        self.functions={
            'GetModuleFileNameA':(3,self.module_name),'GetModuleHandleA':(1,self.module_handle),'CreateFileA':(7,self.open_self),'CreateFileW':(7,self.open_self_w),
            'GetFullPathNameA':(4,self.paths.full_path),
            'CharUpperBuffA':(2,self.paths.upper_ascii),
            'CreateMutexA':(3,self.mutexes.create),'ReleaseMutex':(1,self.mutexes.release),
            'WaitForSingleObject':(2,self.mutexes.wait),
            'GetFileAttributesExW':(3,self.file_attributes.query_w),'ReadFile':(5,self.file_io.read),'SetFilePointer':(4,self.file_io.seek),
            'GetFileSize':(2,self.file_size),'CreateFileMappingA':(6,self.create_mapping),
            'MapViewOfFile':(5,self.map_view),'UnmapViewOfFile':(1,self.unmap_view),
            'CloseHandle':(1,self.close),'GetCurrentProcess':(0,lambda uc:0xffffffff),
            'FlushInstructionCache':(3,self.flush),'ExitProcess':(1,self.exit),
            'VirtualProtectEx':(5,self.protect_current_process),'VirtualProtect':(4,self.protection.protect),
            'GlobalAlloc':(2,self.global_alloc),'GlobalFree':(1,self.global_free),
            'GlobalLock':(1,self.global_lock),'GlobalUnlock':(1,self.global_unlock),
            'GlobalSize':(1,self.global_size),'GlobalFlags':(1,self.global_flags),
            'HeapAlloc':(3,self.heap_alloc),'HeapFree':(3,self.heap_free),'HeapSize':(3,self.heap_size),
            'HeapSetInformation':(4,self.heap_policy.set_information),'GetProcessHeap':(0,self.process_heap),'HeapDestroy':(1,self.heap_destroy),
            'SetHandleCount':(1,self.handle_count),
            '__set_app_type':(1,self.set_app_type,'cdecl'),
            '__lconv_init':(0,self.crt_startup.initialize_locale,'cdecl'),
            'localeconv':(0,self.crt_startup.localeconv,'cdecl'),
            '__getmainargs':(5,self.crt_startup.getmainargs,'cdecl'),
            '_onexit':(1,self.crt_startup.register_exit,'cdecl'),
            'malloc':(1,self.crt_memory.malloc,'cdecl'),
            'calloc':(2,self.crt_memory.calloc,'cdecl'),
            'realloc':(2,self.crt_memory.realloc,'cdecl'),
            'free':(1,self.crt_memory.free,'cdecl'),
            '_errno':(0,lambda uc:self.crt_cell(uc,'errno',0),'cdecl'),
            'strlen':(1,self.crt_buffers.strlen,'cdecl'),
            'memcpy':(3,self.crt_buffers.copy,'cdecl'),
            'memmove':(3,lambda uc,d,s,n:self.crt_buffers.copy(uc,d,s,n,True),'cdecl'),
            'memset':(3,self.crt_buffers.memset,'cdecl'),
            'memcmp':(3,self.crt_buffers.memcmp,'cdecl'),
            'strcmp':(2,self.crt_buffers.strcmp,'cdecl'),
            'strcpy':(2,self.crt_buffers.strcpy,'cdecl'),
            'strncpy':(3,self.crt_buffers.strncpy,'cdecl'),
            'lstrcatA':(2,self.crt_buffers.lstrcat_a),
            'wsprintfA':(2,self.guest_format.format_a,'varargs'),
            'wvsprintfA':(3,self.guest_format.format_a),
            '_controlfp':(2,self.floating_point.control,'cdecl'),
            '_control87':(2,lambda uc,new,mask:self.floating_point.control(uc,new,mask,True),'cdecl'),
            '__p__fmode':(0,lambda uc:self.crt_cell(uc,'fmode',0x4000),'cdecl'),
            '__p__commode':(0,lambda uc:self.crt_cell(uc,'commode',0),'cdecl'),
            'GetACP':(0,lambda uc:1252),
            'GetCPInfo':(2,self.codepage_info),
            'WideCharToMultiByte':(8,self.codepages.wide_to_multi),
            'GetCommandLineA':(0,lambda uc:self.command_line(uc,False)),
            'GetCommandLineW':(0,lambda uc:self.command_line(uc,True)),
            '__p__acmdln':(0,self.command_line_cell,'cdecl'),
            'GetEnvironmentStringsA':(0,lambda uc:self.environment_strings(uc,False)),
            'GetEnvironmentStringsW':(0,lambda uc:self.environment_strings(uc,True)),
            'FreeEnvironmentStringsA':(1,lambda uc,p:self.free_environment(uc,p,False)),
            'FreeEnvironmentStringsW':(1,lambda uc,p:self.free_environment(uc,p,True)),
            'SetUnhandledExceptionFilter':(1,self.set_exception_filter),
            'LocalAlloc':(2,self.global_alloc),'LocalFree':(1,self.global_free),
            'LocalLock':(1,self.global_lock),'LocalUnlock':(1,self.global_unlock),
            'LocalSize':(1,self.global_size),'LocalFlags':(1,self.global_flags),
            'GetTickCount':(0,self.tick_count),'GetVersionExA':(1,self.version_info),
            'OpenProcess':(3,self.open_current_process),'GetCurrentProcessId':(0,self.current_process_id),'GetProcessVersion':(1,self.process_version),
            'GetSystemMetrics':(1,self.system_metrics),
            'GetDC':(1,self.display.get_dc),'GetDeviceCaps':(2,self.display.device_caps),
            'ReleaseDC':(2,self.display.release_dc),
            'GetSysColor':(1,self.display.system_color),
            'GetStartupInfoA':(1,self.startup_info),
            'GetStdHandle':(1,self.standard_handle),'GetFileType':(1,self.file_type),
            'InitializeCriticalSection':(1,self.critical_init),
            'EnterCriticalSection':(1,self.critical_enter),
            'LeaveCriticalSection':(1,self.critical_leave),
            'DeleteCriticalSection':(1,self.critical_delete),
            'TlsAlloc':(0,self.tls_alloc),'TlsSetValue':(2,self.tls_set),
            'TlsGetValue':(1,self.tls_get),'TlsFree':(1,self.tls_free),
            'GetLastError':(0,lambda uc:self.last_error),'SetLastError':(1,self.set_error),
            'RegisterWindowMessageA':(1,self.registered_messages.register),
            'RegisterWindowMessageW':(1,lambda uc,p:self.registered_messages.register(uc,p,True)),
            'MessageBoxA':(4,self.message),
            'MessageBoxW':(4,lambda uc,o,t,c,f:self.message(uc,o,t,c,f,True))}

    def reject(self,name,reason):
        if len(self.unsupported)<32:
            record={'name':str(name)[:128],'reason':str(reason)[:240]}
            if getattr(self,'current_call',None):record['call']=self.current_call
            self.unsupported.append(record)
        self.engine.stop()
        raise UnsupportedAPI(f'{name}: {reason}')

    def string(self,uc,address,operation='CreateFileA'):
        data=bytearray()
        for offset in range(1024):
            value=uc.mem_read(address+offset,1)[0]
            if value==0:return bytes(data)
            data.append(value)
        self.reject(operation,'Guest path exceeds model limit')

    def handle(self,kind,data):
        if len(self.handles)>=128:self.reject(kind,'Handle budget exceeded')
        self.next_handle+=1;self.handles[self.next_handle]=(kind,data);return self.next_handle

    def module_handle(self,uc,name):
        if not name:return self.engine.sample.BASE_ADDR
        return self.modules.handle(uc,name)

    def protect_current_process(self,uc,process,address,size,protection,old_pointer):
        if process!=0xffffffff:
            kind,state=self.handles.get(process,(None,None))
            if kind!='process' or state['pid']!=self.current_process_id(uc):
                self.reject('VirtualProtectEx','Only a current guest process handle is supported')
            if not state['access']&8:self.reject('VirtualProtectEx','Handle lacks PROCESS_VM_OPERATION rights')
        return self.protection.protect(uc,address,size,protection,old_pointer)

    def open_current_process(self,uc,access,inherit,pid):
        if inherit:self.reject('OpenProcess','Inherited process handles are not modeled')
        if access&~0x001fffff:self.reject('OpenProcess','Generic/MAXIMUM_ALLOWED or undeclared process rights require a security-token model')
        if pid!=self.current_process_id(uc):self.reject('OpenProcess','Only the current unprotected virtual process is modeled')
        return self.handle('process',{'pid':pid,'access':access,'inherited':False,'profile':'current_unprotected_guest_process'})

    def current_process_id(self,uc):
        value=getattr(self.handler,'processid',None)
        if type(value) is not int or not 1<=value<=0xffffffff:
            self.reject('GetCurrentProcessId','Current virtual process identity is unavailable or invalid')
        return value

    def process_version(self,uc,pid):
        if pid not in {0,getattr(self.handler,'processid',None)}:
            self.reject('GetProcessVersion','Only the current emulated process is modeled')
        header=getattr(self.engine.sample,'opt_header',None)
        major=getattr(header,'MajorSubsystemVersion',None)
        minor=getattr(header,'MinorSubsystemVersion',None)
        if type(major) is not int or type(minor) is not int or not 1<=major<=65535 or not 0<=minor<=65535:
            self.reject('GetProcessVersion','Input subsystem version is missing or outside the supported profile')
        if len(self.events)<32:
            self.events.append({'operation':'GetProcessVersion','source':'input_subsystem_version',
                'major':major,'minor':minor})
        return major<<16|minor

    def system_metrics(self,uc,index):
        if index not in self.desktop_metrics:
            self.reject('GetSystemMetrics',f'Metric {index} is outside the fixed guest desktop profile')
        value=self.desktop_metrics[index]
        if len(self.events)<32:
            self.events.append({'operation':'GetSystemMetrics','index':index,'value':value,'profile':'guest_96dpi_basic_metrics'})
        return value

    def module_name(self,uc,module,buffer,size):
        if module not in {0,self.engine.sample.BASE_ADDR}:self.reject('GetModuleFileNameA','Only the specimen module is modeled')
        if not 1<=size<=65536:return 0
        value=self.PATH[:size-1];uc.mem_write(buffer,value+b'\0')
        return len(value) if size>len(self.PATH) else size

    def open_self(self,uc,path,access,share,security,creation,flags,template):
        if not path:self.last_error=87;return 0xffffffff
        try:name=self.string(uc,path).decode('ascii')
        except UnicodeDecodeError:self.reject('CreateFileA','Non-ASCII paths require an explicit code-page profile')
        return self._open_known(name,'CreateFileA',access,share,security,creation,flags,template)

    def open_self_w(self,uc,path,access,share,security,creation,flags,template):
        if not path:self.last_error=87;return 0xffffffff
        data=bytearray()
        for index in range(1024):
            try:unit=bytes(uc.mem_read(path+index*2,2))
            except Exception:self.reject('CreateFileW','Guest filename is not readable')
            if unit==b'\0\0':break
            data.extend(unit)
        else:self.reject('CreateFileW','Guest filename exceeds bounded profile')
        try:name=data.decode('utf-16le')
        except UnicodeDecodeError:self.reject('CreateFileW','Malformed UTF-16 filename')
        return self._open_known(name,'CreateFileW',access,share,security,creation,flags,template)

    def _open_known(self,name,operation,access,share,security,creation,flags,template):
        import ntpath
        if len(name)>260 or name.startswith('\\\\') or (':' in name and not name.lower().startswith('c:')):
            self.reject(operation,'Long/network/device/foreign-drive paths are outside virtual file profile')
        name=ntpath.normpath(ntpath.join('C:\\',name.replace('/','\\'))).lower()
        if name!=self.PATH.decode('ascii').lower():
            self.last_error=2
            if len(self.events)<32:self.events.append({'operation':'virtual_path_absent','path':repr(name[:128])})
            return 0xffffffff
        if creation!=3 or access&~0x80000000:self.reject(operation,'Only read-only OPEN_EXISTING is modeled')
        if security or template:self.reject(operation,'Security descriptors/inherited/template handles are not modeled')
        if share&~7:self.last_error=87;return 0xffffffff
        if flags&~(0x80|0x08000000|0x10000000|0x20000000|0x40000000):self.reject(operation,'Requested file flags are not modeled')
        for handle,(kind,_) in self.handles.items():
            if kind!='file':continue
            if handle not in self.file_io.options or handle not in self.file_io.sharing:self.reject(operation,'Existing file access provenance is unavailable')
            old_access=self.file_io.options[handle][0];old_share=self.file_io.sharing[handle]
            if not access or not old_access:self.reject(operation,'Concurrent metadata-only handle sharing is outside profile')
            if (access&0x80000000 and not old_share&1) or (old_access&0x80000000 and not share&1):
                self.last_error=32;return 0xffffffff
        handle=self.handle('file',self.data);self.file_io.register(handle,access,flags,share);return handle

    def file_size(self,uc,handle,high):
        kind,data=self.handles.get(handle,(None,None))
        if kind!='file':return 0xffffffff
        if high:uc.mem_write(high,bytes(4))
        return len(data)

    def create_mapping(self,uc,handle,security,protection,high,low,name):
        if high or protection not in {2,4,8} or name:self.reject('CreateFileMappingA','Unsupported mapping size, protection or named object')
        kind,data=self.handles.get(handle,(None,None))
        if kind!='file':self.reject('CreateFileMappingA','Only specimen-backed mappings are modeled')
        size=low or len(data)
        if not 0<size<=len(data) or size>self.limit:self.reject('CreateFileMappingA','Mapping exceeds specimen/budget')
        if sum(len(value) for kind,value in self.handles.values() if kind=='mapping')+size>self.limit:self.reject('CreateFileMappingA','Aggregate mapping budget exceeded')
        return self.handle('mapping',data[:size])

    def map_view(self,uc,handle,access,high,low,size):
        kind,data=self.handles.get(handle,(None,None))
        if kind!='mapping' or high or low%65536 or access not in {1,2,4,6,0xf001f}:self.reject('MapViewOfFile','Unsupported mapping handle, offset or access')
        size=size or len(data)-low
        if not 0<size<=self.limit or low+size>len(data):self.reject('MapViewOfFile','View exceeds mapping/budget')
        if any(view[2]==handle for view in self.views.values()):self.reject('MapViewOfFile','Simultaneous shared views are not modeled')
        allocated=(size+4095)&~4095
        if sum(view[0] for view in self.views.values())+allocated>max(4096,self.limit):self.reject('MapViewOfFile','Aggregate view budget exceeded')
        address=self.handler.alloc(False,allocated,uc)
        uc.mem_write(address,data[low:low+size]);self.views[address]=(allocated,size,handle)
        if len(self.events)<32:self.events.append({'operation':'self_file_view','bytes':size,'address':address})
        return address

    def unmap_view(self,uc,address):
        view=self.views.pop(address,None)
        if view is None:return 0
        size=view[0];uc.mem_unmap(address,size)
        self.engine.sample.allocated_chunks=[(lo,hi) for lo,hi in self.engine.sample.allocated_chunks if not (lo==address and hi==address+size)]
        self.handler.alloc_sizes.pop(address,None)
        return 1

    def close(self,uc,handle):
        if self.handles.get(handle,(None,None))[0]=='mutex':return self.mutexes.close(handle)
        if self.handles.get(handle,(None,None))[0]=='process':del self.handles[handle];return 1
        if self.handles.get(handle,(None,None))[0] not in {'file','mapping'}:self.last_error=6;return 0
        del self.handles[handle];self.file_io.close(handle);return 1

    def global_alloc(self,uc,flags,size):
        # Obsolete Win16 flags (including DDESHARE) have no NT effect.
        if flags&~0x7172 or size>self.limit:self.reject('GlobalAlloc','Unsupported allocation flags or size')
        if flags&2:
            address=self.global_alloc(uc,flags&0x40,size) if size else 0
            return self.handle('global',{'address':address,'size':size,'locks':0})
        if not size:self.reject('GlobalAlloc','Zero-sized fixed allocation is outside the model')
        allocated=(size+4095)&~4095
        if sum(self.globals.values())+sum(v[0] for v in self.views.values())+allocated>max(4096,self.limit):self.reject('GlobalAlloc','Aggregate model memory budget exceeded')
        address=self.handler.alloc(False,allocated,uc);self.globals[address]=allocated
        if flags&0x40:uc.mem_write(address,bytes(allocated))
        return address

    def global_free(self,uc,address):
        kind,block=self.handles.get(address,(None,None))
        if kind=='global':
            if block['address']:self.global_free(uc,block['address'])
            del self.handles[address];return 0
        size=self.globals.pop(address,None)
        if size is None:return address
        uc.mem_unmap(address,size)
        self.engine.sample.allocated_chunks=[(lo,hi) for lo,hi in self.engine.sample.allocated_chunks if not (lo==address and hi==address+size)]
        self.handler.alloc_sizes.pop(address,None)
        return 0

    def global_lock(self,uc,handle):
        kind,block=self.handles.get(handle,(None,None))
        if kind=='global':
            if not block['address']:self.last_error=157;return 0
            if block['locks']>=255:self.reject('GlobalLock','Movable lock-count budget exceeded')
            block['locks']+=1;return block['address']
        if handle in self.globals:return handle
        self.last_error=6;return 0

    def global_unlock(self,uc,handle):
        kind,block=self.handles.get(handle,(None,None))
        if kind=='global':
            if not block['locks']:self.last_error=158;return 0
            block['locks']-=1;self.last_error=0;return int(block['locks']>0)
        if handle in self.globals:self.last_error=0;return 0
        self.last_error=6;return 0

    def global_size(self,uc,handle):
        kind,block=self.handles.get(handle,(None,None))
        if kind=='global':return block['size']
        if handle in self.globals:return self.globals[handle]
        self.last_error=6;return 0

    def global_flags(self,uc,handle):
        kind,block=self.handles.get(handle,(None,None))
        if kind=='global':return block['locks']|(0x4000 if not block['address'] else 0)
        if handle in self.globals:return 0
        self.last_error=6;return 0x8000

    def heap_alloc(self,uc,heap,flags,size):
        if heap not in self.handler.heaps or flags&~9:self.reject('HeapAlloc','Unknown heap or unsupported flags')
        limit=self.handler.heaps[heap][1]
        if limit and sum(value[1] for value in self.heap_allocations.values() if value[0]==heap)+size>limit:return 0
        address=self.global_alloc(uc,0x40 if flags&8 else 0,max(1,size))
        self.heap_allocations[address]=(heap,size);self.heap_policy.allocated(heap,address);return address

    def heap_free(self,uc,heap,flags,address):
        if flags&~1:return 0
        if self.heap_allocations.get(address,(None,None))[0]!=heap:
            self.heap_policy.invalid_free(uc,heap,address);return 0
        self.global_free(uc,address);del self.heap_allocations[address];self.heap_policy.freed(heap,address);return 1

    def heap_size(self,uc,heap,flags,address):
        entry=self.heap_allocations.get(address)
        return entry[1] if not flags&~1 and entry is not None and entry[0]==heap else 0xffffffff

    def process_heap(self,uc):
        if self.process_heap_handle is None:
            self.process_heap_handle=self.handler.next_heap_handle;self.handler.next_heap_handle+=1
            self.handler.heaps[self.process_heap_handle]=(0,0)
        return self.process_heap_handle

    def heap_destroy(self,uc,heap):
        if heap==self.process_heap_handle or heap not in self.handler.heaps:
            self.last_error=87;return 0
        for address,(owner,size) in list(self.heap_allocations.items()):
            if owner==heap:self.heap_free(uc,heap,0,address)
        del self.handler.heaps[heap];return 1

    def handle_count(self,uc,count):
        # Windows NT compatibility API: no change to actual modeled/host handles.
        return count

    def set_app_type(self,uc,value):
        if value not in {0,1,2}:self.reject('__set_app_type','Unknown CRT application type')
        self.application_type=value;return None

    def crt_cell(self,uc,name,value):
        if name not in self.crt_cells:
            self.crt_cells[name]=self.global_alloc(uc,0x40,4)
            uc.mem_write(self.crt_cells[name],struct.pack('<I',value))
        return self.crt_cells[name]

    def codepage_info(self,uc,codepage,buffer):
        if codepage not in {0,1252}:self.last_error=87;return 0
        uc.mem_write(buffer,struct.pack('<I',1)+b'?\0'+bytes(14));return 1

    def command_line(self,uc,wide):
        if wide not in self.command_lines:
            data=(self.PATH.decode('ascii')+'\0').encode('utf-16le') if wide else self.PATH+b'\0'
            address=self.global_alloc(uc,0x40,len(data));uc.mem_write(address,data);self.command_lines[wide]=address
        return self.command_lines[wide]

    def command_line_cell(self,uc):
        return self.crt_cell(uc,'acmdln',self.command_line(uc,False))

    def environment_strings(self,uc,wide):
        # Explicit empty guest environment; never copy process/host credentials.
        address=self.global_alloc(uc,0x40,4 if wide else 2);self.environment_copies[address]=wide;return address

    def free_environment(self,uc,address,wide):
        if address not in self.environment_copies or self.environment_copies[address]!=wide:self.last_error=87;return 0
        self.global_free(uc,address);del self.environment_copies[address];return 1

    def set_exception_filter(self,uc,address):
        previous=self.exception_filter;self.exception_filter=address;return previous

    def standard_handle(self,uc,index):
        if index in {0xfffffff6,0xfffffff5,0xfffffff4}:return 0
        self.last_error=87;return 0xffffffff

    def file_type(self,uc,handle):
        if self.handles.get(handle,(None,None))[0]=='file':return 1
        self.last_error=6;return 0

    def startup_info(self,uc,buffer):
        data=bytearray(68);struct.pack_into('<I',data,0,68);uc.mem_write(buffer,bytes(data));return None

    def critical_init(self,uc,address):
        if len(self.critical)>=64:self.reject('InitializeCriticalSection','Critical-section budget exceeded')
        uc.mem_write(address,struct.pack('<IiIIII',0,-1,0,0,0,0));self.critical[address]=0;return None

    def critical_enter(self,uc,address):
        if address not in self.critical:
            fields=struct.unpack('<IiIIII',uc.mem_read(address,24))
            if fields[1:4]!=(-1,0,0):self.reject('EnterCriticalSection','Critical section is not initialized in this model')
            if len(self.critical)>=64:self.reject('EnterCriticalSection','Critical-section budget exceeded')
            self.critical[address]=0
        depth=self.critical[address]+1
        if depth>65535:self.reject('EnterCriticalSection','Recursive lock budget exceeded')
        self.critical[address]=depth
        uc.mem_write(address+4,struct.pack('<iII',depth-1,depth,getattr(self.handler,'threadid',1)))
        return None

    def critical_leave(self,uc,address):
        depth=self.critical.get(address,0)
        if not depth:self.reject('LeaveCriticalSection','Critical section is not owned by the emulated thread')
        depth-=1;self.critical[address]=depth
        uc.mem_write(address+4,struct.pack('<iII',depth-1,depth,getattr(self.handler,'threadid',1) if depth else 0));return None

    def critical_delete(self,uc,address):
        if address not in self.critical or self.critical[address]:self.reject('DeleteCriticalSection','Unknown or locked critical section')
        del self.critical[address];return None

    def tick_count(self,uc):return int((self.clock()-self.boot_time)*1000)&0xffffffff

    def version_info(self,uc,buffer):
        size=struct.unpack('<I',uc.mem_read(buffer,4))[0]
        if size not in {148,156}:self.reject('GetVersionExA','Only ANSI OSVERSIONINFO/EX structures are modeled')
        data=bytearray(size);struct.pack_into('<IIIII',data,0,size,6,1,7601,2)
        service=b'Service Pack 1';data[20:20+len(service)]=service
        if size==156:struct.pack_into('<HHHBB',data,148,1,0,0x100,1,0)
        uc.mem_write(buffer,bytes(data))
        if not any(e.get('operation')=='GetVersionExA' for e in self.events) and len(self.events)<32:
            self.events.append({'operation':'GetVersionExA','profile':'Windows 7 SP1 (6.1.7601), emulated'})
        return 1

    def tls_alloc(self,uc):
        for index in range(64):
            if index not in self.tls:
                self.tls[index]=0;self._tls_memory(uc,index,0);return index
        self.last_error=8;return 0xffffffff

    def _tls_memory(self,uc,index,value):
        if hasattr(self.engine,'TEB_BASE'):uc.mem_write(self.engine.TEB_BASE+0xe10+4*index,struct.pack('<I',value))

    def tls_set(self,uc,index,value):
        if index not in self.tls:self.last_error=87;return 0
        self.tls[index]=value;self._tls_memory(uc,index,value);return 1

    def tls_get(self,uc,index):
        if index not in self.tls:self.last_error=87;return 0
        self.last_error=0;return self.tls[index]

    def tls_free(self,uc,index):
        if index not in self.tls:self.last_error=87;return 0
        del self.tls[index];self._tls_memory(uc,index,0);return 1

    def set_error(self,uc,value):self.last_error=value;return None

    def flush(self,uc,process,address,size):
        if process!=0xffffffff:self.reject('FlushInstructionCache','Only the specimen process is modeled')
        if address and size and callable(getattr(uc,'ctl_remove_cache',None)):
            uc.ctl_remove_cache(address,address+size)
        elif 'Instruction-cache flush approximated by backend memory-write behavior' not in self.warnings:
            self.warnings.append('Instruction-cache flush approximated by backend memory-write behavior')
        return 1

    def exit(self,uc,code):
        self.guest_exit_code=code
        if len(self.events)<32:self.events.append({'operation':'ExitProcess','exit_code':code})
        self.engine.stop();return 0

    @staticmethod
    def _message_text(uc,address,wide):
        """Bounded guest-only diagnostics; capture failures cannot change control flow."""
        if not address:return {'value':'','truncated':False}
        data=bytearray();width=2 if wide else 1
        try:
            for offset in range(256):
                item=bytes(uc.mem_read(address+offset*width,width))
                if len(item)!=width:return {'capture':'unreadable'}
                if item==bytes(width):break
                data.extend(item)
            else:
                return {'value':data.decode('utf-16le' if wide else 'cp1252','replace'),'truncated':True}
            return {'value':data.decode('utf-16le' if wide else 'cp1252','replace'),'truncated':False}
        except Exception:return {'capture':'unreadable'}

    def message(self,uc,owner,text,title,flags,wide=False):
        buttons=flags&15
        if buttons==0:response=1
        elif buttons in {1,3,5,6}:response=2
        elif buttons==2:response=3
        elif buttons==4:response=6 if self.yesno_answer=="yes" else 7
        else:self.reject('MessageBoxA','Unsupported button set')
        if buttons and 'MessageBox response selected by noninteractive model' not in self.warnings:
            self.warnings.append('MessageBox response selected by noninteractive model')
        self.last_message={'operation':'MessageBoxW' if wide else 'MessageBoxA',
            'text':self._message_text(uc,text,wide),'title':self._message_text(uc,title,wide),'flags':flags}
        if len(self.events)<32:self.events.append({'operation':'MessageBoxW' if wide else 'MessageBoxA','response':response})
        return response

    def install(self,mapping):
        def dispatch(address,name,uc,esp,log):
            if getattr(self.engine,'_unpacker_core_import_entries',None):
                from unpacker.core_import_bindings import call_matches_binding
                if not call_matches_binding(self.engine,address,name,uc):
                    self.reject(name,'Modified core import entry/interposition is unsupported')
            if self.callbacks.address is not None and address==self.callbacks.address:
                from unicorn.x86_const import UC_X86_REG_EAX
                return self.callbacks.resume(uc,esp,uc.reg_read(UC_X86_REG_EAX))
            if name in {'_initterm','_initterm_e'}:
                stack=struct.unpack('<III',uc.mem_read(esp,12))
                return self.callbacks.start(uc,esp,stack[1],stack[2],name=='_initterm_e')
            if self.desktop_modules is not None:
                response=self.desktop_modules.dispatch(address,name,uc,esp,log)
                if response is not None:return response
            if name in self.functions:
                specification=self.functions[name];count,function=specification[:2]
                convention=specification[2] if len(specification)==3 else 'stdcall'
                cdecl=convention in {'cdecl','varargs'}
                stack=struct.unpack('<'+'I'*(count+1),uc.mem_read(esp,4*(count+1)))
                self.current_call={'name':str(name)[:128],'arguments':list(stack[1:])}
                if name in {'VirtualProtect','VirtualProtectEx'} and getattr(self.engine,'_unpacker_inside_emulation',False):
                    self.protection.return_state=(stack[0],esp+4*(count+1))
                try:value=function(uc,*stack[1:],esp+4*(count+1)) if convention=='varargs' else function(uc,*stack[1:])
                finally:
                    self.current_call=None
                    self.protection.return_state=None
                new_esp=esp if cdecl else esp+4*count
                uc.mem_write(new_esp,struct.pack('<I',stack[0]));return value,new_esp
            if name not in mapping:
                # The signature is unknown: preserve raw stack words as evidence,
                # never label them as verified arguments or invent a return value.
                words=[]
                for index in range(6):
                    try:
                        raw=bytes(uc.mem_read(esp+4+index*4,4))
                        if len(raw)!=4:break
                        words.append(struct.unpack('<I',raw)[0])
                    except Exception:break
                self.current_call={'name':str(name)[:128],'stack_words':words,'signature':'unknown'}
                try:self.reject(name,'API semantics are not implemented')
                finally:self.current_call=None
            return mapping[name](self.handler,uc,esp,log)
        self.handler.apicall=dispatch
