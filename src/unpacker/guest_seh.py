"""Bounded PE32 guest exception delivery through the existing CPU loop.

PECompact keeps its first-handler access-violation profile. Generic PE32 can
select short INT3/ICEBP delivery; search, unwind, nested exceptions and absent
context payloads remain explicitly unsupported. No native callback is used.
"""
import struct


class UnsupportedDispatch(RuntimeError):
    pass


class UnhandledGuestException(RuntimeError):
    pass


class _ExceptionMemory:
    """Keep modeled API copies subject to the same active-context guards."""
    def __init__(self,dispatcher,uc):self.dispatcher=dispatcher;self.uc=uc
    def mem_read(self,address,size):
        self.dispatcher.check_context_access(address,size);return self.uc.mem_read(address,size)
    def mem_write(self,address,data):
        self.dispatcher.check_context_access(address,len(data),writing=True);return self.uc.mem_write(address,data)
    def __getattr__(self,name):return getattr(self.uc,name)


class AccessViolationDispatcher:
    RETURN_NAME='<unpacker:seh-return>'
    MAX_FAULTS=8
    CONTEXT_FLAGS=0x10007
    REGISTERS={'EDI':0x9c,'ESI':0xa0,'EBX':0xa4,'EDX':0xa8,'ECX':0xac,
               'EAX':0xb0,'EBP':0xb4,'EIP':0xb8,'EFLAGS':0xc0,'ESP':0xc4}
    SEGMENTS={'GS':0x8c,'FS':0x90,'ES':0x94,'DS':0x98,'CS':0xbc,'SS':0xc8}

    def __init__(self,engine,*,access_violations=True,software_traps=False,null_page_guard=True):
        from unicorn import x86_const
        if any(type(value) is not bool for value in [access_violations,software_traps,null_page_guard]):
            raise ValueError('Exception profile switches must be boolean')
        self.engine=engine;self.uc=engine.uc;self.constants=x86_const
        self.access_violations=access_violations;self.software_traps=software_traps;self.software_pending=None
        self.events=[];self.active=False;self.pending=None;self.unsupported=None
        self.arena=None;self.saved=None;self.saved_context=None;self.call_stack=None
        regions=list(self.uc.mem_regions())
        if null_page_guard and any(lo==0 and hi==engine.STACK_SIZE-1 for lo,hi,_ in regions) and engine.STACK_ADDR==0:
            # Unicorn 1 can allocate a second large region while splitting an
            # existing mapping. Rebuild the small owned stack without page zero
            # to retain the existing process address-space limit.
            stack=bytes(self.uc.mem_read(4096,engine.STACK_SIZE-4096))
            self.uc.mem_unmap(0,engine.STACK_SIZE)
            self.uc.mem_map(4096,engine.STACK_SIZE-4096)
            self.uc.mem_write(4096,stack)
        elif null_page_guard and any(lo==0 and hi>=4095 for lo,hi,_ in regions):
            self.reject('Unsupported zero-page mapping outside the owned stack')
        if access_violations:
            from unicorn import UC_HOOK_MEM_READ_PROT,UC_HOOK_MEM_WRITE_PROT
            def protected_fault(uc,access,address,size,value,user):
                engine._unpacker_memory_fault={'access':access,'address':address,'size':size}
                return False  # Preserve protection; arm only after the CPU stops.
            self.protected_fault_hook=self.uc.hook_add(UC_HOOK_MEM_READ_PROT|UC_HOOK_MEM_WRITE_PROT,protected_fault)
        self.null_page_guard=null_page_guard
        if null_page_guard and engine.STACK_ADDR==0:self.uc.mem_write(engine.TEB_BASE+8,struct.pack('<I',4096))
        previous=engine.apicall_handler.apicall
        def dispatch(address,name,uc,esp,log):
            if self.arena is not None and address==self.arena and name==self.RETURN_NAME:
                return self.complete(esp)
            return previous(address,name,_ExceptionMemory(self,uc) if self.active else uc,esp,log)
        engine.apicall_handler.apicall=dispatch
        if software_traps:
            from unicorn import UC_HOOK_INTR
            self.interrupt_hook=self.uc.hook_add(UC_HOOK_INTR,self._interrupt)

    def _interrupt(self,uc,number,user_data):
        # This callback never swallows another interrupt. The pinned Unicorn
        # reports EIP at INT3 here, then advances it after emu_stop returns.
        try:
            address=uc.reg_read(self.register('EIP'))
            if number!=3 or bytes(uc.mem_read(address,1))!=b'\xcc':
                self.reject('Interrupt vector/encoding is outside the short INT3/ICEBP profile')
            if self.active:self.reject('Nested guest software traps are not supported')
            self.software_pending={'kind':'int3','code':0x80000003,'origin':address,
                                   'context_eip':address,'exception_address':address}
        except Exception as exc:
            if self.unsupported is None:self.unsupported=f'Interrupt capture failed: {type(exc).__name__}'
        uc.emu_stop()

    def capture_cpu_error(self,error):
        """Recognize only the missing F1 instruction, never arbitrary bad code."""
        from unicorn import UC_ERR_INSN_INVALID
        if not self.software_traps or error.errno!=UC_ERR_INSN_INVALID:return False
        address=self.uc.reg_read(self.register('EIP'))
        try:opcode=bytes(self.uc.mem_read(address,1))
        except Exception:return False
        if opcode!=b'\xf1':return False
        if self.active:self.reject('Nested guest software traps are not supported')
        self.software_pending={'kind':'icebp','code':0x80000004,'origin':address,
                               'context_eip':address+1,'exception_address':address+1}
        return True

    def _validate_av_origin(self,address):
        primary=getattr(getattr(self.engine,'sample',None),'BASE_ADDR',None)
        for row in getattr(self.engine,'_unpacker_loader_lists',{}).get('module_images',[]):
            if row['base']!=primary and row['base']<=address<row['base']+row['image_size']:
                self.reject('Access violation inside unmodeled native DLL code is outside guest-image exception delivery')

    def register(self,name):return getattr(self.constants,'UC_X86_REG_'+name)

    def reject(self,reason):
        self.unsupported=reason;self.engine.stop()
        raise UnsupportedDispatch(reason)

    def _mapped(self,address,size,permission):
        return any(lo<=address and address+size-1<=hi and flags&permission
                   for lo,hi,flags in self.uc.mem_regions())

    def _arena(self):
        if self.arena is not None:return
        regions=list(self.uc.mem_regions())
        for address in range(0x7e000000,0x7e010000,8192):
            if not any(lo<address+8192 and address<=hi for lo,hi,_ in regions):
                self.uc.mem_map(address,4096,5);self.uc.mem_write(address,b'\x90\xc3')
                self.uc.mem_map(address+4096,4096,3)
                self.arena=address
                self.engine.apicall_handler.hooks[address]=self.RETURN_NAME
                return
        self.reject('No free bounded guest SEH workspace')

    def arm(self):
        """Called after emu_start stopped with a recorded read/write fault."""
        from unicorn import UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED,UC_MEM_READ_PROT,UC_MEM_WRITE_PROT
        if self.unsupported:return None
        software=self.software_pending;self.software_pending=None
        fault=getattr(self.engine,'_unpacker_memory_fault',None)
        if software is None and (not self.access_violations or not fault or fault.get('access') not in {UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED,UC_MEM_READ_PROT,UC_MEM_WRITE_PROT}):return None
        if software is None:self._validate_av_origin(self.uc.reg_read(self.register('EIP')))
        if self.active:self.reject('Nested guest access violations are not supported')
        if len(self.events)>=self.MAX_FAULTS:self.reject('Guest SEH fault budget exceeded')
        frame=struct.unpack('<I',self.uc.mem_read(self.engine.TEB_BASE,4))[0]
        if frame==0xffffffff:
            if software is not None:
                self.events.append({**software,'status':'unhandled_no_registered_handler'})
                raise UnhandledGuestException(f"Unhandled guest software exception {software['code']:#x}: no registered stack handler")
            return None
        lower=max(4096,self.engine.STACK_ADDR);upper=self.engine.STACK_ADDR+self.engine.STACK_SIZE
        if frame%4 or not lower<=frame or frame+8>upper or not self._mapped(frame,8,1):
            self.reject('Registered SEH frame is outside the supported guest stack')
        following,handler=struct.unpack('<II',self.uc.mem_read(frame,8))
        if following!=0xffffffff and not frame<following<=upper-8:
            self.reject('Registered SEH chain order is invalid')
        if handler<4096 or not self._mapped(handler,1,4):self.reject('Registered SEH handler is not mapped executable guest memory')
        self._arena()
        context=bytearray(0x2cc);struct.pack_into('<I',context,0,self.CONTEXT_FLAGS)
        self.saved={name:self.uc.reg_read(self.register(name)) for name in self.REGISTERS|self.SEGMENTS}
        self.saved_context=self.uc.context_save()
        self.current_kind=software['kind'] if software is not None else 'access_violation'
        if software is not None:self.saved['EIP']=software['context_eip']
        for name,offset in (self.REGISTERS|self.SEGMENTS).items():struct.pack_into('<I',context,offset,self.saved[name])
        self.context_address=self.arena+0x1000;record_address=self.arena+0x1400
        self.record_address=record_address
        self.uc.mem_write(self.context_address,bytes(context))
        record=bytearray(80)
        writing=software is None and fault['access'] in {UC_MEM_WRITE_UNMAPPED,UC_MEM_WRITE_PROT}
        code=software['code'] if software is not None else 0xc0000005
        exception_address=software['exception_address'] if software is not None else self.saved['EIP']
        parameters=(3 if software['kind']=='int3' else 0) if software is not None else 2
        struct.pack_into('<5I',record,0,code,0,0,exception_address,parameters)
        if software is None:struct.pack_into('<II',record,20,int(writing),fault['address'])
        self.uc.mem_write(record_address,bytes(record))
        stack=(self.saved['ESP']-0x100)&~15;stack-=20
        if stack<lower or not self._mapped(stack,20,2):self.reject('Insufficient mapped guest stack for SEH call')
        # DispatcherContext is outside this profile; zero is never dereferenced
        # by the validated handler. Any nested fault remains unsupported.
        self.uc.mem_write(stack,struct.pack('<5I',self.arena,record_address,frame,self.context_address,0))
        self.call_stack=stack;self.active=True
        self.engine._unpacker_seh_active=True
        event={'code':code,'exception_address':exception_address,'fault_eip':self.saved['EIP'],
               'frame':frame,'handler':handler,'status':'handler_pending','kind':self.current_kind}
        if software is None:event.update(address=fault['address'],access='write' if writing else 'read')
        else:event['instruction_address']=software['origin']
        self.events.append(event)
        self.engine._unpacker_memory_fault=None
        self.uc.reg_write(self.register('ESP'),stack)
        # Windows enters its exception dispatcher with TF/DF/AC cleared. Keep
        # the fault flags in CONTEXT so a validated continuation restores them.
        self.uc.reg_write(self.register('EFLAGS'),self.saved['EFLAGS']&~(0x100|0x400|0x40000))
        return handler

    def complete(self,esp):
        if not self.active or esp!=self.call_stack+4:self.reject('Unsupported SEH return stack or calling convention')
        disposition=self.uc.reg_read(self.register('EAX'))
        self.events[-1]['disposition']=disposition
        if disposition!=0:self.reject('Only SEH ContinueExecution is supported; search/unwind is not implemented')
        context=bytes(self.uc.mem_read(self.context_address,0x2cc))
        if struct.unpack_from('<I',context,0)[0]!=self.CONTEXT_FLAGS:self.reject('Unsupported SEH context flags')
        values={name:struct.unpack_from('<I',context,offset)[0] for name,offset in (self.REGISTERS|self.SEGMENTS).items()}
        if any(values[name]!=self.saved[name] for name in self.SEGMENTS):self.reject('SEH segment-register changes are unsupported')
        if (values['EFLAGS']^self.saved['EFLAGS'])&0x23200:self.reject('SEH privileged flag changes are unsupported')
        if self.current_kind!='access_violation' and (values['EFLAGS']^self.saved['EFLAGS'])&0x100:
            self.reject('Hardware trap-flag transitions are outside the software-trap profile')
        if not self._mapped(values['EIP'],1,4) or not self._mapped(values['ESP']-4,4,2):
            self.reject('SEH continuation is outside mapped guest code/stack')
        self.pending=values;self.active=False;self.engine._unpacker_seh_active=False
        self.events[-1].update(status='continue_execution',continuation_eip=values['EIP'])
        # Resume only after the current emu_start returns, outside the callback.
        self.engine.stop()
        return None,esp

    def take_resume(self):
        if self.pending is None:return None
        values=self.pending;self.pending=None
        # Preserve CPU state not represented by this CONTEXT_FULL profile,
        # including x87/SSE state clobbered while the handler executes.
        self.uc.context_restore(self.saved_context)
        for name in self.REGISTERS:self.uc.reg_write(self.register(name),values[name])
        self.engine._unpacker_memory_fault=None
        self.engine._unpacker_seh_completed=True
        if hasattr(self.engine,'sample'):self.engine.sample._unpacker_seh_completed=True
        return values['EIP']

    def check_context_access(self,address,size,writing=False):
        if not self.active:return
        if not self.null_page_guard and address<4096 and address+size>0:
            self.reject('Null/DispatcherContext dereference is outside the exception profile')
        if self.current_kind=='int3' and address<self.record_address+32 and self.record_address+24<address+size:
            self.reject('Opaque breakpoint exception parameters are not modeled')
        begin=self.context_address
        if any(address<begin+upper and begin+lower<address+size
               for lower,upper in [(4,0x8c),(0xcc,0x2cc)]):
            # Debug/floating-point and reserved context payloads are not supplied
            # by CONTEXT_FULL; model only its declared control/integer fields.
            self.reject('Unsupported debug/floating-point SEH context access')

    def facts(self):
        return {'profile':'pe32_first_handler_continue_execution','scope':'generic_software_traps' if self.software_traps else 'PECompact_only',
            'access_violations':self.access_violations,'software_traps':self.software_traps,
            'null_page_guard':self.null_page_guard,'max_faults':self.MAX_FAULTS,
            'events':self.events,'unsupported':self.unsupported,'pending_handler':self.active,
            'search_unwind_vectored_dispatch':'not_implemented','dispatcher_context':'not_modeled'}
