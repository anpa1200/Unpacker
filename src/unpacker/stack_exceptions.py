"""Bounded x86 stack exception delivery, with guest-executed handlers.

Behavioral references: pinned Wine i386 dispatch/exception tests, and Microsoft's
exception-dispatch model. This is an independent implementation, not native
Windows code. PECompact retains the separate first-handler AV profile.
"""
import struct
from .guest_seh import AccessViolationDispatcher,UnhandledGuestException


class StackExceptionDispatcher(AccessViolationDispatcher):
    CONTEXT_FLAGS=0x10017
    DEBUG_REGISTERS={'DR0':4,'DR1':8,'DR2':12,'DR3':16,'DR6':20,'DR7':24}
    MAX_FAULTS=64
    MAX_DEPTH=8
    MAX_SEARCH=32
    requires_instruction_observation=True

    def __init__(self,engine,*,access_violations=False):
        self.levels=[];self.slots=[];self.pending_transfer=None;self.guard_history=[]
        super().__init__(engine,access_violations=access_violations,software_traps=True,null_page_guard=False)
        self.debug_state={name:self.uc.reg_read(self.register(name)) for name in self.DEBUG_REGISTERS}
        self.breakpoint_addresses={};self.resume_rf=False;self.has_instruction_state=False;self.divide_boundary=None

    def _head(self):return struct.unpack('<I',self.uc.mem_read(self.engine.TEB_BASE,4))[0]
    def _write_head(self,value):self.uc.mem_write(self.engine.TEB_BASE,struct.pack('<I',value))

    def _slot(self,index):
        if index<len(self.slots):return self.slots[index]
        regions=list(self.uc.mem_regions())
        for address in range(0x7e000000,0x7e010000,8192):
            if not any(lo<address+8192 and address<=hi for lo,hi,_ in regions):
                self.uc.mem_map(address,4096,5);self.uc.mem_write(address,b'\x90\xc3'+bytes(14)+b'\x0f\x0b')
                self.uc.mem_map(address+4096,4096,3)
                self.engine.apicall_handler.hooks[address]=self.RETURN_NAME
                self.slots.append(address);return address
        self.reject('No free bounded guest exception workspace')

    def _frame(self,frame):
        lower=max(4096,self.engine.STACK_ADDR);upper=self.engine.STACK_ADDR+self.engine.STACK_SIZE
        if frame%4 or not lower<=frame or frame+8>upper or not self._mapped(frame,8,1):
            self.reject('Registered SEH frame is outside the supported guest stack')
        following,handler=struct.unpack('<II',self.uc.mem_read(frame,8))
        if following!=0xffffffff and not frame<following<=upper-8:self.reject('Registered SEH chain order is invalid')
        if handler<4096 or not self._mapped(handler,1,4):self.reject('Registered SEH handler is not mapped executable guest memory')
        return following,handler

    def _guard(self,frame):
        for level in reversed(self.levels):
            if frame==level.get('guard'):
                actual=bytes(self.uc.mem_read(frame,12))
                if actual!=level['guard_bytes']:self.reject('Guest changed a live dispatcher guard frame')
                return level
        return None

    def _chain(self,head):
        result=[];frame=head
        while frame!=0xffffffff:
            if len(result)>=self.MAX_SEARCH:self.reject('Guest exception frame-search budget exceeded')
            result.append(frame);frame,_=self._frame(frame)
        return result

    def _retire_nonlocal(self,address):
        # A handler may deliberately restore its registration/stack and branch
        # out, without returning through a CONTEXT. Retire only when both its
        # guard is absent from the validated chain and ESP has left that stack.
        while self.levels:
            level=self.levels[-1]
            if self.uc.reg_read(self.register('ESP'))<=level['guard']:break
            chain=self._chain(self._head())
            if level['guard'] in chain:break
            level['event'].update(status='guest_nonlocal_exit',continuation_eip=address)
            self.guard_history.append({'kind':'nonlocal_exit','frame':level['frame'],'pc':address})
            self.levels.pop();self._select()
    def observe_instruction(self,address,size):
        self._retire_nonlocal(address)
        # Pinned Unicorn retains internal old_exception after #DE. Restore the
        # full pre-fault CPU state rather than relabel #DF or skip instructions.
        self.divide_boundary=None
        if 2<=size<=15:
            first=bytes(self.uc.mem_read(address,1))[0]
            if first in {0xf6,0xf7,0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf2,0xf3}:
                raw=bytes(self.uc.mem_read(address,size));index=0
                while index<len(raw) and raw[index] in {0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf2,0xf3}:index+=1
                if index+1<len(raw) and raw[index] in {0xf6,0xf7} and (raw[index+1]>>3)&7 in {6,7}:
                    self.divide_boundary=(address,raw,self.uc.context_save())
        if self.resume_rf:
            # Consume RF at the next instruction boundary after suppressing its
            # execution breakpoint. The instruction still executes normally.
            self.uc.reg_write(self.register('EFLAGS'),self.uc.reg_read(self.register('EFLAGS'))&~0x10000)
            self.resume_rf=False;self.has_instruction_state=bool(self.breakpoint_addresses)
            return False
        match=self.breakpoint_addresses.get(address,0)
        if match:
            self.software_pending={'kind':'execution_breakpoint','code':0x80000004,'origin':address,
              'context_eip':address,'exception_address':address,'debug_status':(self.debug_state['DR6']&~0x4000)|match}
            self.engine.stop();return True
        return False

    def _configure_debug(self,values):
        control=values['DR7']
        if control&~0xffff07ff:self.reject('Reserved/general-detect DR7 control is unsupported')
        addresses={}
        for index in range(4):
            if control>>(index*2)&3:
                if control>>(16+index*4)&15:
                    self.reject('Only one-byte execution breakpoints are implemented; data/IO breakpoints unsupported')
                address=values['DR'+str(index)]
                addresses[address]=addresses.get(address,0)|(1<<index)
        self.debug_state={name:values[name] for name in self.DEBUG_REGISTERS}
        self.breakpoint_addresses=addresses;self.has_instruction_state=bool(addresses) or self.resume_rf

    def _select(self):
        self.active=bool(self.levels);self.engine._unpacker_seh_active=self.active
        if not self.levels:return
        for name in ['arena','context_address','record_address','saved','saved_context','call_stack','current_kind']:
            if name in self.levels[-1]:setattr(self,name,self.levels[-1][name])

    def _interrupt(self,uc,number,user_data):
        try:
            self._retire_nonlocal(uc.reg_read(self.register('EIP')))
            address=uc.reg_read(self.register('EIP'));opcode=bytes(uc.mem_read(address,2))
            if number==3 and opcode[:1]==b'\xcc':
                event={'kind':'int3','code':0x80000003,'origin':address,'context_eip':address,'exception_address':address}
            elif number==1:
                from unicorn.x86_const import UC_X86_REG_DR6,UC_X86_REG_DR7
                status=uc.reg_read(UC_X86_REG_DR6);control=uc.reg_read(UC_X86_REG_DR7)
                # Pinned Unicorn marks BS for real TF stepping, including POPFD
                # that clears TF. Explicit CD01 does not set it. Consume BS so
                # stale status cannot make a later software interrupt look valid.
                last=getattr(self.engine,'_unpacker_last_address',address)
                previous=bytes(uc.mem_read(last,2))
                if previous==b'\xcd\x01' or not status&0x4000 or status&0xa000 or control&0x2000:
                    self.reject('Debug interrupt is outside the TF-only single-step profile')
                uc.reg_write(UC_X86_REG_DR6,status&~0x4000)
                event={'kind':'single_step','code':0x80000004,'origin':last,'context_eip':address,'exception_address':address,'debug_status':self.debug_state['DR6']|0x4000}
            elif number==0:
                code=bytearray()
                for offset in range(15):
                    try:code.extend(uc.mem_read(address+offset,1))
                    except Exception:break
                code=bytes(code);index=0
                while index<len(code) and code[index] in {0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf2,0xf3}:index+=1
                if index+1>=len(code) or code[index] not in {0xf6,0xf7} or (code[index+1]>>3)&7 not in {6,7}:
                    self.reject('Divide vector is outside the DIV/IDIV exception profile')
                boundary=self.divide_boundary
                if boundary is None or boundary[0]!=address or code[:len(boundary[1])]!=boundary[1]:
                    self.reject('CPU divide fault lacks an authenticated pre-instruction context')
                self.uc.context_restore(boundary[2]);self.divide_boundary=None
                event={'kind':'divide_error','code':0xc0000094,'origin':address,'context_eip':address,'exception_address':address}
            else:self.reject('Interrupt vector/encoding is outside the bounded x86 exception profile')
            self.software_pending=event
        except Exception as exc:
            if self.unsupported is None:self.unsupported=f'Interrupt capture failed: {type(exc).__name__}'
        uc.emu_stop()

    def capture_cpu_error(self,error):
        from unicorn import UC_ERR_INSN_INVALID
        if error.errno!=UC_ERR_INSN_INVALID:return False
        address=self.uc.reg_read(self.register('EIP'))
        code=bytearray()
        for offset in range(15):
            try:code.extend(self.uc.mem_read(address+offset,1))
            except Exception:break
        code=bytes(code)
        if not code:return False
        if code[:1]==b'\xf1':
            event={'kind':'icebp','code':0x80000004,'origin':address,'context_eip':address+1,'exception_address':address+1}
        else:
            index=0
            while index<len(code) and code[index] in {0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf2,0xf3}:index+=1
            invalid_lea=index+1<len(code) and code[index]==0x8d and code[index+1]&0xc0==0xc0
            explicit_ud2=code[index:index+2]==b'\x0f\x0b'
            if not (invalid_lea or explicit_ud2):return False
            event={'kind':'illegal_instruction','code':0xc000001d,'origin':address,'context_eip':address,'exception_address':address}
        self._retire_nonlocal(address);self.software_pending=event
        return True

    def arm(self):
        if self.unsupported:return None
        software=self.software_pending;self.software_pending=None
        if software is None:
            from unicorn import UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED,UC_MEM_READ_PROT,UC_MEM_WRITE_PROT
            fault=getattr(self.engine,'_unpacker_memory_fault',None)
            if not self.access_violations or not fault or fault.get('access') not in {UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED,UC_MEM_READ_PROT,UC_MEM_WRITE_PROT}:return None
            if not 0<=fault['address']<2**32 or not 0<fault['size']<=16:self.reject('Access-violation fault range is outside the PE32 profile')
            pc=self.uc.reg_read(self.register('EIP'));self._validate_av_origin(pc)
            software={'kind':'access_violation','code':0xc0000005,'origin':pc,'context_eip':pc,'exception_address':pc,
                'fault_address':fault['address'],'fault_operation':int(fault['access'] in {UC_MEM_WRITE_UNMAPPED,UC_MEM_WRITE_PROT})}
        self._retire_nonlocal(software['origin'])
        if len(self.events)>=self.MAX_FAULTS:self.reject('Guest exception event budget exceeded')
        if len(self.levels)>=self.MAX_DEPTH:self.reject('Guest exception nesting budget exceeded')
        head=self._head()
        if head==0xffffffff:
            self.events.append({**software,'status':'unhandled_no_registered_handler'})
            raise UnhandledGuestException(f"Unhandled guest exception {software['code']:#x}: no registered stack handler")
        self._chain(head)
        arena=self._slot(len(self.levels));saved={name:self.uc.reg_read(self.register(name)) for name in self.REGISTERS|self.SEGMENTS}
        saved['EIP']=software['context_eip']
        if software['kind'] in {'single_step','icebp'}:saved['EFLAGS']&=~0x100
        if software['kind'] in {'execution_breakpoint','divide_error','illegal_instruction','access_violation'}:saved['EFLAGS']|=0x10000
        saved_debug=dict(self.debug_state)
        if 'debug_status' in software:saved_debug['DR6']=software['debug_status']
        context=bytearray(0x2cc);struct.pack_into('<I',context,0,self.CONTEXT_FLAGS)
        for name,offset in (self.REGISTERS|self.SEGMENTS).items():struct.pack_into('<I',context,offset,saved[name])
        context_address=arena+4096;record_address=arena+0x1400
        for name,offset in self.DEBUG_REGISTERS.items():struct.pack_into('<I',context,offset,saved_debug[name])
        self.uc.mem_write(context_address,bytes(context))
        record=bytearray(80);parameters=3 if software['kind']=='int3' else (2 if software['kind']=='access_violation' else 0)
        # Hardware records start with no associated record, as in the pinned
        # signal handler. Nested host metadata does not invent a guest pointer.
        struct.pack_into('<5I',record,0,software['code'],0,0,software['exception_address'],parameters)
        if software['kind']=='access_violation':struct.pack_into('<II',record,20,software['fault_operation'],software['fault_address'])
        self.uc.mem_write(record_address,bytes(record))
        event={**software,'fault_eip':saved['EIP'],'depth':len(self.levels)+1,'status':'handler_pending','handlers':[]}
        self.events.append(event)
        level={'arena':arena,'context_address':context_address,'record_address':record_address,
               'saved':saved,'saved_debug':saved_debug,'saved_context':self.uc.context_save(),'current_kind':software['kind'],
               'event':event,'nested_boundary':None,'searched':0}
        self.levels.append(level)
        self._select()
        if software['kind']=='access_violation':self.engine._unpacker_memory_fault=None
        return self._call(level,head)

    def _call(self,level,frame):
        while frame!=0xffffffff:
            level['searched']+=1
            if level['searched']>self.MAX_SEARCH:self.reject('Guest exception frame-search budget exceeded')
            following,handler=self._frame(frame);guard=self._guard(frame)
            if guard is not None:
                # The dispatcher guard has the documented raise-handler
                # disposition: designate the faulting frame and continue search.
                designated=guard['frame'];level['nested_boundary']=max(level['nested_boundary'] or 0,designated)
                self._record_flags(level,self._record_flags(level)|0x10)
                level['event']['handlers'].append({'frame':frame,'disposition':2,'dispatcher_guard':True,'designated_frame':designated})
                frame=following;continue
            level['frame']=frame;level['following']=following
            lower=max(4096,self.engine.STACK_ADDR)
            guard_address=(level['saved']['ESP']-0x100)&~15
            stack=guard_address-20
            if stack<lower or not self._mapped(stack,32,2):self.reject('Insufficient mapped guest stack for exception call')
            previous_head=self._head();guard_bytes=struct.pack('<III',previous_head,level['arena']+16,frame)
            self.uc.mem_write(guard_address,guard_bytes)
            self.uc.mem_write(level['arena']+0x1480,bytes(4))
            level.update(guard=guard_address,guard_bytes=guard_bytes,previous_head=previous_head,
                         call_stack=stack,dispatcher_pointer=level['arena']+0x1480,dispatcher_written=0)
            self.uc.mem_write(stack,struct.pack('<5I',level['arena'],level['record_address'],frame,level['context_address'],level['dispatcher_pointer']))
            self._write_head(guard_address)
            self.uc.reg_write(self.register('ESP'),stack)
            self.uc.reg_write(self.register('EFLAGS'),level['saved']['EFLAGS']&~(0x100|0x400|0x10000|0x40000))
            level['event'].update(frame=frame,handler=handler)
            self._select();return handler
        raise UnhandledGuestException('No stack handler accepted the guest exception')

    def _record_flags(self,level,value=None):
        address=level['record_address']+4
        if value is None:return struct.unpack('<I',self.uc.mem_read(address,4))[0]
        self.uc.mem_write(address,struct.pack('<I',value))

    def complete(self,esp):
        if not self.levels:self.reject('Exception return has no live dispatcher context')
        level=self.levels[-1]
        if esp!=level['call_stack']+4:self.reject('Unsupported SEH return stack or calling convention')
        if self._head()!=level['guard']:self.reject('Handler returned with outstanding or altered registrations')
        self._guard(level['guard']);self._write_head(level['previous_head'])
        disposition=self.uc.reg_read(self.register('EAX'))
        level['event']['disposition']=disposition
        level['event']['handlers'].append({'frame':level['frame'],'disposition':disposition})
        if level['frame']==level['nested_boundary']:
            level['nested_boundary']=None;self._record_flags(level,self._record_flags(level)&~0x10)
        if disposition in {1,2}:
            if disposition==2:
                if level['dispatcher_written']!=15:self.reject('Nested disposition lacks a complete dispatcher output')
                designated=struct.unpack('<I',self.uc.mem_read(level['dispatcher_pointer'],4))[0]
                chain=self._chain(level['frame'])
                if designated not in chain:self.reject('Nested disposition designated a frame outside its chain')
                level['nested_boundary']=max(level['nested_boundary'] or 0,designated)
                self._record_flags(level,self._record_flags(level)|0x10)
            following,_=self._frame(level['frame'])
            self.pending_transfer=('search',level,following);self.engine.stop();return None,esp
        if disposition!=0:self.reject('Unwind/collided or invalid exception disposition is unsupported')
        if self._record_flags(level)&1:self.reject('Noncontinuable exception cannot resume')
        context=bytes(self.uc.mem_read(level['context_address'],0x2cc))
        if struct.unpack_from('<I',context,0)[0]!=self.CONTEXT_FLAGS:self.reject('Unsupported SEH context flags')
        values={name:struct.unpack_from('<I',context,offset)[0] for name,offset in (self.REGISTERS|self.SEGMENTS).items()}
        if any(values[name]!=level['saved'][name] for name in self.SEGMENTS):self.reject('SEH segment-register changes are unsupported')
        if (values['EFLAGS']^level['saved']['EFLAGS'])&0x23200:self.reject('SEH privileged flag changes are unsupported')
        if not self._mapped(values['EIP'],1,4) or not self._mapped(values['ESP']-4,4,2):self.reject('SEH continuation is outside mapped guest code/stack')
        values.update({name:struct.unpack_from('<I',context,offset)[0] for name,offset in self.DEBUG_REGISTERS.items()})
        self._configure_debug(values)
        level['event'].update(status='continue_execution',continuation_eip=values['EIP'],debug_registers={name:values[name] for name in self.DEBUG_REGISTERS})
        self.levels.pop();self._select();self.pending_transfer=('resume',level,values)
        self.engine.stop();return None,esp

    def take_resume(self):
        if self.pending_transfer is None:return None
        kind,level,value=self.pending_transfer;self.pending_transfer=None
        self.uc.context_restore(level['saved_context'])
        registers=level['saved'] if kind=='search' else value
        for name in self.REGISTERS:self.uc.reg_write(self.register(name),registers[name])
        self.engine._unpacker_memory_fault=None
        if kind=='search':return self._call(level,value)
        for name in self.DEBUG_REGISTERS:self.uc.reg_write(self.register(name),value[name])
        self.resume_rf=bool(value['EFLAGS']&0x10000);self.has_instruction_state=bool(self.breakpoint_addresses) or self.resume_rf
        self.engine._unpacker_seh_completed=True
        if hasattr(self.engine,'sample'):self.engine.sample._unpacker_seh_completed=True
        return value['EIP']

    def check_context_access(self,address,size,writing=False):
        if not self.active:return
        if address<4096 and address+size>0:self.reject('Null exception-context dereference is unsupported')
        for level in self.levels:
            begin=level['context_address'];record=level['record_address']
            if level['current_kind']=='int3' and address<record+32 and record+24<address+size:self.reject('Opaque breakpoint exception parameters are not modeled')
            if any(address<begin+upper and begin+lower<address+size for lower,upper in [(0x1c,0x8c),(0xcc,0x2cc)]):self.reject('Unsupported debug/floating-point SEH context access')
            pointer=level.get('dispatcher_pointer')
            if pointer is not None and address<pointer+4 and pointer<address+size:
                mask=sum(1<<i for i in range(4) if address<=pointer+i<address+size)
                if writing:level['dispatcher_written']|=mask
                elif level['dispatcher_written']&mask!=mask:self.reject('Dispatcher output read before guest initialization')

    def facts(self):
        return {'profile':'bounded_x86_stack_dispatch','scope':getattr(self,'profile_scope','generic_PE32'),'max_faults':self.MAX_FAULTS,'max_depth':self.MAX_DEPTH,
          'max_search':self.MAX_SEARCH,'events':self.events,'unsupported':self.unsupported,'pending_handler':self.active,
          'allocated_workspace_bytes':len(self.slots)*8192,'live_depth':len(self.levels),'nonlocal_exits':self.guard_history,
          'single_step':'TF; execution_breakpoints_with_RF','debug_registers':self.debug_state,'data_io_breakpoints':'unsupported','search':'bounded_frame_chain','unwind_vectored_dispatch':'not_implemented','access_violations':self.access_violations}
