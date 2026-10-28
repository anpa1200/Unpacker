"""Bounded direct control-flow evidence for absolute PE32 IAT call/jump slots.

Only the handoff's guest image region is examined. Unreachable data, arbitrary
first byte-pattern hits and original programs cannot select a slot here.
"""


def dialog_bindings(observed):
    if len(observed)>128:return set()
    identities={};count=0
    for module,functions in observed.items():
        for name,address in functions:
            count+=1
            if count>4096:return set()
            if type(address) is not int or not 0<address<2**32:return set()
            identities.setdefault(address,set()).add((str(module).split('#')[0].lower(),str(name)))
    allowed={('user32.dll','DialogBoxParamA'),('user32.dll','DialogBoxParamW')}
    return {address for address,names in identities.items() if len(names)==1 and names<=allowed}


def reachable_iat_slots(code,region_base,entry,max_instructions=65536,max_paths=4096,callback_resolver=None):
    from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_JUMP,CS_GRP_RET,CS_GRP_INT,CS_AC_WRITE
    from capstone.x86_const import X86_OP_MEM,X86_OP_IMM,X86_INS_CALL,X86_INS_JMP,X86_INS_HLT,X86_INS_PUSH,X86_REG_ESP,X86_REG_EBP
    if not code or len(code)>32*1024*1024 or not region_base<=entry<region_base+len(code):
        raise ValueError('Invalid bounded code-provenance region')
    if type(max_instructions) is not int or not 1<=max_instructions<=65536 or type(max_paths) is not int or not 1<=max_paths<=4096:
        raise ValueError('Invalid code-provenance budget')
    decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
    pending=[entry];starts=set();occupied=set();slots=set();callbacks=set();complete=True;reason='within_bounded_direct_flow_scope'
    while pending and complete:
        pc=pending.pop();pushes=[]
        while region_base<=pc<region_base+len(code) and pc not in starts:
            if len(starts)>=max_instructions:
                complete=False;reason='instruction_budget_exceeded';break
            offset=pc-region_base
            insn=next(decoder.disasm(code[offset:offset+15],pc,count=1),None)
            if insn is None:
                complete=False;reason='undecodable_reachable_instruction';break
            covered=set(range(pc,pc+insn.size))
            if occupied&covered:
                complete=False;reason='overlapping_reachable_instructions';break
            starts.add(pc);occupied.update(covered)
            operands=insn.operands
            if insn.id==X86_INS_PUSH:
                pushes.append(operands[0].imm&0xffffffff if len(operands)==1 and operands[0].type==X86_OP_IMM else None)
                pushes=pushes[-16:]
            elif insn.id!=X86_INS_CALL:
                if X86_REG_ESP in insn.regs_access()[1] or any(op.type==X86_OP_MEM and op.access&CS_AC_WRITE and op.mem.base in {X86_REG_ESP,X86_REG_EBP} for op in operands):pushes=[]
            if insn.id in {X86_INS_CALL,X86_INS_JMP} and len(operands)==1 and operands[0].type==X86_OP_MEM:
                mem=operands[0].mem
                if not mem.base and not mem.index and not mem.segment:
                    slot=mem.disp&0xffffffff;slots.add(slot)
                    # A literal fourth argument to an observed user32 dialog
                    # API is a documented DLGPROC root, not arbitrary data.
                    prototype=callback_resolver(slot) if callback_resolver and insn.id==X86_INS_CALL else None
                    if prototype and len(pushes)>=prototype[0]:
                        target=pushes[-prototype[1]]
                        if target is not None and region_base<=target<region_base+len(code) and target not in starts:
                            if len(pending)>=max_paths:
                                complete=False;reason='path_budget_exceeded';break
                            callbacks.add(target);pending.append(target)
            control=insn.id==X86_INS_CALL or insn.group(CS_GRP_JUMP)
            if control and len(operands)==1 and operands[0].type==X86_OP_IMM:
                target=operands[0].imm&0xffffffff
                if region_base<=target<region_base+len(code) and target not in starts:
                    if len(pending)>=max_paths:
                        complete=False;reason='path_budget_exceeded';break
                    pending.append(target)
            if insn.id==X86_INS_CALL:pushes=[]
            if insn.id in {X86_INS_JMP,X86_INS_HLT} or insn.group(CS_GRP_RET) or insn.group(CS_GRP_INT):break
            pc+=insn.size
    return {'slots':sorted(slots) if complete else [],'complete':complete,'reason':reason,
            'decoded_instructions':len(starts),'api_callback_roots':len(callbacks),
            'scope':'handoff_region_direct_flow_and_observed_literal_dialog_callbacks'}


def select_referenced_iat(candidates,symbol_count,base,provenance):
    if not provenance['complete']:return None
    referenced=set(provenance['slots'])
    matches=[rva for rva in candidates if any(base+rva+index*4 in referenced for index in range(symbol_count))]
    return matches[0] if len(matches)==1 else None
