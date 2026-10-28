"""PE32 CRT control-word mapping to real guest x87/SSE registers."""


class FloatingPoint:
    # CRT abstract mask bit -> x87 hardware bit; SSE mask bits are shifted by 7.
    EXCEPTIONS=[(0x10,0),(0x80000,1),(8,2),(4,3),(2,4),(1,5)]

    def __init__(self,model):
        self.model=model
        uc=getattr(model.engine,'uc',None)
        if uc is not None and hasattr(uc,'reg_write'):
            from unicorn.x86_const import UC_X86_REG_FPCW,UC_X86_REG_MXCSR
            uc.reg_write(UC_X86_REG_FPCW,0x027f);uc.reg_write(UC_X86_REG_MXCSR,0x1f80)

    def control(self,uc,new,mask,denormal=False):
        from unicorn.x86_const import UC_X86_REG_FPCW,UC_X86_REG_MXCSR
        if mask&~0x030f031f:self.model.reject('_controlfp','Unsupported floating-point control mask')
        if not denormal:mask&=~0x80000
        cw=uc.reg_read(UC_X86_REG_FPCW);sse=uc.reg_read(UC_X86_REG_MXCSR)
        for abstract,hardware in self.EXCEPTIONS:
            if mask&abstract:
                cw=(cw&~(1<<hardware))|((1<<hardware) if new&abstract else 0)
                sse=(sse&~(1<<(hardware+7)))|((1<<(hardware+7)) if new&abstract else 0)
        if mask&0x300:
            rounding=((cw>>2)&0x300&~mask)|(new&mask&0x300)
            cw=(cw&~0xc00)|(rounding<<2);sse=(sse&~0x6000)|(rounding<<5)
        if mask&0x30000:
            precision={3:0,2:0x10000,0:0x20000}.get((cw>>8)&3)
            if precision is None:self.model.reject('_controlfp','Reserved guest x87 precision state')
            precision=(precision&~mask)|(new&mask&0x30000)
            if precision not in {0,0x10000,0x20000}:self.model.reject('_controlfp','Reserved x87 precision selection')
            cw=(cw&~0x300)|({0:3,0x10000:2,0x20000:0}[precision]<<8)
        if mask&0x40000:cw=(cw&~0x1000)|(0x1000 if new&0x40000 else 0)
        uc.reg_write(UC_X86_REG_FPCW,cw);uc.reg_write(UC_X86_REG_MXCSR,sse)
        result=sum(abstract for abstract,bit in self.EXCEPTIONS if cw&(1<<bit))
        result|=((cw>>2)&0x300)|({3:0,2:0x10000,0:0x20000}.get((cw>>8)&3,0))
        if cw&0x1000:result|=0x40000
        if (cw&0x3f)!=((sse>>7)&0x3f) or ((cw>>10)&3)!=((sse>>13)&3):result|=0x80000000
        return result
