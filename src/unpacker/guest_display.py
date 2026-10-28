"""Bounded virtual screen DC handles and immutable display capabilities.

No host screen, window, font or drawing call is made. Other GDI operations
remain unsupported; a returned handle is useful only for modeled operations.
"""


class GuestDisplay:
    MAX_DCS = 64

    def __init__(self,model):
        self.model=model
        self.contexts={}
        self.next_handle=0x73000000
        # WinSDK GetDeviceCaps selectors: raster display, pixels, color planes,
        # logical DPI and unscaled desktop dimensions. This is guest configuration.
        self.capabilities={2:1,8:1920,10:1080,12:32,14:1,88:96,90:96,117:1080,118:1920}
        # Explicit Win7-style guest palette in COLORREF byte order. These are
        # chosen guest settings, not asserted defaults for every Windows host.
        # 25 is reserved; only documented selectors are accepted.
        self.colors={0:0xc8c8c8,1:0x000000,2:0xd1b499,3:0xdbcdbf,4:0xf0f0f0,
            5:0xffffff,6:0x646464,7:0x000000,8:0x000000,9:0x000000,
            10:0xb4b4b4,11:0xfcf7f4,12:0xababab,13:0xff9933,14:0xffffff,
            15:0xf0f0f0,16:0xa0a0a0,17:0x6d6d6d,18:0x000000,19:0x544e43,
            20:0xffffff,21:0x696969,22:0xe3e3e3,23:0x000000,24:0xe1ffff,
            26:0xcc6600,27:0xead1b9,28:0xf2e4d7,29:0xff9933,30:0xf0f0f0}

    def get_dc(self,uc,window):
        if window!=0:self.model.reject('GetDC','Only the virtual screen DC is modeled; window objects are unsupported')
        if len(self.contexts)>=self.MAX_DCS:self.model.reject('GetDC','Guest DC count budget exceeded')
        handle=self.next_handle;self.next_handle+=4
        self.contexts[handle]=window
        return handle

    def device_caps(self,uc,handle,index):
        if handle not in self.contexts:self.model.reject('GetDeviceCaps','Unknown or released guest screen DC')
        if index not in self.capabilities:self.model.reject('GetDeviceCaps','Capability is outside the explicit guest display profile')
        return self.capabilities[index]

    def release_dc(self,uc,window,handle):
        if handle not in self.contexts or self.contexts[handle]!=window:return 0
        del self.contexts[handle]
        return 1

    def system_color(self,uc,index):
        # A fixed guest theme query; no host theme or window access occurs.
        if index not in self.colors:self.model.reject('GetSysColor','Color is outside the explicit guest palette')
        return self.colors[index]

    def metadata(self):
        return {'scope':'virtual_screen_dc_capabilities_only','live_contexts':len(self.contexts),
                'context_limit':self.MAX_DCS,'pixels':[1920,1080],'bits_per_pixel':32,'planes':1,'dpi':[96,96],
                'capability_indices':sorted(self.capabilities),'colorref_by_index':{str(k):v for k,v in self.colors.items()},'window_objects':'unsupported',
                'drawing':'unsupported','source':'fixed_guest_configuration'}
