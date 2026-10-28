"""Synchronous readonly guest I/O over already-supplied specimen bytes only."""
import struct


class GuestFileIO:
    def __init__(self,model):self.model=model;self.positions={};self.options={};self.sharing={};self.bytes_read=0

    def register(self,handle,access,flags,share=0):
        self.positions[handle]=0;self.options[handle]=(access,flags);self.sharing[handle]=share

    def close(self,handle):self.positions.pop(handle,None);self.options.pop(handle,None);self.sharing.pop(handle,None)

    def _file(self,handle):
        kind,data=self.model.handles.get(handle,(None,None))
        if kind!='file':self.model.last_error=6;return None
        access,flags=self.options.get(handle,(0,0))
        if flags&(0x40000000|0x20000000):
            self.model.reject('FileIO','Overlapped/unbuffered file modes are not modeled')
        if not access&0x80000000:self.model.last_error=5;return None
        return data

    def _writable(self,uc,address,size,operation):
        if not size:return
        if address<=0 or address+size>0x100000000:self.model.reject(operation,'Guest output range is invalid')
        cursor=address;end=address+size
        for lo,hi,permissions in sorted(uc.mem_regions()):
            if hi<cursor:continue
            if lo>cursor or not permissions&2:break
            cursor=min(end,hi+1)
            if cursor==end:return
        self.model.reject(operation,'Guest output range is not mapped writable')

    def read(self,uc,handle,buffer,count,out_read,overlapped):
        if overlapped:self.model.reject('ReadFile','Overlapped I/O is not modeled')
        if count>self.model.limit:self.model.reject('ReadFile','Read exceeds guest I/O budget')
        if not out_read:self.model.last_error=87;return 0  # Declared Windows7 synchronous contract.
        self._writable(uc,out_read,4,'ReadFile');uc.mem_write(out_read,bytes(4))
        data=self._file(handle)
        if data is None:return 0
        position=self.positions.get(handle,0);chunk=data[position:position+count]
        self._writable(uc,buffer,len(chunk),'ReadFile')
        if chunk:uc.mem_write(buffer,chunk)
        uc.mem_write(out_read,struct.pack('<I',len(chunk)))
        self.positions[handle]=position+len(chunk);self.bytes_read+=len(chunk)
        if len(self.model.events)<32:self.model.events.append({'operation':'ReadFile','handle':handle,'offset':position,'requested':count,'read':len(chunk),'source':'supplied_specimen_bytes'})
        return 1

    def seek(self,uc,handle,low,high_pointer,method):
        data=self._file(handle)
        if data is None:return 0xffffffff
        if method not in {0,1,2}:self.model.last_error=87;return 0xffffffff
        if high_pointer:
            high=struct.unpack('<I',uc.mem_read(high_pointer,4))[0]
            distance=(high<<32)|low
            if distance&0x8000000000000000:distance-=0x10000000000000000
        else:distance=low-0x100000000 if low&0x80000000 else low
        position=[0,self.positions.get(handle,0),len(data)][method]+distance
        if position<0:self.model.last_error=131;return 0xffffffff
        if position>0x7fffffffffffffff or (not high_pointer and position>0xffffffff):self.model.last_error=87;return 0xffffffff
        if high_pointer:
            self._writable(uc,high_pointer,4,'SetFilePointer');uc.mem_write(high_pointer,struct.pack('<I',position>>32))
        self.positions[handle]=position
        if position&0xffffffff==0xffffffff:self.model.last_error=0
        return position&0xffffffff

    def facts(self):
        return {'scope':'synchronous_readonly_supplied_specimen_handles','open_file_cursors':len(self.positions),
                'bytes_read':self.bytes_read,'overlapped_unbuffered_writes_host_paths':'not_modeled'}
