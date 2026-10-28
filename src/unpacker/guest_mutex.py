"""Bounded mutex objects for the declared single-thread guest process.

No host kernel object, external process, sleep, or thread is created.
"""
class GuestMutexes:
    def __init__(self,model):
        self.model=model;self.named={};self.acquisitions=0;self.releases=0

    def create(self,uc,security,initial,name_pointer):
        if security:self.model.reject('CreateMutexA','Security attributes/inherited handles are not modeled')
        name=self.model.string(uc,name_pointer,'CreateMutexA') if name_pointer else None
        if name is not None:
            if not name or len(name)>260:self.model.reject('CreateMutexA','Mutex name is outside the bounded profile')
            if name.startswith(b'Local\\'):name=name[6:]
            if not name or b'\\' in name:self.model.reject('CreateMutexA','Global/private cross-process namespaces are not modeled')
        existing=self.named.get(name) if name is not None else None
        obj=existing if existing is not None else {'name':name,'owner':1 if initial else None,'depth':1 if initial else 0,'references':0}
        handle=self.model.handle('mutex',obj)  # Budget failure precedes namespace mutation.
        obj['references']+=1
        if name is not None:self.named[name]=obj
        self.model.last_error=183 if existing is not None else 0
        if existing is None and initial:self.acquisitions+=1
        return handle

    def _object(self,handle,operation):
        kind,obj=self.model.handles.get(handle,(None,None))
        if kind=='mutex':return obj
        if operation=='WaitForSingleObject' and (kind is not None or handle in {0xffffffff,0xfffffffe}):
            self.model.reject(operation,'Wait/release semantics for this object type are not modeled')
        self.model.last_error=6;return None

    def wait(self,uc,handle,milliseconds):
        obj=self._object(handle,'WaitForSingleObject')
        if obj is None:return 0xffffffff
        if obj['owner'] not in {None,1}:
            self.model.reject('WaitForSingleObject','External owner/thread scheduling/abandonment is not modeled')
        if obj['depth']>=0x7fffffff:self.model.reject('WaitForSingleObject','Mutex recursion budget exceeded')
        obj['owner']=1;obj['depth']+=1;self.acquisitions+=1
        return 0  # Already-owned or unowned mutex is immediately satisfiable.

    def release(self,uc,handle):
        obj=self._object(handle,'ReleaseMutex')
        if obj is None:return 0
        if obj['owner']!=1 or not obj['depth']:self.model.last_error=288;return 0
        obj['depth']-=1;self.releases+=1
        if not obj['depth']:obj['owner']=None
        return 1

    def close(self,handle):
        _,obj=self.model.handles.pop(handle);obj['references']-=1
        if not obj['references'] and obj['name'] is not None:self.named.pop(obj['name'],None)
        return 1

    def facts(self):
        return {'profile':'single_guest_thread_local_mutex_objects','named_objects':len(self.named),
          'open_handles':sum(k=='mutex' for k,_ in self.model.handles.values()),
          'acquisitions':self.acquisitions,'releases':self.releases,
          'external_processes_threads_abandonment_security':'not_modeled'}
