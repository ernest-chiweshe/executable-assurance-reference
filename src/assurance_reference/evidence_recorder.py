"""Reference recording with atomic companion index, preserving all age checks."""
from assurance_reference.recorder import ReferenceDecisionRecorder

class SharedEvidenceRecorder(ReferenceDecisionRecorder):
    def __init__(self,*args,service_for,**kwargs):
        super().__init__(*args,**kwargs)
        self.service_for=service_for
        self._raw_recorder=ReferenceDecisionRecorder(*args,**kwargs)
    def bind_clock(self,clock):
        super().bind_clock(clock)
        if hasattr(self,'_raw_recorder'):self._raw_recorder.bind_clock(clock)
    def _append_on(self,conn,record,record_hash):
        envelope,_=self.service_for(record.tenant_id).append_record_on(conn,self._raw_recorder,record,record_hash)
        return envelope
