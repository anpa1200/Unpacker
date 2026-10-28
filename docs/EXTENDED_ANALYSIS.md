# Extended wall-clock analysis profile

Defaults remain a 60-second decode budget and 300-second total job budget. For a problematic specimen, use the explicit isolated command:

```sh
unpacker-sandbox SAMPLE -o OUTPUT --allow-emulation --timeout 180 --total-timeout 210 --max-total-output-mb 32
```

The equivalent direct CLI settings are in `config/extended-analysis.yaml`. Direct CLI emulation still requires an external sandbox; the file does not create isolation.

Validation profiles use these seconds:

| Profile | Decode | Total job | Sandbox watchdog | Outer launcher |
| --- | --- | --- | --- | --- |
| Control | 60 | 90 | 95 | 105 |
| Extended | 180 | 210 | 215 | 225 |

A shorter explicit total job always wins and is never silently extended. Time must be positive and finite. Input/output/memory/event limits do not change. After killing an owned process group, cleanup uses a finite 5-second reap deadline. Analyst KeyboardInterrupt cleans up owned descendants before propagating. The child receives the same input/output/entry budgets as its parent.

HeapSetInformation supports only the process-wide, irreversible class 1 NULL/zero configuration observed in Amber. Recorded guest heap double frees terminate the guest with STATUS_HEAP_CORRUPTION. Unknown corruption-sensitive pointers stop as unsupported; full Windows heap metadata, LFH and WER are not modeled.

No native specimen execution, host heap/process changes, private LLM requests, publication, credentials or newly downloaded dependencies are part of this work.


The follow-up candidate delivers actual read/write access violations to guest
stack handlers, with two exception parameters and unchanged protections. Generic
profiles retain64 events/depth8; the newly enabled PEtite profile is limited to8
events. Unknown native-DLL snapshot faults are rejected rather than fictitiously
delivered as sample faults. Floating/extended context and unsupported frames
remain explicit limitations.

GetFileAttributesExW exposes the supplied virtual sample only, with a complete
36-byte attribute record and accurate supplied-byte length. Timestamps are an
explicit fixed guest epoch1970 configuration, not host-file metadata. Other
files do not gain host access; complex paths/directories remain unsupported.
