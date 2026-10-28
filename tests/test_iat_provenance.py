"""Benign x86 bytes are disassembled only; never executed."""
import struct
import pytest
from unpacker.pe_rebuilder.iat_provenance import reachable_iat_slots,select_referenced_iat

REGION=0x401000;BASE=0x400000;REAL=0x403000;DECOY=0x404000
call=lambda slot:b'\xff\x15'+struct.pack('<I',slot)


def test_only_reachable_absolute_indirect_call_selects_an_iat_copy():
    code=call(REAL)+b'\xc3'+call(DECOY)+b'\xc3'
    facts=reachable_iat_slots(code,REGION,REGION)
    assert facts['complete'] and facts['slots']==[REAL]
    assert select_referenced_iat([0x3000,0x4000],1,BASE,facts)==0x3000


def test_direct_jump_skips_data_that_resembles_an_import_call():
    code=b'\xe9'+struct.pack('<i',11)+call(DECOY)+b'x'*5+call(REAL)+b'\xc3'
    facts=reachable_iat_slots(code,REGION,REGION)
    assert facts['complete'] and facts['slots']==[REAL]


def test_direct_internal_call_visits_callee_and_return_fallthrough():
    code=b'\xe8'+struct.pack('<i',11)+b'\xc3'+b'x'*10+call(REAL)+b'\xc3'
    assert reachable_iat_slots(code,REGION,REGION)['slots']==[REAL]


def test_two_referenced_copies_stay_ambiguous():
    code=call(REAL)+call(DECOY)+b'\xc3'
    facts=reachable_iat_slots(code,REGION,REGION)
    assert select_referenced_iat([0x3000,0x4000],1,BASE,facts) is None


def test_instruction_and_overlap_limits_never_select_partial_evidence():
    facts=reachable_iat_slots(call(REAL)+b'\xc3',REGION,REGION,max_instructions=1)
    assert not facts['complete'] and facts['slots']==[]
    assert select_referenced_iat([0x3000],1,BASE,facts) is None
    facts=reachable_iat_slots(b'\xeb\xff'+bytes(16),REGION,REGION)
    assert not facts['complete'] and facts['slots']==[]


def test_segmented_and_register_indirect_calls_are_not_absolute_iat_evidence():
    code=b'\x64'+call(REAL)+b'\xff\xd0\xc3'
    assert reachable_iat_slots(code,REGION,REGION)['slots']==[]


def test_path_work_queue_has_a_separate_bound():
    code=b'\x74\x0e\x74\x1c\xc3'+bytes(11)+b'\xc3'+bytes(15)+b'\xc3'
    facts=reachable_iat_slots(code,REGION,REGION,max_paths=1)
    assert not facts['complete'] and facts['reason']=='path_budget_exceeded'


@pytest.mark.parametrize('entry',[REGION-1,REGION+1])
def test_entry_must_belong_to_the_bounded_region(entry):
    with pytest.raises(ValueError):reachable_iat_slots(b'\xc3',REGION,entry)


def dialog_fixture():
    callback=REGION+64;slot=0x403020
    pushes=b'\x6a\x00\x68'+struct.pack('<I',callback)+b'\x6a\x00\x6a\x00\x6a\x00'
    code=pushes+call(slot)+b'\xc3'
    return code+b'x'*(64-len(code))+call(REAL)+b'\xc3',slot


def test_documented_literal_dialog_callback_is_an_additional_code_root():
    code,slot=dialog_fixture()
    facts=reachable_iat_slots(code,REGION,REGION,callback_resolver=lambda address:(5,4) if address==slot else None)
    assert facts['complete'] and facts['api_callback_roots']==1 and REAL in facts['slots']


def test_unidentified_call_does_not_make_a_literal_pointer_executable():
    code,_=dialog_fixture()
    facts=reachable_iat_slots(code,REGION,REGION,callback_resolver=lambda address:None)
    assert facts['api_callback_roots']==0 and REAL not in facts['slots']


def test_missing_or_unknown_callback_argument_does_not_select_a_root():
    code,slot=dialog_fixture()
    # Replace the callback immediate PUSH with PUSH EAX and padding. The
    # callback cannot be inferred from a register whose value is not modeled.
    code=code[:2]+b'\x50\x90\x90\x90\x90'+code[7:]
    facts=reachable_iat_slots(code,REGION,REGION,callback_resolver=lambda address:(5,4))
    assert facts['api_callback_roots']==0 and REAL not in facts['slots']


def test_stack_adjustment_invalidates_preceding_literal_arguments():
    code,slot=dialog_fixture();position=code.index(call(slot))
    changed=code[:position]+b'\x83\xc4\x14'+code[position:]
    facts=reachable_iat_slots(changed,REGION,REGION,callback_resolver=lambda address:(5,4))
    assert facts['api_callback_roots']==0


def test_callback_identity_requires_the_observed_system_module():
    from unpacker.pe_rebuilder.iat_provenance import dialog_bindings
    assert dialog_bindings({'USER32.dll#0':[('DialogBoxParamA',123)],'USER32.dll#1':[('DialogBoxParamA',123)]})=={123}
    assert dialog_bindings({'other.dll#0':[('DialogBoxParamA',123)]})==set()


def test_aliased_api_addresses_are_not_treated_as_a_known_callback_prototype():
    from unpacker.pe_rebuilder.iat_provenance import dialog_bindings
    assert dialog_bindings({'user32.dll#0':[('DialogBoxParamA',123)],'other.dll#0':[('OtherFunction',123)]})==set()


@pytest.mark.parametrize('observed',[{'user32.dll#0':[('DialogBoxParamA',123)]*4097},
                                    {str(i):[] for i in range(129)}])
def test_callback_identity_observation_budgets_are_explicit(observed):
    from unpacker.pe_rebuilder.iat_provenance import dialog_bindings
    assert dialog_bindings(observed)==set()
