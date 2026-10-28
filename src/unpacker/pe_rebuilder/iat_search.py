"""Conservative PE32 IAT matching against complete observed lookup sequences.

This fallback has no descriptor/slot provenance. Only one aligned, complete,
zero-terminated sequence may be selected; a prefix or first occurrence is not
sufficient. This function does not patch bytes or consult an original program.
"""
import struct

MAX_IMAGE_BYTES=32*1024*1024


def find_unique_iat(memory,values,max_candidates=128):
    if not isinstance(memory,(bytes,bytearray)) or not 0<len(memory)<=MAX_IMAGE_BYTES:
        raise ValueError('IAT search image exceeds bounded profile')
    if not 1<=len(values)<=4096 or any(type(value) is not int or not 0<value<2**32 for value in values):
        raise ValueError('Invalid or excessive observed IAT sequence')
    if type(max_candidates) is not int or not 1<=max_candidates<=4096:
        raise ValueError('Invalid IAT search candidate budget')
    needle=struct.pack('<'+'I'*len(values),*values)
    cursor=0;checked=0;matches=[]
    while True:
        position=memory.find(needle,cursor)
        if position<0:break
        checked+=1
        if checked>max_candidates:
            return {'rva':None,'reason':'candidate_budget_exceeded','candidates_checked':max_candidates}
        cursor=position+1;end=position+len(needle)
        if position%4 or memory[end:end+4]!=bytes(4):continue
        matches.append(position)
    if len(matches)>1:
        return {'rva':None,'reason':'ambiguous_complete_sequences','candidates_checked':checked,'candidate_rvas':matches}
    return {'rva':matches[0] if matches else None,
            'reason':'unique_complete_terminated_sequence' if matches else 'no_complete_terminated_sequence',
            'candidates_checked':checked}
