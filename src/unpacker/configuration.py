"""Explicit bounded YAML configuration; unknown or unimplemented options fail."""
from pathlib import Path
import math
from unpacker.deadlines import positive_seconds


def load_config(path: Path):
    if not path.is_file() or path.stat().st_size>16384:raise ValueError('Invalid configuration file')
    try:import yaml
    except ImportError:raise ValueError('Install the config extra for YAML') from None
    data=yaml.safe_load(path.read_text())
    if not isinstance(data,dict) or set(data)-{'detector','orchestrator','unpackers'}:raise ValueError('Invalid configuration sections')
    result={}
    allowed={'detector':{'confidence_threshold'},'orchestrator':{'max_layers','timeout_seconds','rebuild_iat','allow_emulation','max_output_size_mb','total_timeout_seconds','max_total_output_size_mb','max_output_entries'},'unpackers':{'upx_prefer_native'}}
    for section,values in data.items():
        if not isinstance(values,dict) or set(values)-allowed[section]:raise ValueError('Unknown configuration option')
        for key,value in values.items():
            if key=='upx_prefer_native':
                if value is not True:raise ValueError('Only native UPX is implemented')
            elif key=='rebuild_iat':
                if value is not False:raise ValueError('Standalone IAT rebuild is not implemented')
            else:
                if key=='allow_emulation' and type(value) is not bool:raise ValueError('Invalid emulation flag')
                if key in {'max_layers','max_output_size_mb','max_total_output_size_mb','max_output_entries'} and type(value) is not int:raise ValueError('Invalid integer budget')
                if key in {'timeout_seconds','total_timeout_seconds','confidence_threshold'} and (type(value) not in {int,float} or not math.isfinite(value)):raise ValueError('Invalid numeric setting')
                if key in {'timeout_seconds','total_timeout_seconds'}:value=positive_seconds(value,key)
                result[key]=value
    return result
