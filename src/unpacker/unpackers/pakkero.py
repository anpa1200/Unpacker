"""Authenticated static pakkero ELF extraction; no launcher execution."""
from pathlib import Path
import shutil,tempfile,time
from unpacker.types import UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.pakkero_format import MAX_BYTES,upx_carrier,decode_payload


class PakkeroUnpacker(BaseUnpacker):
    @property
    def packer_id(self):return 'pakkero'

    def unpack(self,sample_path,options):
        from unpacker.backend_worker import supervise
        return supervise('pakkero_static',sample_path,options.output_dir/'payload.bin',options,'pakkero_static')


def _extract_pakkero(sample_path,out_path,options):
    from unpacker.process import run_command
    started=time.monotonic();limit=min(MAX_BYTES,options.max_output_size_mb*1024*1024)
    metadata={'method':'pakkero_static','scope':'UPX-carried ELF64 Unicode-offset AES-GCM profile',
              'launcher_execution':False,'complete_recovery':'not_established'}
    if sample_path.stat().st_size>min(MAX_BYTES,options.max_input_size_mb*1024*1024):
        return UnpackResult(False,error='Pakkero input exceeds profile/input budget',status='input_error',metadata=metadata)
    tool=shutil.which('upx')
    if tool is None:return UnpackResult(False,error='Pakkero static profile requires installed UPX decoder',status='dependency_error',metadata=metadata)
    try:
        data=sample_path.read_bytes();carrier,facts=upx_carrier(data,limit);metadata.update(facts)
        with tempfile.TemporaryDirectory(prefix='.pakkero-',dir=options.output_dir) as scratch:
            scratch=Path(scratch);packed=scratch/'carrier.bin';launcher=scratch/'launcher.bin'
            packed.write_bytes(carrier);packed.chmod(0o600)
            # Keep the decoder in the supervised worker's process group.
            result=run_command([tool,'-d','-o',str(launcher),str(packed)],
                timeout=max(.001,options.timeout_seconds-(time.monotonic()-started)),
                max_output_mb=options.max_output_size_mb,output_root=options.extra.get('output_budget_root',options.output_dir),
                max_total_output_mb=options.max_total_output_size_mb,max_output_entries=options.max_output_entries,
                start_new_session=False)
            logs=[result['stdout'],result['stderr']]
            if result.get('output_limit_exceeded'):
                return UnpackResult(False,error=result['output_limit_exceeded'],status='resource_limit',metadata=metadata,log=logs)
            if result['timed_out']:return UnpackResult(False,error='Pakkero carrier decode deadline exceeded',status='timeout',metadata=metadata,log=logs)
            if result['returncode']!=0 or not launcher.is_file():
                return UnpackResult(False,error='Pakkero carrier was not decoded by UPX',status='unsupported',metadata=metadata,log=logs)
            if launcher.stat().st_size!=facts['declared_launcher_bytes']:
                raise ValueError('Decoded launcher size differs from checked header')
            metadata['carrier_decoder_warnings']='[WARNING]' in result['stdout'] or '[WARNING]' in result['stderr']
            payload,facts=decode_payload(data,launcher.read_bytes(),len(carrier),limit);metadata.update(facts)
        with out_path.open('xb') as output:output.write(payload)
        out_path.chmod(0o600)
        if metadata['self_prefix_payload']:
            return UnpackResult(False,output_path=out_path,status='partial',artifact_kind='decompressed_file',metadata=metadata,log=logs,
                error='Authenticated payload equals its own carrier prefix; original application recovery is not established')
        return UnpackResult(True,output_path=out_path,status='completed',artifact_kind='decompressed_file',metadata=metadata,log=logs)
    except ImportError:
        return UnpackResult(False,error='Pakkero static profile requires the optional crypto extra',status='dependency_error',metadata=metadata)
    except (ValueError,TypeError,KeyError,IndexError) as exc:
        return UnpackResult(False,error=str(exc)[:240],status='unsupported',metadata=metadata)
