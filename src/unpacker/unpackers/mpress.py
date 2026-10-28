"""MPRESS PE32 adapter using the common supervised Unipacker path."""
from unpacker.unpackers.base import BaseUnpacker
from unpacker.unpackers._unipacker_shared import run_unipacker_emulation

class MPRESSUnpacker(BaseUnpacker):
    @property
    def packer_id(self): return "mpress"

    def unpack(self, sample_path, options):
        return run_unipacker_emulation(sample_path,options.output_dir/"dump.bin",options,packer_label="unipacker_mpress")
