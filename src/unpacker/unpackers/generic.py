"""Bounded gzip-wrapper extraction and explicitly opted-in PE32 emulation."""
import zlib
from unpacker.types import UnpackResult
from unpacker.unpackers.base import BaseUnpacker

class GenericUnpacker(BaseUnpacker):
    @property
    def packer_id(self): return "generic"

    def can_handle(self, packer_id, sample_path): return packer_id.lower() in ("unknown","generic","gzexe")

    def unpack(self, sample_path, options):
        head = sample_path.read_bytes()
        if head.startswith(b"#!/bin/sh") and b"gzip" in head[:4096] and b"tail" in head[:4096]:
            offset = head.find(b"\x1f\x8b\x08")
            if offset >= 0:
                try:
                    decoder = zlib.decompressobj(31)
                    limit = options.max_output_size_mb * 1024 * 1024
                    data = decoder.decompress(head[offset:], limit + 1)
                    if len(data)>limit or not decoder.eof or decoder.unused_data:
                        return UnpackResult(False,error="Invalid or oversized gzip wrapper")
                    out=options.output_dir/"decompressed.bin";out.write_bytes(data)
                    return UnpackResult(True,output_path=out,status="completed",artifact_kind="decompressed_file",
                                        metadata={"method":"gzip_wrapper_static"})
                except zlib.error:
                    return UnpackResult(False,error="Invalid gzip wrapper")
        if not options.allow_emulation:
            return UnpackResult(False,error="No static adapter; emulation requires explicit opt-in in an isolated environment",status="unsupported")
        from unpacker.unpackers._unipacker_shared import run_unipacker_emulation
        return run_unipacker_emulation(sample_path,options.output_dir/"dump.bin",options,packer_label="unipacker_generic")
