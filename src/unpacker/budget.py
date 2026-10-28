"""Bounded output accounting; rejects links, special files and deep trees.

This watchdog is not a filesystem quota: a writer can overshoot between checks.
"""
import os,stat
from pathlib import Path


def directory_usage(root, max_entries=4096):
    total=0;entries=0
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    def walk(fd,depth):
        nonlocal total,entries
        if depth>64:raise ValueError('Output directory nesting exceeds budget')
        with os.scandir(fd) as children:
            for child in children:
                entries+=1
                if entries>max_entries:raise ValueError('Output entry count exceeds budget')
                info=child.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    nested=os.open(child.name,flags,dir_fd=fd)
                    try:walk(nested,depth+1)
                    finally:os.close(nested)
                elif stat.S_ISREG(info.st_mode):total+=max(info.st_size,info.st_blocks*512)
                else:raise ValueError('Output contains link or special file')
    fd=os.open(Path(root),flags)
    try:walk(fd,0)
    finally:os.close(fd)
    return total,entries


def check_output_budget(root, max_bytes, max_entries=4096):
    try:
        size,entries=directory_usage(root,max_entries)
        if size>max_bytes:return f'Aggregate output budget exceeded ({size} > {max_bytes} bytes)'
    except (OSError,ValueError) as exc:
        return f'Output accounting rejected: {type(exc).__name__}'
    return None
