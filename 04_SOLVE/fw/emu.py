#!/usr/bin/env python3
"""Unicorn harness for the CV6 T-BOX firmware (ARMv7-M Thumb-2, base 0x08000000)."""
import struct, sys
from unicorn import *
from unicorn.arm_const import *

FW = open(r'D:\qwb\work\bundle2\tbox-firmware.dec.bin','rb').read()
FLASH, FLASH_SZ = 0x08000000, 0x4000
RAM,   RAM_SZ   = 0x20000000, 0x10000

def new_uc(trace_calls=True):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(FLASH, FLASH_SZ)
    uc.mem_write(FLASH, FW)
    uc.mem_map(RAM, RAM_SZ)
    uc.reg_write(UC_ARM_REG_SP, 0x20010000)
    uc.log = []
    return uc

def run(uc, start, sp=0x20010000, stop_wfi=True, max_insn=2_000_000, args=None, base_sp=None, stops=()):
    """args: dict reg->value"""
    if base_sp is not None: sp = base_sp
    uc.reg_write(UC_ARM_REG_SP, sp)
    if args:
        for r,v in args.items(): uc.reg_write(r, v)
    pc_state = {'halt':None}
    calls=[]
    def hook_code(uc, address, size, ud):
        pass
    def hook_block(uc, address, size, ud):
        pass
    def on_mem_unmapped(uc, access, address, size, value, ud):
        raise RuntimeError(f"unmapped access {access} @0x{address:08x}")
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_mem_unmapped)
    n=[0]
    last=[start]
    stopset=set(stops)
    def hc(uc, addr, size, ud):
        n[0]+=1
        last[0]=addr
        if addr in stopset:
            raise StopIteration(('stop',addr))
        if n[0]>max_insn: raise RuntimeError("insn budget")
        # detect WFI (0xbf30) and BKPT
        if size==2:
            hw = bytes(uc.mem_read(addr,2))
            if hw==b'\x30\xbf':
                raise StopIteration(('wfi',addr))
    uc.hook_add(UC_HOOK_CODE, hc)
    try:
        uc.emu_start(start, 0, count=max_insn)
    except StopIteration as e:
        pc_state['halt']=e.args[0]
        return pc_state, uc, n[0]
    except UcError as e:
        print(f"  UcError {e} last_pc=0x{last[0]:08x}")
        raise
    return pc_state, uc, n[0]

if __name__=='__main__':
    uc=new_uc()
    st,uc,n = run(uc, 0x08000755)
    print("halt:",st,"insns:",n)
    print("R0 =",hex(uc.reg_read(UC_ARM_REG_R0)))
    print("SP =",hex(uc.reg_read(UC_ARM_REG_SP)))
    sp=0x20010000-0x3c
    print("stack:",bytes(uc.mem_read(sp,0x3c)).hex(' '))
    print("flash 0x2000:",bytes(uc.mem_read(0x08002000,0x70)).hex(' '))
