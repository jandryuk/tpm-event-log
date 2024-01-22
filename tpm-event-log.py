#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-only

# Copyright (C) 2018 Jason Andryuk <jandryuk@gmail.com>

from __future__ import print_function
import sys
import struct
from struct import unpack,unpack_from,calcsize
from binascii import hexlify,unhexlify
#from hashlib import sha1
import hashlib
from uuid import UUID

fmt = "<II20sI"

f = open(sys.argv[1], "rb")
d = f.read()

i = 0

total = len(d)
agile=False
TrEE=False

debug=False

def dprint(*args):
    if debug:
        print(*args)

def dump_boot_var(d):
    vfmt="<16sQQ"
    guid,name_len,data_len = unpack(vfmt, d[:32])
    d = d[32:]
    name_len *= 2
    name = d[:name_len].decode("utf-16")
    data = d[name_len:]
    print("BootVariable", UUID(bytes_le=guid), name)
    if name[:5] == "Boot0":
        #print(hexlify(data))
        i = data[6:].find(b'\x00\x00\x00')
        # i + 1 here so we don't print(a literal 'u0000')
        print("Label:", data[6:6 + i + 1].decode("utf-16"))
        # i + 3 here to skip the 'u0000'
        rem_len = dump_device_path(data[6 + i + 3:])
        if rem_len > 0:
            try:
                # decode/encode/decode is to print only ascii utf-16 strings
                # otherwise we can print kanji.  We hexdump below for that case
                print("Remainder: %d %s" % (rem_len, data[-rem_len:].decode('utf-16').encode('ascii').decode('ascii')))
            except:
                print("Remainder: %d %s" % (rem_len, hexlify(data[-rem_len:])))
    elif name == "BootOrder":
        print("BootOrder:", end="")
        offset=0
        entries=[]
        while offset < len(data):
            vfmt = "<H"
            e = unpack_from(vfmt, data, offset=offset)[0]
            entries.append("%04x" % e)
            offset += calcsize(vfmt)
        print(*entries, sep=",")
    elif data_len > 0:
        print(f"{data_len=} {hexlify(data)}")

def dump_boot_serv(d):
    vfmt = "<QQQQ"
    vfmt_len = calcsize(vfmt)
    paddr,img_len,link_time_addr,dev_path_len = unpack(vfmt, d[:vfmt_len])
    dev_path = hexlify(d[vfmt_len:vfmt_len + dev_path_len])
    print("Boot Service  paddr:%#x len:%#x link_time_addr:%#x" % \
          ( paddr,img_len,link_time_addr ))
    rem_len = dump_device_path(unhexlify(dev_path))
    if rem_len > 0:
        print("Remainder: %d %s" % (rem_len, dev_path[-rem_len * 2:]))

def dump_platform_firmware_blob(d):
    # UEFI_PLATFORM_FIRMWARE_BLOB2
    if len(d) > 16:
        vfmt = "<B"
        vfmt_len = calcsize(vfmt)
        desc_len, = unpack(vfmt, d[:vfmt_len])
        if desc_len > 0:
            print("Platform Firmware Blob description", end=" ")
            try:
                print(f"{d[vfmt_len:vfmt_len+desc_len].decode('ascii')}")
            except:
                print(f"{hexlify(d[vfmt_len:vfmt_len+desc_len])}")
        d = d[vfmt_len + desc_len:]
        version=""
    else:
        version="Legacy "
    # Legacy UEFI_PLATFORM_FIRMWARE_BLOB
    vfmt = "<QQ"
    vfmt_len = calcsize(vfmt)
    base, length = unpack(vfmt, d[:vfmt_len])
    print(f"{version}Platform Firmware Blob {base=:#x} {length=:#x}")

def dump_gpt_entry(d):
    vfmt = "<16s16sQQQ72s"
    vfmt_len = calcsize(vfmt)
    part_guid,uniq_guid,first_lba,last_lba,flags,name = unpack(vfmt,d[:vfmt_len])
    name = name.decode('utf-16').replace("\x00","")
    print(f"part_uuid={UUID(bytes_le=part_guid)},uniq_guid={UUID(bytes_le=uniq_guid)} lba={first_lba}-{last_lba} {name=}")

def dump_gpt(d):
    # typedef struct {
    #    UEFI_PARTITION_TABLE_HEADER UEFIPartitionHeader;
    #    UINT64                      NumberOfPartitions;
    #    UEFI_PARTITION_ENTRY        Partitions [1];
    # } UEFI_GPT_DATA;
    #
    # UEFI_PARTITION_TABLE_HEADER
    vfmt = "<8sIIIIQQQQ16sQIII"
    vfmt_len = calcsize(vfmt)
    sig,rev,hdr_size,crc32,resv,curr_lba,bkup_lba,first_lba,last_lba, \
        disk_guid,start_lba,num_parts,part_size,crc32_parts \
            = unpack(vfmt, d[:vfmt_len])
    print(f"{unpack(vfmt, d[:vfmt_len])=}")
    if rev == 0x10000:
        rev = "Rev 1.0"
    else:
        rev = f"Unknown {rev=}"
    print(f"Sigature \"{sig.decode('ascii')}\" {rev=} disk_guid={UUID(bytes_le=disk_guid)}")
    print(f"{hdr_size=} {num_parts=} {part_size=}")
    # NumberOfPartitions
    num_entries = unpack("<Q", d[vfmt_len:vfmt_len + 8])[0]
    offset = vfmt_len + 8
    i = 0
    while i < num_entries:
        print(f"{i=}")
        i += 1
        dump_gpt_entry(d[offset:offset + part_size])
        offset += part_size

def dump_device_path(d):
    i = 0
    indent = 0
    #d = unhexlify(dev_path)
    dev_path_len = len(d)
    dprint(f"{len(d)=}")
    print("Device Path: ", end="")
    while i < dev_path_len:
        #print("iteration", i, dev_path_len)
        typ,subtyp,path,path_len = device_path(d[i:])
        try:
            path = UUID(bytes_le=unhexlify(path))
        except:
            pass
        i += path_len
        dprint(f"{typ=}, {subtyp=}, {path=}, {path_len=}")
        typ,subtyp = get_dev_type(typ, subtyp)
        if typ == "End" and subtyp == "Entire":
            break
        if typ == "End" and subtyp == "Instance":
            print("\nDevice Path: ", end="")

        if subtyp == "Filepath":
            path = unhexlify(path).decode("utf-16").rstrip('\x00')
        if path_len > 4:
            print("\\%s(%s)" % ( subtyp, path ), end="")
        else:
            print("%s %s" % ( typ, subtyp ), end="")
    print()
    return dev_path_len - i

dev_type = {1:    ("Hardware",
                    {1: "PCI",
                     2: "PCCard",
                     3: "Memmap",
                     4: "Vendor",
                     5: "Controller"}),
            2:    ("ACPI",
                    {1: "ACPI",
                     2: "Extended",
                     3: "ADR"}),
            3:    ("Messaging",
                    {1: "ATAPI",
                     2: "SCSI",
                     11: "MACAddress",
                     12: "IPv4",
                     13: "IPv6",
                     0x12: "SATA",
                     23: "NVMeNamespace",
                     0x13: "ISCSI"}),
            4:    ("Media",
                    {1: "Hard Drive",
                     2: "CD-Rom",
                     3: "Vendor",
                     4: "Filepath",
                     5: "Protocol",
                     6: "FVFile",
                     7: "FV",
                     8: "RelativeOffsetRange",
                     9: "Ramdisk"}),
            5:    ("BBS",
                    {1: "BBS"}),
            0x7f: ("End",
                    {1: "Instance",
                     0xff: "Entire"})
                   }

def get_dev_type(typ, subtyp):
    try:
        t, st_dict = dev_type[typ]
    except:
        return str(typ), str(subtyp)
    try:
        st = st_dict[subtyp]
    except:
        return t, str(subtyp)

    return t, st

def device_path(d):
    vfmt = "<BBH"
    vfmt_len = calcsize(vfmt)
    typ,subtyp,path_len = unpack(vfmt, d[:vfmt_len])
    #path_len -= vfmt_len
    path = hexlify(d[vfmt_len:path_len])
    return typ,subtyp,path,path_len

AlgIDSHA1=4
AlgIDSHA256=0xb
AlgIDSHA384=0xc
AlgIDSHA512=0xd
alg_name={ AlgIDSHA1   : "SHA1",
           AlgIDSHA256 : "SHA256",
           AlgIDSHA384 : "SHA384",
           AlgIDSHA512 : "SHA512" }
alg_len={ AlgIDSHA1: 20,
          AlgIDSHA256: 32,
          AlgIDSHA384: 48,
          AlgIDSHA512 : 64 }
TrEE_to_TPM2 = { 1 : AlgIDSHA1,
                 2 : AlgIDSHA256,
                 3 : AlgIDSHA384,
                 4 : AlgIDSHA512 }
compat_alg=AlgIDSHA1

def check_agile(d):
    global agile
    global TrEE
    if d[:16] == b"Spec ID Event03\x00":
        print("agile log %d" % len(d))
        agile=True
        vfmt="<16sIBBBBI"
        vfmt_len = calcsize(vfmt)
        sig,platClass,specVerMin,specVerMaj,specVerErrata,uintnSize,nAlgs = \
                unpack(vfmt,d[:vfmt_len])
        print(f"{sig.decode('utf-8')=},{platClass=},{specVerMin=},{specVerMaj=},{specVerErrata=},{uintnSize=},{nAlgs=}")
        i = vfmt_len
        print("i=%d len(d)=%d" % (i, len(d)))
        for j in range(nAlgs):
            algId,digestSize = unpack("<HH", d[i:i+4])
            print(f"{algId=:#x}",f"{digestSize=}")
            global alg_len
            if alg_len[algId] != digestSize:
                print(f"Mismatch between {alg_len[algId]=} and {digestSize}")
            alg_len[algId] = digestSize
            i += 4

        vendorInfoSize, = unpack("<B", d[i:i + 1])
        print(f"{vendorInfoSize=}")
    elif d[:16] == b"FRMT ID EVENT00\x00":
        TrEE=True
        print(f"TrEE event log {len(d)}")
        vfmt="<16sIII"
        vfmt_len = calcsize(vfmt)
        sig,revision,digestAlgID,digestSize = unpack(vfmt,d[:vfmt_len])
        print(f"{sig.decode('utf-8')=},{revision=},{digestAlgID=},{digestSize=}")
        global compat_alg
        compat_alg = TrEE_to_TPM2[digestAlgID]
        if alg_len[compat_alg] != digestSize:
            print(f"Mismatch between {alg_len[compat_alg]=} and {digestSize}")

    else:
        print(d)

def unpack_event(d):
    i=0

    global agile

    if agile:
        pcr, evtag, count = unpack("<III", d[:12])
        #print("agile", pcr, evtag, count)
        i=12
        digests = []
        for j in range(count):
            alg, = unpack("<H", d[i:i+2])
            #print("found alg %d %s" % (alg, alg_name[alg]))
            i += 2
            l = alg_len[alg]
            digests.append((alg, l, d[i:i+l]))
            i += l

        event_size, = unpack("<I", d[i:i+4])
        i += 4
        event = d[i:i + event_size]
        #if i + event_size != len(d):
        #    print("len(d) = %d but only parsed %d" % (len(d), i + event_size))
        i += event_size
    else:
        # Originally the legacy tpm1 TCG_PCR_EVENT sha1 format, this has been
        # extended do handle TrEE TCG_PCR_EVENT_EX format
        fmt = "<II%dsI" % alg_len[compat_alg]
        fmt_len = calcsize(fmt)
        pcr, evtag, digest, event_size = unpack(fmt, d[i:i + fmt_len])
        #digests = [(compat_alAlgIDSHA1, alg_len[AlgIDSHA1], digest)]
        digests = [(compat_alg, alg_len[compat_alg], digest)]
        event = d[i + fmt_len: i + fmt_len + event_size]
        i = i + fmt_len + event_size

    return pcr, evtag, digests, event_size, event, i

def check_hash(algId, digest, s):
    new_digest = hashlib.new(alg_name[algId], s).digest()
    if new_digest == digest:
        print(f"{alg_name[algId]} match for {s}")
    else:
        print(f"{alg_name[algId]} mismatch for {s}")

def dump_ipl(event, digests):
    prefixes = [ b"grub_cmd: ", b"kernel_cmdline: ", b"module_cmdline: " ]
    prefix=None
    for p in prefixes:
        if event.startswith(p):
            prefix = p
            dprint(f"Prefix match {prefix}")
            break
    if prefix == None:
        print(f"No grub prefix (maybe a file?) - Skipping")
        return

    if event[-1] != 0:
        print(f"End of event is not a NUL byte - '{event[-1]}'")

    s = event[len(prefix):-1]

    for algId, algLen, digest in digests:
        check_hash(algId, digest, s)

if d.find(b"FRMT ID EVENT00\x00") == 56:
    print("Skipping 0x18 bytes for legacy tpm2.0 compatibility")
    i += 0x18

if d.find(b"TXT Event Container\x00") == 0:
    print("Skipping 0x30 bytes for tpm1.2 TXT compatibility")
    i += 0x30

class Digest():
    def __init__(self, algId, algLen, digest):
        if alg_len[algId] != algLen:
            print(f"{alg_len[algId]=} != {algLen=}")
        self.digest = digest
        self.algId = algId

    # Maybe this should be some different repr
    def __repr__(self):
        return f"{alg_name[self.algId]}:{hexlify(self.digest).decode('utf-8')}"

    def __str__(self):
        return f"{alg_name[self.algId]}:{hexlify(self.digest).decode('utf-8')}"

while i < total:
    print("=" * 64)
    #tag,evtag,hash,size = unpack(fmt, d[i:i+32])
    #data = d[i+32:i+32+size]
    #print("loop i=%d" % i)
    pcr,evtag,digests,event_size, event, j = unpack_event(d[i:])
    #print(pcr,evtag,digests,event_size, event, j)
    if evtag == 0xffffffff:
        print("exiting on 0xffffffff")
        break

    #print("pcr%02d %08x %s %08x %s" % (pcr,evtag,digests,event_size, event))
    #print(f"pcr{pcr:02d} {evtag:08x} {digests} {event_size:08x} {event}")
    print(f"pcr{pcr:02d} {evtag:08x} {[Digest(x,y,z) for x,y,z in digests]} {event_size:08x} {event}")
    if evtag == 0x80000002 or evtag == 0x80000001:
        dump_boot_var(event)
    elif evtag == 0x80000003 or evtag == 0x80000004:
        dump_boot_serv(event)
    elif evtag == 0x80000006:
        dump_gpt(event)
    elif evtag == 0x80000008:
        dump_platform_firmware_blob(event)
    elif evtag == 0x3:
        check_agile(event)
    elif evtag == 0xd:
        dump_ipl(event, digests)
    else:
        print("Skipping pcr%02d tag %08x event_size:%#x" % (pcr, evtag, event_size))

    i += j

if i != total:
    print("Finished with i=%d and total=%d" % (i, total))
