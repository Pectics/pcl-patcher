#!/usr/bin/env python3
"""Scan .NET IL for ldstr references and map methods -> user strings."""
import sys, struct
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from dnmeta import PE


def read_compressed(d, p):
    b = d[p]
    if b & 0x80 == 0:
        return b, p + 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3f) << 8) | d[p + 1], p + 2
    return ((b & 0x1f) << 24) | (d[p + 1] << 16) | (d[p + 2] << 8) | d[p + 3], p + 4


class Asm:
    def __init__(self, path):
        self.pe = PE(path)
        d = self.pe.data
        self.d = d
        # Build US offset -> string map
        self.us = {}
        o, end = self.pe.us_off, self.pe.us_off + self.pe.us_size
        p = o + 1
        while p < end:
            start = p
            n, p = read_compressed(d, p)
            if n == 0:
                continue
            self.us[start - o] = d[p:p + n - 1].decode('utf-16-le', 'replace')
            p += n
        # TypeDef -> method range
        self.types = self.pe.typedefs()
        m = self.pe.methoddefs()
        self.methods = m
        self.method_by_idx = {x['idx']: x for x in m}
        # TypeDef row: flags, name, ns, extends, fieldlist, methodlist
        self.type_methods = []  # (type_name, [methoddefs])
        tdef = self.pe.rows.get(0x02, 0)
        off = self.pe.table_offsets[0x02]
        row = self.pe.schemas[0x02]
        rs = sum(row)
        # columns: 0 flags u32, 4 name, 4+sidx ns, 4+2sidx extends, 4+2sidx+2 fieldlist, ...
        methodlist_col = 4 + self.pe.sidx * 2 + 2 + (4 if self.pe.rows.get(0x06, 0) >= 65536 else 2)
        # fieldlist col is 2 or 4
        fieldlist_size = 4 if self.pe.rows.get(0x04, 0) >= 65536 else 2
        methodlist_col = 4 + self.pe.sidx * 2 + 2 + fieldlist_size
        starts = []
        for i in range(tdef):
            p = off + i * rs
            fmt = '<I' if self.pe.sidx == 4 else '<H'
            nidx = struct.unpack_from(fmt, d, p + 4)[0]
            nsidx = struct.unpack_from(fmt, d, p + 4 + self.pe.sidx)[0]
            msize = 2 if self.pe.rows.get(0x06, 0) < 65536 else 4
            ml = struct.unpack_from('<H' if msize == 2 else '<I', d, p + methodlist_col)[0]
            starts.append((f'{self.pe.string(nsidx)}.{self.pe.string(nidx)}'.strip('.'), ml))
        for i, (name, ml) in enumerate(starts):
            endm = starts[i + 1][1] if i + 1 < len(starts) else len(m) + 1
            self.type_methods.append((name, [self.method_by_idx[j] for j in range(ml, endm) if j in self.method_by_idx]))

    def method_body(self, m):
        rva = m['rva']
        if rva == 0:
            return None
        o = self.pe.rva2off(rva)
        b = self.d[o]
        if b & 3 == 2:
            size = b >> 2
            return o + 1, size
        if b & 3 == 3:
            flags_size = struct.unpack_from('<H', self.d, o)[0]
            hdr = (flags_size >> 12) * 4
            code = struct.unpack_from('<I', self.d, o + 4)[0]
            return o + hdr, code
        return None

    def strings_in(self, m):
        body = self.method_body(m)
        if not body:
            return []
        o, size = body
        code = self.d[o:o + size]
        out = []
        for i in range(len(code) - 4):
            if code[i] == 0x72:  # ldstr
                tok = struct.unpack_from('<I', code, i + 1)[0]
                if tok >> 24 == 0x70:
                    off = tok & 0xFFFFFF
                    out.append((i, off, self.us.get(off, '<bad>')))
        return out


if __name__ == '__main__':
    a = Asm(sys.argv[1])
    pat = sys.argv[2] if len(sys.argv) > 2 else None
    for tname, ms in a.type_methods:
        for m in ms:
            ss = a.strings_in(m)
            if pat:
                ss = [(i, o, s) for i, o, s in ss if pat.lower() in s.lower()]
            if ss:
                print(f'{tname}.{m["name"]} (rva {m["rva"]:x})')
                for i, o, s in ss:
                    print(f'    +{i:04x} [{o:06x}] {s!r}')
