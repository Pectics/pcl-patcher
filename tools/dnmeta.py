#!/usr/bin/env python3
"""Minimal .NET PE metadata reader (no external deps).

Extracts:
  - assembly identity
  - #Strings heap (type/method/field names)
  - #US heap (user strings) with their heap offsets
  - metadata tables (TypeDef, MethodDef, MemberRef, TypeRef)
  - method RVA/size (for locating IL)
  - raw file offset mapping for RVA
"""
import struct

def u8(d, o): return d[o]
def u16(d, o): return struct.unpack_from('<H', d, o)[0]
def u32(d, o): return struct.unpack_from('<I', d, o)[0]
def u64(d, o): return struct.unpack_from('<Q', d, o)[0]

class PE:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        d = self.data
        self.pe_off = u32(d, 0x3c)
        assert d[self.pe_off:self.pe_off+4] == b'PE\0\0'
        coff = self.pe_off + 4
        self.n_sections = u16(d, coff + 2)
        self.opt_size = u16(d, coff + 16)
        opt = coff + 20
        self.magic = u16(d, opt)
        self.image_base = u64(d, opt + 24) if self.magic == 0x20b else u32(d, opt + 28)
        self.section_alignment = u32(d, opt + 32)
        self.file_alignment = u32(d, opt + 36)
        dd = opt + (112 if self.magic == 0x20b else 96)
        self.dirs = [(u32(d, dd + i*8), u32(d, dd + i*8 + 4)) for i in range(16)]
        self.sections = []
        s = opt + self.opt_size
        for i in range(self.n_sections):
            o = s + i*40
            name = d[o:o+8].rstrip(b'\0').decode('latin1')
            vsize, va, rsize, rptr = struct.unpack_from('<IIII', d, o + 8)
            self.sections.append(dict(name=name, va=va, vsize=vsize, rsize=rsize, rptr=rptr, off=o))
        self.cli_rva, self.cli_size = self.dirs[14]
        self.cli_off = self.rva2off(self.cli_rva)
        assert u32(d, self.cli_off) == 0x48
        self.meta_rva, self.meta_size = u32(d, self.cli_off+8), u32(d, self.cli_off+12)
        self.meta_off = self.rva2off(self.meta_rva)
        self.parse_metadata()

    def rva2off(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['vsize'], s['rsize']):
                return s['rptr'] + (rva - s['va'])
        raise ValueError('bad rva %x' % rva)

    def off2rva(self, off):
        for s in self.sections:
            if s['rptr'] <= off < s['rptr'] + s['rsize']:
                return s['va'] + (off - s['rptr'])
        raise ValueError('bad off %x' % off)

    def parse_metadata(self):
        d = self.data
        o = self.meta_off
        assert u32(d, o) == 0x424A5342  # BSJB
        ver_len = u32(d, o + 12)
        p = o + 16 + ver_len
        p += 2 + 2  # flags, streams
        nstreams = u16(d, p - 2)
        self.streams = {}
        for _ in range(nstreams):
            soff, ssize = u32(d, p), u32(d, p + 4)
            p += 8
            end = d.index(b'\0', p)
            name = d[p:end].decode('ascii')
            p = (end + 4) & ~3
            self.streams[name] = (self.meta_off + soff, ssize)
        self.tables_off, self.tables_size = self.streams['#~']
        self.strings_off, self.strings_size = self.streams.get('#Strings', (0, 0))
        self.us_off, self.us_size = self.streams.get('#US', (0, 0))
        self.blob_off, self.blob_size = self.streams.get('#Blob', (0, 0))
        self.parse_tables()

    def string(self, idx):
        o = self.strings_off + idx
        e = self.data.index(b'\0', o)
        return self.data[o:e].decode('utf-8', 'replace')

    def user_string(self, idx):
        o = self.us_off + idx
        b = self.data[o]
        if b & 0x80 == 0:
            n, p = b, o + 1
        elif b & 0xC0 == 0x80:
            n, p = ((b & 0x3f) << 8) | self.data[o+1], o + 2
        else:
            n, p = ((b & 0x1f) << 24) | (self.data[o+1] << 16) | (self.data[o+2] << 8) | self.data[o+3], o + 4
        raw = self.data[p:p+n-1]  # trailing byte is a flag
        return raw.decode('utf-16-le', 'replace')

    def parse_tables(self):
        d = self.data
        o = self.tables_off
        heap_sizes = d[o + 6]
        valid = u64(d, o + 8)
        p = o + 24
        rows = {}
        for i in range(64):
            if valid >> i & 1:
                rows[i] = u32(d, p); p += 4
        self.rows = rows
        self.sidx = 4 if heap_sizes & 1 else 2
        self.gidx = 4 if heap_sizes & 2 else 2
        self.bidx = 4 if heap_sizes & 4 else 2

        def idx(tid):
            n = rows.get(tid, 0)
            return 4 if n >= 0x10000 else 2

        def coded(tables, bits):
            n = max(rows.get(t, 0) for t in tables)
            return 4 if n >= (1 << (16 - bits)) else 2

        S, G, B = self.sidx, self.gidx, self.bidx
        tdor = coded([0x02, 0x01, 0x1B], 2)
        hca = coded([0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17,
                     0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A,
                     0x2C, 0x0C], 5)
        rs = coded([0x00, 0x1A, 0x23, 0x01], 2)
        mrp = coded([0x02, 0x01, 0x1A, 0x06, 0x1B], 3)
        cat = coded([0x06, 0x0A], 3)
        # Table schemas as list of column sizes in bytes.
        schemas = {
            0x00: [2, S, G, G, G],
            0x01: [rs, S, S],
            0x02: [4, S, S, tdor, idx(0x04), idx(0x06)],
            0x03: [idx(0x04)],
            0x04: [2, S, B],
            0x05: [idx(0x06)],
            0x06: [4, 2, 2, S, B, idx(0x08)],
            0x07: [idx(0x08)],
            0x08: [2, 2, S],
            0x09: [idx(0x02), tdor],
            0x0A: [mrp, S, B],
            0x0B: [2, coded([0x04, 0x08, 0x17], 2), B],
            0x0C: [hca, cat, B],
            0x0D: [coded([0x04, 0x08], 1), B],
            0x0E: [2, coded([0x02, 0x06, 0x20], 2), B],
            0x0F: [2, 4, idx(0x02)],
            0x10: [4, idx(0x04)],
            0x11: [B],
            0x12: [idx(0x02), idx(0x14)],
            0x13: [idx(0x14)],
            0x14: [2, S, tdor],
            0x15: [idx(0x02), idx(0x17)],
            0x16: [idx(0x17)],
            0x17: [2, S, B],
            0x18: [2, idx(0x06), coded([0x14, 0x17], 1)],
            0x19: [idx(0x02), coded([0x06, 0x0A], 1), coded([0x06, 0x0A], 1)],
            0x1A: [S],
            0x1B: [B],
            0x1C: [2, coded([0x04, 0x06], 1), S, idx(0x1A)],
            0x1D: [4, idx(0x04)],
            0x1E: [4, 4],
            0x1F: [4],
            0x20: [4, 2, 2, 2, 2, 4, B, S, S],
            0x21: [4],
            0x22: [4, 4, 4],
            0x23: [2, 2, 2, 2, 4, B, S, S, B],
            0x24: [4, idx(0x23)],
            0x25: [4, 4, 4, idx(0x23)],
            0x26: [4, S, B],
            0x27: [4, 4, S, S, coded([0x26, 0x23, 0x27], 2)],
            0x28: [4, 4, S, coded([0x26, 0x23, 0x27], 2)],
            0x29: [idx(0x02), idx(0x02)],
            0x2A: [2, 2, coded([0x02, 0x06], 1), S],
            0x2B: [coded([0x06, 0x0A], 1), B],
            0x2C: [idx(0x2A), tdor],
        }
        table_offsets = {}
        t = p
        for tid in sorted(rows):
            table_offsets[tid] = t
            if tid not in schemas:
                raise NotImplementedError('table 0x%x not in schemas' % tid)
            t += rows[tid] * sum(schemas[tid])
        self.table_offsets = table_offsets
        self.schemas = schemas

    def typedefs(self):
        d = self.data
        if 0x02 not in self.rows: return []
        o = self.table_offsets[0x02]
        r = self.schemas[0x02]
        out = []
        for i in range(self.rows[0x02]):
            p = o + i * sum(r)
            flags = u32(d, p)
            name = self.string(struct.unpack_from('<I' if self.sidx == 4 else '<H', d, p + 4)[0])
            ns = self.string(struct.unpack_from('<I' if self.sidx == 4 else '<H', d, p + 4 + self.sidx)[0])
            out.append((i + 1, ns, name, flags))
        return out

    def methoddefs(self):
        d = self.data
        if 0x06 not in self.rows: return []
        o = self.table_offsets[0x06]
        r = self.schemas[0x06]
        out = []
        for i in range(self.rows[0x06]):
            p = o + i * sum(r)
            rva = u32(d, p)
            impl = u16(d, p + 4)
            flags = u16(d, p + 6)
            name = self.string(struct.unpack_from('<I' if self.sidx == 4 else '<H', d, p + 8)[0])
            sig = struct.unpack_from('<I' if self.bidx == 4 else '<H', d, p + 8 + self.sidx)[0]
            out.append(dict(idx=i + 1, rva=rva, impl=impl, flags=flags, name=name, sig=sig))
        return out

    def assembly(self):
        d = self.data
        if 0x20 not in self.rows: return None
        o = self.table_offsets[0x20]
        # Assembly: HashAlgId(4) Major(2) Minor(2) Build(2) Rev(2) Flags(4) PublicKey(blob) Name(str) Culture(str)
        p = o
        p += 4
        major, minor, build, rev = struct.unpack_from('<HHHH', d, p); p += 8
        flags = u32(d, p); p += 4
        p += self.bidx
        name = self.string(struct.unpack_from('<I' if self.sidx == 4 else '<H', d, p)[0]); p += self.sidx
        culture = self.string(struct.unpack_from('<I' if self.sidx == 4 else '<H', d, p)[0])
        return dict(name=name, version=f'{major}.{minor}.{build}.{rev}', culture=culture)

    def user_strings(self):
        """Yield (heap_offset, string) for every entry in #US."""
        d = self.data
        o = self.us_off
        end = o + self.us_size
        p = o + 1  # first byte is 0
        while p < end:
            start = p
            b = d[p]
            if b & 0x80 == 0:
                n, p = b, p + 1
            elif b & 0xC0 == 0x80:
                n, p = ((b & 0x3f) << 8) | d[p+1], p + 2
            else:
                n, p = ((b & 0x1f) << 24) | (d[p+1] << 16) | (d[p+2] << 8) | d[p+3], p + 4
            if n == 0:
                continue
            raw = d[p:p+n-1]
            p += n
            yield start, raw.decode('utf-16-le', 'replace')

if __name__ == '__main__':
    import sys
    pe = PE(sys.argv[1])
    print('sections:', [(s['name'], hex(s['va']), hex(s['rptr']), hex(s['rsize'])) for s in pe.sections])
    print('assembly:', pe.assembly())
    print('rows:', {hex(k): v for k, v in sorted(pe.rows.items())})
    print('streams:', {k: (hex(v[0]), v[1]) for k, v in pe.streams.items()})
    print('types:', len(pe.typedefs()), 'methods:', len(pe.methoddefs()))
