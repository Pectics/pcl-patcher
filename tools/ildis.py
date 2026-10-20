#!/usr/bin/env python3
"""Tiny .NET IL disassembler for targeted method inspection."""
import sys, struct
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from ilscan import Asm

ONE = {
0x00:'nop',0x01:'break',0x02:'ldarg.0',0x03:'ldarg.1',0x04:'ldarg.2',0x05:'ldarg.3',
0x06:'ldloc.0',0x07:'ldloc.1',0x08:'ldloc.2',0x09:'ldloc.3',0x0A:'stloc.0',0x0B:'stloc.1',
0x0C:'stloc.2',0x0D:'stloc.3',0x0E:'ldarg.s',0x0F:'ldarga.s',0x10:'starg.s',0x11:'ldloc.s',
0x12:'ldloca.s',0x13:'stloc.s',0x14:'ldnull',0x15:'ldc.i4.m1',0x16:'ldc.i4.0',0x17:'ldc.i4.1',
0x18:'ldc.i4.2',0x19:'ldc.i4.3',0x1A:'ldc.i4.4',0x1B:'ldc.i4.5',0x1C:'ldc.i4.6',0x1D:'ldc.i4.7',
0x1E:'ldc.i4.8',0x1F:'ldc.i4.s',0x20:'ldc.i4',0x21:'ldc.i8',0x22:'ldc.r4',0x23:'ldc.r8',
0x25:'dup',0x26:'pop',0x27:'jmp',0x28:'call',0x29:'calli',0x2A:'ret',0x2B:'br.s',
0x2C:'brfalse.s',0x2D:'brtrue.s',0x2E:'beq.s',0x2F:'bge.s',0x30:'bgt.s',0x31:'ble.s',
0x32:'blt.s',0x33:'bne.un.s',0x34:'bge.un.s',0x35:'bgt.un.s',0x36:'ble.un.s',0x37:'blt.un.s',
0x38:'br',0x39:'brfalse',0x3A:'brtrue',0x3B:'beq',0x3C:'bge',0x3D:'bgt',0x3E:'ble',0x3F:'blt',
0x40:'bne.un',0x41:'bge.un',0x42:'bgt.un',0x43:'ble.un',0x44:'blt.un',0x45:'switch',
0x46:'ldind.i1',0x47:'ldind.u1',0x48:'ldind.i2',0x49:'ldind.u2',0x4A:'ldind.i4',0x4B:'ldind.u4',
0x4C:'ldind.i8',0x4D:'ldind.i',0x4E:'ldind.r4',0x4F:'ldind.r8',0x50:'ldind.ref',
0x51:'stind.ref',0x52:'stind.i1',0x53:'stind.i2',0x54:'stind.i4',0x55:'stind.i8',
0x56:'stind.r4',0x57:'stind.r8',0x58:'add',0x59:'sub',0x5A:'mul',0x5B:'div',0x5C:'div.un',
0x5D:'rem',0x5E:'rem.un',0x5F:'and',0x60:'or',0x61:'xor',0x62:'shl',0x63:'shr',0x64:'shr.un',
0x65:'neg',0x66:'not',0x67:'conv.i1',0x68:'conv.i2',0x69:'conv.i4',0x6A:'conv.i8',
0x6B:'conv.r4',0x6C:'conv.r8',0x6D:'conv.u4',0x6E:'conv.u8',0x6F:'callvirt',0x70:'cpobj',
0x71:'ldobj',0x72:'ldstr',0x73:'newobj',0x74:'castclass',0x75:'isinst',0x76:'conv.r.un',
0x79:'unbox',0x7A:'throw',0x7B:'ldfld',0x7C:'ldflda',0x7D:'stfld',0x7E:'ldsfld',0x7F:'ldsflda',
0x80:'stsfld',0x81:'stobj',0x82:'conv.ovf.i1.un',0x83:'conv.ovf.i2.un',0x84:'conv.ovf.i4.un',
0x85:'conv.ovf.i8.un',0x86:'conv.ovf.u1.un',0x87:'conv.ovf.u2.un',0x88:'conv.ovf.u4.un',
0x89:'conv.ovf.u8.un',0x8A:'conv.ovf.i.un',0x8B:'conv.ovf.u.un',0x8C:'box',0x8D:'newarr',
0x8E:'ldlen',0x8F:'ldelema',0x90:'ldelem.i1',0x91:'ldelem.u1',0x92:'ldelem.i2',0x93:'ldelem.u2',
0x94:'ldelem.i4',0x95:'ldelem.u4',0x96:'ldelem.i8',0x97:'ldelem.i',0x98:'ldelem.r4',
0x99:'ldelem.r8',0x9A:'ldelem.ref',0x9B:'stelem.i',0x9C:'stelem.i1',0x9D:'stelem.i2',
0x9E:'stelem.i4',0x9F:'stelem.i8',0xA0:'stelem.r4',0xA1:'stelem.r8',0xA2:'stelem.ref',
0xA3:'ldelem',0xA4:'stelem',0xA5:'unbox.any',0xB3:'conv.ovf.i1',0xB4:'conv.ovf.u1',
0xB5:'conv.ovf.i2',0xB6:'conv.ovf.u2',0xB7:'conv.ovf.i4',0xB8:'conv.ovf.u4',
0xB9:'conv.ovf.i8',0xBA:'conv.ovf.u8',0xC2:'refanyval',0xC3:'ckfinite',0xC6:'mkrefany',
0xD0:'ldtoken',0xD1:'conv.u2',0xD2:'conv.u1',0xD3:'conv.i',0xD4:'conv.ovf.i',0xD5:'conv.ovf.u',
0xD6:'add.ovf',0xD7:'add.ovf.un',0xD8:'mul.ovf',0xD9:'mul.ovf.un',0xDA:'sub.ovf',
0xDB:'sub.ovf.un',0xDC:'endfinally',0xDD:'leave',0xDE:'leave.s',0xDF:'stind.i',0xE0:'conv.u',
}
SIZE1 = {0x0E,0x0F,0x10,0x11,0x12,0x13,0x1F,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0xDE}
SIZE2 = {0xFE09,0xFE0A,0xFE0B,0xFE0C,0xFE0D,0xFE0E}
SIZE4 = {0x20,0x22,0x27,0x28,0x29,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x40,0x41,0x42,0x43,0x44,
         0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x79,0x7B,0x7C,0x7D,0x7E,0x7F,0x80,0x81,0x8C,0x8D,
         0x8F,0xA3,0xA4,0xA5,0xC2,0xC6,0xD0,0xDD,0xFE06,0xFE07,0xFE15,0xFE16,0xFE1C}
SIZE8 = {0x21,0x23}
FE = {0x00:'arglist',0x01:'ceq',0x02:'cgt',0x03:'cgt.un',0x04:'clt',0x05:'clt.un',0x06:'ldftn',
      0x07:'ldvirtftn',0x09:'ldarg',0x0A:'ldarga',0x0B:'starg',0x0C:'ldloc',0x0D:'ldloca',
      0x0E:'stloc',0x0F:'localloc',0x11:'endfilter',0x12:'unaligned.',0x13:'volatile.',
      0x14:'tail.',0x15:'initobj',0x16:'constrained.',0x17:'cpblk',0x18:'initblk',0x19:'no.',
      0x1A:'rethrow',0x1C:'sizeof',0x1D:'refanytype',0x1E:'readonly.'}

class Dis:
    def __init__(self, path):
        self.a = Asm(path)
        self.pe = self.a.pe
        self.d = self.pe.data
        self.typeref = {}
        self.typedef = {}
        self._parse_typerefs()
        self.memberref = {}
        self._parse_memberrefs()
        self.methodspec = {}
        self._parse_methodspecs()
        # Field names + owner
        self.fields = {}
        self._parse_fields()

    def _parse_typerefs(self):
        pe = self.pe
        if 0x01 not in pe.rows: return
        off, d = pe.table_offsets[0x01], self.d
        # ResolutionScope coded 2/4, name, ns
        rowsize = (pe.table_offsets.get(0x02, 0) - off) // pe.rows[0x01] if 0x02 in pe.rows else 2 + 2*pe.sidx
        csz = rowsize - 2*pe.sidx
        fmt = '<I' if pe.sidx == 4 else '<H'
        for i in range(pe.rows[0x01]):
            p = off + i * rowsize
            name = pe.string(struct.unpack_from(fmt, d, p + csz)[0])
            ns = pe.string(struct.unpack_from(fmt, d, p + csz + pe.sidx)[0])
            self.typeref[0x01 << 24 | (i + 1)] = f'{ns}.{name}'.strip('.')
        for i, ns, n, _ in pe.typedefs():
            self.typedef[0x02 << 24 | i] = f'{ns}.{n}'.strip('.')

    def _parse_memberrefs(self):
        pe = self.pe
        if 0x0A not in pe.rows: return
        off = pe.table_offsets[0x0A]
        d = self.d
        n = pe.rows[0x0A]
        if 0x0B in pe.rows:
            rowsize = (pe.table_offsets[0x0B] - off) // n
        else:
            rowsize = 2 + pe.sidx + pe.bidx
        csz = rowsize - pe.sidx - pe.bidx
        fmt = '<I' if pe.sidx == 4 else '<H'
        for i in range(n):
            p = off + i * rowsize
            cls = struct.unpack_from('<H' if csz == 2 else '<I', d, p)[0]
            name = pe.string(struct.unpack_from(fmt, d, p + csz)[0])
            tag = cls & 7
            ridx = cls >> 3
            owner = {0: self.typedef, 1: self.typeref}.get(tag, {}).get(({0: 0x02, 1: 0x01}.get(tag, 0) << 24) | ridx, '')
            self.memberref[0x0A000000 | (i + 1)] = f'{owner}::{name}'.lstrip(':')

    def _parse_methodspecs(self):
        pe = self.pe
        if 0x2B not in pe.rows: return
        off, d = pe.table_offsets[0x2B], self.d
        rowsize = (pe.table_offsets.get(0x2C, 0) - off) // pe.rows[0x2B] if 0x2C in pe.rows else 2 + pe.bidx
        msz = rowsize - pe.bidx
        for i in range(pe.rows[0x2B]):
            p = off + i * rowsize
            coded = struct.unpack_from('<H' if msz == 2 else '<I', d, p)[0]
            self.methodspec[0x2B000000 | (i + 1)] = (coded >> 1, coded & 1)

    def _parse_fields(self):
        pe = self.pe
        if 0x04 not in pe.rows: return
        d = self.d
        off = pe.table_offsets[0x04]
        rowsize = 2 + pe.sidx + pe.bidx
        # owner via TypeDef FieldList
        tdef_off = pe.table_offsets.get(0x02)
        owners = {}
        if tdef_off is not None:
            rs = (pe.table_offsets.get(0x03, off) - tdef_off) // pe.rows[0x02] if 0x03 in pe.rows else None
            if rs is None:
                # compute TypeDef row size from schemas
                rs = sum(pe.schemas[0x02])
            fsz = 4 if pe.rows.get(0x04, 0) >= 65536 else 2
            flcol = 4 + pe.sidx * 2 + 2
            starts = []
            for i in range(pe.rows[0x02]):
                p = tdef_off + i * rs
                fl = struct.unpack_from('<H' if fsz == 2 else '<I', d, p + flcol)[0]
                name = self.typedef.get(0x02000000 | (i + 1), '')
                starts.append((fl, name))
            for j, (fl, name) in enumerate(starts):
                end = starts[j + 1][0] if j + 1 < len(starts) else pe.rows[0x04] + 1
                for k in range(fl, end):
                    owners[k] = name
        fmt = '<I' if pe.sidx == 4 else '<H'
        for i in range(pe.rows[0x04]):
            p = off + i * rowsize
            name = pe.string(struct.unpack_from(fmt, d, p + 2)[0])
            owner = owners.get(i + 1, '')
            self.fields[0x04000000 | (i + 1)] = f'{owner}::{name}'.lstrip(':')

    def resolve(self, tok):
        t = tok >> 24
        idx = tok & 0xFFFFFF
        if t == 0x70:
            return repr(self.a.us.get(idx, '<bad>'))
        if t == 0x0A:
            return self.memberref.get(tok, 'memberref#%x' % idx)
        if t == 0x2B:
            info = self.methodspec.get(tok)
            if info:
                ridx, is_ref = info
                inner = (0x0A if is_ref else 0x06) << 24 | ridx
                return '<' + self.resolve(inner) + '>'
            return 'methodspec#%x' % idx
        if t == 0x04:
            return self.fields.get(tok, 'field#%x' % idx)
        if t == 0x06:
            m = self.a.method_by_idx.get(idx)
            owner = ''
            for tname, ms in self.a.type_methods:
                if any(x is m for x in ms):
                    owner = tname
                    break
            return f'{owner}::{m["name"]}'.lstrip(':') if m else 'method#%x' % idx
        if t in (0x01, 0x02, 0x1B):
            if t == 0x02:
                return self.typedef.get(tok, 'type#%x' % idx)
            if t == 0x01:
                return self.typeref.get(tok, 'typeref#%x' % idx)
            return 'typespec#%x' % idx
        return 'tok#%08x' % tok

    def disasm(self, target):
        found = False
        for tname, ms in self.a.type_methods:
            for m in ms:
                label = f'{tname}.{m["name"]}'
                if target.lower() not in label.lower():
                    continue
                found = True
                body = self.a.method_body(m)
                print(f'--- {label} rva={m["rva"]:x} ---')
                if not body:
                    print('  <no body>'); continue
                o, size = body
                code = self.d[o:o + size]
                yield (label, o, code)
                self._print_code(o, code)
        if not found:
            print('no method matched', target)

    def _print_code(self, base, code):
        i = 0
        while i < len(code):
            start = i
            b = code[i]
            if b == 0xFE:
                op2 = code[i+1]; i += 2; op = FE.get(op2, 'fe%02x' % op2); key = 0xFE00 | op2
            else:
                op = ONE.get(b, 'op%02x' % b); i += 1; key = b
            if key in SIZE1:
                arg = struct.unpack_from('<b', code, i)[0]; i += 1; res = str(arg)
                extra = ''
            elif key in SIZE2:
                res = str(struct.unpack_from('<H', code, i)[0]); i += 2; extra = ''
            elif key in SIZE8:
                res = str(struct.unpack_from('<q', code, i)[0]); i += 8; extra = ''
            elif key == 0x45:
                n = struct.unpack_from('<I', code, i)[0]; i += 4
                tgts = [struct.unpack_from('<i', code, i + 4*j)[0] for j in range(n)]; i += 4*n
                res = str(tgts); extra = ''
            elif key in SIZE4:
                tok = struct.unpack_from('<I', code, i)[0]; i += 4
                if key in (0x28,0x6F,0x73,0xFE06,0xFE07,0xD0,0x7B,0x7C,0x7D,0x7E,0x7F,0x80,0x72):
                    res = self.resolve(tok)
                else:
                    res = hex(tok)
                extra = ''
                if key in (0x2B,0x2C,0x2D) or 0x2E <= key <= 0x37:
                    pass
            else:
                res = ''; extra = ''
            print(f'  IL_{start:04x}: {op:12s} {res}')
            if i <= start:
                break


if __name__ == '__main__':
    d = Dis(sys.argv[1])
    for _ in d.disasm(sys.argv[2]):
        pass
