#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcl_download_unlock.py
======================

为 PCL2（Plain Craft Launcher 2）2.99.0.0 恢复原版 Minecraft 下载功能。

背景
----
2.99.0.0 中，下载页（PageDownloadInstall）的 LoaderInit 被替换成了一个
“占位加载器”：它只显示“关闭下载”按钮，并在被启动时抛出

    为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……

原有的版本列表加载器 DlClientListLoader、Mojang/BMCLAPI 版本清单请求、
安装逻辑、资源下载逻辑都仍然完整地保留在程序里。本工具只重写
PageDownloadInstall.LoaderInit 的方法体，让它像旧版一样正常启动
DlClientListLoader，从而恢复版本列表 → 选择版本 → 安装游戏 的完整链路。

安全性
------
* 只修改目标方法的 IL 指令区，不增加/移动任何节区，不修改元数据。
* 修改前会校验程序集版本、方法指纹与所有 token 的指向；不匹配则拒绝修改。
* 程序集未强名称签名，也没有 Authenticode 签名。
* 默认输出到新文件，不覆盖原文件。

用法
----
    python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe"
    python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe" -o "PCL-unlocked.exe"
    python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe" --dry-run
    python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe" --in-place
"""

import argparse
import hashlib
import os
import struct
import sys

# ---------------------------------------------------------------------------
# 常量 / 指纹
# ---------------------------------------------------------------------------

TARGET_ASSEMBLY = "Plain Craft Launcher 2"
TARGET_VERSION = "2.99.0.0"

TYPE_PAGE = ("PCL", "PageDownloadInstall")
TYPE_RIGHT = ("PCL", "MyPageRight")
TYPE_MODDL = ("PCL", "ModDownload")

BAN_TEXT = "为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……"
BAN_TEXT_OFFSET = 0x1A  # ldstr BAN_TEXT 在 LoaderInit 原始方法体中的偏移

# 旧版本（2.13.1.1）中同样的调用形状，用于最终说明
NEW_IL_NOTE = """
期望补丁后的 LoaderInit 逻辑（VB 伪代码）：

    ControlInit()
    PageLoaderInit(
        LoadMinecraft, PanLoad, PanAllBack,
        Nothing,
        DlClientListLoader,
        New Action(AddressOf LoadMinecraft_OnFinish),
        Nothing,
        autoRun:=True)
"""

# ---------------------------------------------------------------------------
# 极简 PE / .NET 元数据解析
# ---------------------------------------------------------------------------

class PEError(Exception):
    pass


def _u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def _u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def _u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


class NetPE:
    def __init__(self, data):
        self.d = data
        d = data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEError("不是 PE 文件")
        pe = _u32(d, 0x3C)
        if d[pe:pe + 4] != b"PE\0\0":
            raise PEError("不是 PE 文件（缺少 PE 签名）")
        self.pe_off = pe
        coff = pe + 4
        nsec = _u16(d, coff + 2)
        optsz = _u16(d, coff + 16)
        opt = coff + 20
        self.magic = _u16(d, opt)
        self.checksum_off = opt + 64
        dd = opt + (112 if self.magic == 0x20B else 96)
        self.dirs = [(_u32(d, dd + i * 8), _u32(d, dd + i * 8 + 4))
                     for i in range(16)]
        self.sections = []
        s = opt + optsz
        for i in range(nsec):
            o = s + i * 40
            name = d[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
            self.sections.append(dict(name=name, va=va, vsize=vsize,
                                      rsize=rsize, rptr=rptr))
        cli_rva, cli_size = self.dirs[14]
        if not cli_rva:
            raise PEError("不是 .NET 程序集（缺少 CLI 头）")
        self.cli_off = self.rva2off(cli_rva)
        if _u32(d, self.cli_off) != 0x48:
            raise PEError("CLI 头格式异常")
        meta_rva = _u32(d, self.cli_off + 8)
        self.meta_off = self.rva2off(meta_rva)
        self._parse_metadata()

    def rva2off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                return s["rptr"] + (rva - s["va"])
        raise PEError("RVA 0x%X 不在任何节中" % rva)

    # -- metadata -----------------------------------------------------------
    def _parse_metadata(self):
        d, o = self.d, self.meta_off
        if _u32(d, o) != 0x424A5342:
            raise PEError("无效的元数据签名（BSJB）")
        ver_len = _u32(d, o + 12)
        p = o + 16 + ver_len
        p += 4  # flags + stream count
        nstreams = _u16(d, p - 2)
        self.streams = {}
        for _ in range(nstreams):
            soff, ssize = _u32(d, p), _u32(d, p + 4)
            p += 8
            end = d.index(b"\0", p)
            name = d[p:end].decode("ascii")
            p = (end + 4) & ~3
            self.streams[name] = (self.meta_off + soff, ssize)
        if "#~" not in self.streams or "#Strings" not in self.streams:
            raise PEError("缺少 #~ / #Strings 元数据流")
        self.tables_off, _ = self.streams["#~"]
        self.strings_off, self.strings_size = self.streams["#Strings"]
        self.us_off, self.us_size = self.streams.get("#US", (0, 0))
        self.blob_off, self.blob_size = self.streams.get("#Blob", (0, 0))
        self._parse_tables()

    def string(self, idx):
        o = self.strings_off + idx
        e = self.d.index(b"\0", o)
        return self.d[o:e].decode("utf-8", "replace")

    def user_string(self, idx):
        d, o = self.d, self.us_off + idx
        b = d[o]
        if b & 0x80 == 0:
            n, p = b, o + 1
        elif b & 0xC0 == 0x80:
            n, p = ((b & 0x3F) << 8) | d[o + 1], o + 2
        else:
            n, p = (((b & 0x1F) << 24) | (d[o + 1] << 16) |
                    (d[o + 2] << 8) | d[o + 3]), o + 4
        return d[p:p + n - 1].decode("utf-16-le", "replace")

    def blob(self, idx):
        d, o = self.d, self.blob_off + idx
        b = d[o]
        if b & 0x80 == 0:
            n, p = b, o + 1
        elif b & 0xC0 == 0x80:
            n, p = ((b & 0x3F) << 8) | d[o + 1], o + 2
        else:
            n, p = (((b & 0x1F) << 24) | (d[o + 1] << 16) |
                    (d[o + 2] << 8) | d[o + 3]), o + 4
        return d[p:p + n]

    def _parse_tables(self):
        d, o = self.d, self.tables_off
        heap_sizes = d[o + 6]
        valid = _u64(d, o + 8)
        p = o + 24
        rows = {}
        for i in range(64):
            if valid >> i & 1:
                rows[i] = _u32(d, p)
                p += 4
        self.rows = rows
        S = 4 if heap_sizes & 1 else 2
        G = 4 if heap_sizes & 2 else 2
        B = 4 if heap_sizes & 4 else 2
        self.sidx, self.gidx, self.bidx = S, G, B

        def idx(tid):
            return 4 if rows.get(tid, 0) >= 0x10000 else 2

        def coded(tables, bits):
            n = max(rows.get(t, 0) for t in tables)
            return 4 if n >= (1 << (16 - bits)) else 2

        tdor = coded([0x02, 0x01, 0x1B], 2)
        hca = coded([0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E,
                     0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27,
                     0x28, 0x2A, 0x2C, 0x0C], 5)
        rs = coded([0x00, 0x1A, 0x23, 0x01], 2)
        mrp = coded([0x02, 0x01, 0x1A, 0x06, 0x1B], 3)
        cat = coded([0x06, 0x0A], 3)
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
            0x19: [idx(0x02), coded([0x06, 0x0A], 1),
                   coded([0x06, 0x0A], 1)],
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
        self.schemas = schemas
        self.table_offsets = {}
        t = p
        for tid in sorted(rows):
            if tid not in schemas:
                raise PEError("不支持的元数据表 0x%X" % tid)
            self.table_offsets[tid] = t
            t += rows[tid] * sum(schemas[tid])

    # -- typed rows ---------------------------------------------------------
    def typedefs(self):
        """[(rid, namespace, name, flags, field_start, method_start)]"""
        d = self.d
        if 0x02 not in self.rows:
            return []
        o = self.table_offsets[0x02]
        rs = sum(self.schemas[0x02])
        fmt = "<I" if self.sidx == 4 else "<H"
        fl_size = 4 if self.rows.get(0x04, 0) >= 65536 else 2
        ml_size = 4 if self.rows.get(0x06, 0) >= 65536 else 2
        fl_col = 4 + self.sidx * 2 + 2
        ml_col = fl_col + fl_size
        out = []
        for i in range(self.rows[0x02]):
            p = o + i * rs
            flags = _u32(d, p)
            name = self.string(struct.unpack_from(fmt, d, p + 4)[0])
            ns = self.string(struct.unpack_from(fmt, d, p + 4 + self.sidx)[0])
            fl = struct.unpack_from("<I" if fl_size == 4 else "<H",
                                    d, p + fl_col)[0]
            ml = struct.unpack_from("<I" if ml_size == 4 else "<H",
                                    d, p + ml_col)[0]
            out.append((i + 1, ns, name, flags, fl, ml))
        return out

    def methoddefs(self):
        """[(rid, rva, name, sig)]"""
        d = self.d
        if 0x06 not in self.rows:
            return []
        o = self.table_offsets[0x06]
        rs = sum(self.schemas[0x06])
        fmt = "<I" if self.sidx == 4 else "<H"
        bfmt = "<I" if self.bidx == 4 else "<H"
        out = []
        for i in range(self.rows[0x06]):
            p = o + i * rs
            rva = _u32(d, p)
            name = self.string(struct.unpack_from(fmt, d, p + 8)[0])
            sig = struct.unpack_from(bfmt, d, p + 8 + self.sidx)[0]
            out.append((i + 1, rva, name, sig))
        return out

    def fielddefs(self):
        """[(rid, name)]"""
        d = self.d
        if 0x04 not in self.rows:
            return []
        o = self.table_offsets[0x04]
        rs = sum(self.schemas[0x04])
        fmt = "<I" if self.sidx == 4 else "<H"
        out = []
        for i in range(self.rows[0x04]):
            p = o + i * rs
            out.append((i + 1, self.string(struct.unpack_from(fmt, d, p + 2)[0])))
        return out

    def assembly_identity(self):
        d = self.d
        if 0x20 not in self.rows:
            return None
        o = self.table_offsets[0x20]
        major, minor, build, rev = struct.unpack_from("<HHHH", d, o + 4)
        p = o + 16 + self.bidx
        fmt = "<I" if self.sidx == 4 else "<H"
        name = self.string(struct.unpack_from(fmt, d, p)[0])
        return name, "%d.%d.%d.%d" % (major, minor, build, rev)

    def method_body(self, rva):
        o = self.rva2off(rva)
        b = self.d[o]
        kind = b & 3
        if kind == 2:  # tiny
            size = b >> 2
            return o, 1, size, False
        if kind == 3:  # fat
            flags_size = _u16(self.d, o)
            hdr = (flags_size >> 12) * 4
            size = _u32(self.d, o + 4)
            more_sects = bool(flags_size & 0x8)
            return o, hdr, size, more_sects
        raise PEError("未知的方法头格式")


# ---------------------------------------------------------------------------
# IL 指令长度（仅用于线性扫描，足够覆盖 LoaderInit）
# ---------------------------------------------------------------------------

_ONE = {0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1, 0x1F: 1,
        0x2B: 1, 0x2C: 1, 0x2D: 1, 0x2E: 1, 0x2F: 1, 0x30: 1, 0x31: 1,
        0x32: 1, 0x33: 1, 0x34: 1, 0x35: 1, 0x36: 1, 0x37: 1, 0xDE: 1}
_FOUR = {0x20, 0x22, 0x27, 0x28, 0x29, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
         0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x6F, 0x70,
         0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7B, 0x7C, 0x7D, 0x7E,
         0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5, 0xC2,
         0xC6, 0xD0, 0xDD}
_FE = {0x06, 0x07, 0x15, 0x16, 0x1C}
_FE_TWO = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}
_EIGHT = {0x21, 0x23}


def il_walk(code):
    """生成 (offset, opcode, operand_bytes)。"""
    i = 0
    n = len(code)
    while i < n:
        start = i
        b = code[i]
        if b == 0xFE:
            if i + 1 >= n:
                break
            op = 0xFE00 | code[i + 1]
            i += 2
            if (code[i - 1] in _FE_TWO):
                size = 2
            elif code[i - 1] in _FE:
                size = 4
            elif code[i - 1] in (0x12, 0x13, 0x14, 0x19, 0x1E):
                size = 1
            else:
                size = 0
        else:
            op = b
            i += 1
            if b in _EIGHT:
                size = 8
            elif b in _FOUR:
                size = 4
            elif b in _ONE:
                size = 1
            elif b == 0x45:  # switch
                cnt = _u32(code, i)
                size = 4 + 4 * cnt
            else:
                size = 0
        operand = code[i:i + size]
        i += size
        yield start, op, operand


def il_find(code, op, operand=None):
    return [(off, opb) for off, o, opb in il_walk(code)
            if o == op and (operand is None or opb == operand)]


# ---------------------------------------------------------------------------
# 定位与补丁
# ---------------------------------------------------------------------------

class Unlocker:
    def __init__(self, data):
        self.data = bytearray(data)
        self.pe = NetPE(bytes(data))
        self.types = {("%s.%s" % (ns, name) if ns else name): (rid, fl, ml)
                      for rid, ns, name, flags, fl, ml in self.pe.typedefs()}
        self.methods = {rid: (rva, name, sig)
                        for rid, rva, name, sig in self.pe.methoddefs()}
        self.fields = {rid: name for rid, name in self.pe.fielddefs()}

    def type_range(self, fullname):
        key = ".".join(fullname) if isinstance(fullname, tuple) else fullname
        if key not in self.types:
            raise PEError("找不到类型 %s" % key)
        rid, fl, ml = self.types[key]
        # MethodDef / Field 表按 TypeDef 的 MethodList / FieldList 连续排列；
        # 下一个区的起点（或表尾）就是本类型的结束。
        m_end = next((x[2] for x in self.types.values() if x[2] > ml),
                     len(self.methods) + 1)
        f_end = next((x[1] for x in self.types.values() if x[1] > fl),
                     len(self.fields) + 1)
        return (ml, m_end, fl, f_end)

    def find_method(self, typename, name):
        ms, me, _, _ = self.type_range(typename)
        for rid in range(ms, me):
            if rid in self.methods and self.methods[rid][1] == name:
                return rid, self.methods[rid][0]
        raise PEError("找不到方法 %s::%s" % (typename, name))

    def find_field(self, typename, name):
        _, _, fs, fe = self.type_range(typename)
        for rid in range(fs, fe):
            if self.fields.get(rid) == name:
                return 0x04000000 | rid
        raise PEError("找不到字段 %s::%s" % (typename, name))

    # ------------------------------------------------------------------
    def locate(self):
        self.loader_mid, self.loader_rva = self.find_method(
            TYPE_PAGE, "LoaderInit")
        self.loader_field_tok = self.find_field(TYPE_MODDL, "DlClientListLoader")
        self.m_loading = self.find_method(TYPE_PAGE, "get_LoadMinecraft")[0]
        self.m_panload = self.find_method(TYPE_PAGE, "get_PanLoad")[0]
        self.m_panback = self.find_method(TYPE_PAGE, "get_PanAllBack")[0]

        # 读取方法头与代码
        body_off, hdr, code_size, more = self.pe.method_body(self.loader_rva)
        self.body_off, self.hdr, self.code_size, self.more_sects = (
            body_off, hdr, code_size, more)
        self.code_off = body_off + hdr
        code = bytes(self.data[self.code_off:self.code_off + code_size])

        # 指纹 1：开头必须是 ControlInit()
        control_rid, _ = self.find_method(TYPE_PAGE, "ControlInit")
        self.m_controlinit = control_rid
        tok = lambda rid: struct.pack("<I", 0x06000000 | rid)
        expect_head = b"\x02\x28" + tok(control_rid)
        if code[:len(expect_head)] != expect_head:
            raise PEError(
                "LoaderInit 指纹不匹配（方法开头不是 ControlInit 调用）。\n"
                "这可能不是 2.99.0.0，或已经被修改过。")

        # 幂等：已打过补丁的识别
        patched_head = (expect_head + b"\x02\x02\x6f" + tok(self.m_loading) +
                        b"\x02\x6f" + tok(self.m_panload) +
                        b"\x02\x6f" + tok(self.m_panback) +
                        b"\x14\x7e" + struct.pack("<I", self.loader_field_tok))
        if code.startswith(patched_head):
            self.already_patched = True
            return code
        # 指纹 2：包含“关闭下载”字符串
        ldstr = [(o, struct.unpack('<I', opb)[0])
                 for o, op, opb in il_walk(code) if op == 0x72]
        self.ban_str_off = None
        for off, tok in ldstr:
            if tok >> 24 == 0x70:
                s = self.pe.user_string(tok & 0xFFFFFF)
                if s == "关闭下载":
                    self.ban_str_off = off
                    break
        if self.ban_str_off is None:
            raise PEError("LoaderInit 指纹不匹配（找不到“关闭下载”占位按钮）。")

        # 从原始 IL 中提取可复用的 token
        # 末尾形状: ldnull (14), ldc.i4.1 (17), call <PageLoaderInit>
        calls = il_find(code, 0x28)
        if not calls:
            raise PEError("LoaderInit 中找不到 PageLoaderInit 调用")
        call_off, call_operand = calls[-1]
        call_tok = struct.unpack("<I", call_operand)[0]
        self.page_loader_callspec = call_tok
        if call_tok >> 24 != 0x2B:
            raise PEError("PageLoaderInit 不是泛型方法调用（token 0x%08X）" % call_tok)
        prev = [x for x in il_walk(code) if x[0] < call_off][-2:]
        if not (prev[0][1] == 0x14 and prev[1][1] == 0x17):
            raise PEError("LoaderInit 末尾参数形状异常（预期 Nothing, True）")

        # newobj <delegate ctor> 紧挨在 ldnull; ldc.i4.1 之前
        before = [x for x in il_walk(code) if x[0] < prev[0][0]]
        if not before or before[-1][1] != 0x73:
            raise PEError("找不到完成回调委托的构造指令")
        del_off, _, del_op = before[-1]
        self.delegate_ctor_tok = struct.unpack("<I", del_op)[0]
        # ldftn <lambda> 紧挨在 newobj 之前
        before2 = [x for x in il_walk(code) if x[0] < del_off]
        if not before2 or before2[-1][1] != 0xFE06:
            raise PEError("找不到完成回调 lambda")
        _, _, ftn_op = before2[-1]
        self.finish_lambda_tok = struct.unpack("<I", ftn_op)[0]

        # 校验 MethodSpec → PageLoaderInit
        ms_rid = call_tok & 0xFFFFFF
        target = self._methodspec_target(ms_rid)
        if target != self.find_method(TYPE_RIGHT, "PageLoaderInit")[0]:
            raise PEError("PageLoaderInit 调用目标校验失败")
        # 校验 lambda 属于 PageDownloadInstall
        lambda_rid = self.finish_lambda_tok & 0xFFFFFF
        if not (self.type_range(TYPE_PAGE)[0] <= lambda_rid <
                self.type_range(TYPE_PAGE)[1]):
            raise PEError("完成回调 lambda 不属于 PageDownloadInstall")
        # 校验字段名
        if self.loader_field_tok & 0xFFFFFF not in self.fields:
            raise PEError("DlClientListLoader 字段 token 无效")
        return code

    def _methodspec_target(self, rid):
        pe = self.pe
        if 0x2B not in pe.rows or not (1 <= rid <= pe.rows[0x2B]):
            raise PEError("MethodSpec 索引无效")
        o = pe.table_offsets[0x2B]
        rs = sum(pe.schemas[0x2B])
        p = o + (rid - 1) * rs
        coded = _u16(pe.d, p) if rs - pe.bidx == 2 else _u32(pe.d, p)
        target_rid, is_ref = coded >> 1, coded & 1
        if is_ref:
            raise PEError("PageLoaderInit 解析到了 MemberRef")
        return target_rid

    # ------------------------------------------------------------------
    def build_il(self):
        tok = lambda rid: struct.pack("<I", 0x06000000 | rid)
        code = bytearray()
        code += b"\x02\x28" + tok(self.m_controlinit)  # Me.ControlInit()
        code += b"\x02"                       # ldarg.0
        code += b"\x02"                       # ldarg.0
        code += b"\x6F" + tok(self.m_loading)  # callvirt get_LoadMinecraft
        code += b"\x02"                       # ldarg.0
        code += b"\x6F" + tok(self.m_panload)  # callvirt get_PanLoad
        code += b"\x02"                       # ldarg.0
        code += b"\x6F" + tok(self.m_panback)  # callvirt get_PanAllBack
        code += b"\x14"                       # ldnull
        code += b"\x7E" + struct.pack("<I", self.loader_field_tok)  # ldsfld
        code += b"\x02"                       # ldarg.0
        code += b"\xFE\x06" + struct.pack("<I", self.finish_lambda_tok)  # ldftn
        code += b"\x73" + struct.pack("<I", self.delegate_ctor_tok)      # newobj
        code += b"\x14"                       # ldnull
        code += b"\x17"                       # ldc.i4.1
        code += b"\x28" + struct.pack("<I", self.page_loader_callspec)  # call
        code += b"\x2A"                       # ret
        return bytes(code)

    def _find_methodspec(self, method_rid):
        pe = self.pe
        if 0x2B not in pe.rows:
            raise PEError("没有 MethodSpec 表")
        o = pe.table_offsets[0x2B]
        rs = sum(pe.schemas[0x2B])
        for i in range(pe.rows[0x2B]):
            p = o + i * rs
            coded = _u16(pe.d, p) if rs - pe.bidx == 2 else _u32(pe.d, p)
            if (coded >> 1) == method_rid and (coded & 1) == 0:
                return i + 1
        raise PEError("找不到 PageLoaderInit 的 MethodSpec")

    # ------------------------------------------------------------------
    def apply(self, dry_run=False):
        original = self.locate()
        if getattr(self, "already_patched", False):
            return dict(changed=False, new_il=b"", original=original)
        new_il = self.build_il()
        if len(new_il) > self.code_size:
            raise PEError("补丁代码 %d 字节，超过方法体空间 %d 字节" %
                          (len(new_il), self.code_size))

        # 幂等：已经打过补丁
        if original[:len(new_il)] == new_il:
            return dict(changed=False, new_il=new_il, original=original)

        # 注意：填充必须使用 ret (0x2A)，不能使用 nop (0x00)。
        # .NET Framework 的 JIT 会把 ret 之后、方法末尾的 nop 视为
        # “可落入方法末尾”的不可达路径，从而抛出 InvalidProgramException。
        patched = new_il + b"\x2a" * (self.code_size - len(new_il))
        if not dry_run:
            self.data[self.code_off:self.code_off + self.code_size] = patched
        return dict(changed=True, new_il=new_il, original=original)


# ---------------------------------------------------------------------------
# 校验输出
# ---------------------------------------------------------------------------

def verify_patched(data, expected_il):
    pe = NetPE(data)
    types = {("%s.%s" % (ns, name) if ns else name): (rid, fl, ml)
             for rid, ns, name, flags, fl, ml in pe.typedefs()}
    if "PCL.PageDownloadInstall" not in types:
        raise PEError("补丁后找不到 PageDownloadInstall")
    # 找 LoaderInit
    ml = types["PCL.PageDownloadInstall"][2]
    mrows = {rid: (rva, name) for rid, rva, name, sig in pe.methoddefs()}
    rva = None
    for rid in sorted(mrows):
        if rid >= ml and mrows[rid][1] == "LoaderInit":
            rva = mrows[rid][0]
            break
    o, hdr, size, _ = pe.method_body(rva)
    code = bytes(data[o + hdr:o + hdr + size])
    if code[:len(expected_il)] != expected_il:
        raise PEError("补丁后回读校验失败")
    return True


def pe_checksum(data):
    """计算 PE 校验和（可选写入）。"""
    d = bytearray(data)
    pe = _u32(d, 0x3C)
    csum_off = pe + 4 + 20 + 64
    d[csum_off:csum_off + 4] = b"\0\0\0\0"
    total = 0
    for i in range(0, len(d), 2):
        if i + 1 < len(d):
            total += d[i] | (d[i + 1] << 8)
        else:
            total += d[i]
        total = (total & 0xFFFF) + (total >> 16)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + len(d)
    return total & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="为 PCL 2.99.0.0 恢复原版 Minecraft 下载功能")
    ap.add_argument("input", help="PCL 主程序路径")
    ap.add_argument("-o", "--output", help="输出路径（默认 *.unlocked.exe）")
    ap.add_argument("--in-place", action="store_true",
                    help="原地修改（会先备份为 *.unlock-backup）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只检查，不写文件")
    ap.add_argument("--force", action="store_true",
                    help="跳过版本号检查（仍会校验方法指纹）")
    args = ap.parse_args(argv)

    try:
        data = open(args.input, "rb").read()
    except OSError as e:
        print("读取失败：%s" % e, file=sys.stderr)
        return 2

    try:
        unlocker = Unlocker(data)
        asm = unlocker.pe.assembly_identity()
        if not asm:
            raise PEError("找不到 Assembly 元数据")
        name, ver = asm
        print("输入 SHA-256：%s" % hashlib.sha256(data).hexdigest())
        print("目标程序集：%s %s" % (name, ver))
        if name != TARGET_ASSEMBLY:
            print("警告：程序集名称不是 %s" % TARGET_ASSEMBLY, file=sys.stderr)
        if ver != TARGET_VERSION and not args.force:
            print("错误：版本为 %s，本补丁为 %s 编写。"
                  "确需尝试请加 --force。" % (ver, TARGET_VERSION),
                  file=sys.stderr)
            return 3

        res = unlocker.apply(dry_run=args.dry_run)
        print("LoaderInit: RVA 0x%X, 文件偏移 0x%X, 代码 %d 字节" %
              (unlocker.loader_rva, unlocker.code_off, unlocker.code_size))
        print("DlClientListLoader 字段 token: 0x%08X" %
              unlocker.loader_field_tok)
        if res["changed"]:
            print("完成回调 lambda token: 0x%08X" %
                  unlocker.finish_lambda_tok)
            print("补丁 IL 长度: %d 字节" % len(res["new_il"]))
            print("新 IL: %s" % res["new_il"].hex(" "))
            print(NEW_IL_NOTE)
        else:
            print("此文件已经打过补丁，无需修改。")
            return 0

        out_data = bytes(unlocker.data)
        if not args.dry_run:
            verify_patched(out_data, res["new_il"])
            # 原校验和为 0 时保持 0（Windows 不校验用户程序）；
            # 若原文件有校验和，则同步更新。
            orig_csum = _u32(data, unlocker.pe.checksum_off)
            if orig_csum:
                out_data = bytearray(out_data)
                struct.pack_into("<I", out_data, unlocker.pe.checksum_off,
                                 pe_checksum(out_data))
                out_data = bytes(out_data)
            print("回读校验通过。")

        if args.dry_run:
            print("--dry-run：未写入文件。")
            return 0

        if args.in_place:
            backup = args.input + ".unlock-backup"
            if not os.path.exists(backup):
                with open(backup, "wb") as f:
                    f.write(data)
                print("已备份原文件：%s" % backup)
            out_path = args.input
        else:
            out_path = args.output or (os.path.splitext(args.input)[0] +
                                       ".unlocked.exe")
        with open(out_path, "wb") as f:
            f.write(out_data)
        print("已写入：%s" % out_path)
        print("SHA-256：%s" % hashlib.sha256(out_data).hexdigest())
        print("\n提示：如果下载页仍未显示，请检查设置中的 "
              "UiHiddenPageDownload（隐藏下载页）是否为 False。")
        return 0
    except PEError as e:
        print("失败：%s" % e, file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
