"""合成 H.222.0 TS 流的测试/演示工具（仅用于本机核验，不参与采集逻辑）。"""

from .core import TS_SIZE, SYNC, crc32_mpeg2


def _section(table_id, body_after_len):
    """拼 section_length + CRC32/MPEG-2。body_after_len 为长度字段之后、CRC 之前的字节。"""
    inner = bytes(body_after_len)
    length = len(inner) + 4  # 含 CRC
    if length > 1021:
        raise ValueError("section too long")
    head = bytes([table_id, 0xB0 | (length >> 8), length & 0xFF])
    section = head + inner
    crc = crc32_mpeg2(section)
    return section + bytes([(crc >> 24) & 0xFF, (crc >> 16) & 0xFF,
                            (crc >> 8) & 0xFF, crc & 0xFF])


def build_pat(pmt_map, version, tsid=0x0001):
    """pmt_map: {program_no: pmt_pid}"""
    body = bytearray()
    body += bytes([(tsid >> 8) & 0xFF, tsid & 0xFF])
    body.append(0xC1 | ((version & 0x1F) << 1))  # 当前/下一个指示=1
    body += b"\x00\x00"                            # section_number=0, last=0
    for prog, pid in sorted(pmt_map.items()):
        body += bytes([(prog >> 8) & 0xFF, prog & 0xFF,
                       0xE0 | ((pid >> 8) & 0x1F), pid & 0xFF])
    return _section(0x00, body)


def build_pmt(program, version, pcr_pid, prog_descs, es_entries,
              section_no=0, last_section=0):
    """es_entries: [(es_pid, stream_type, es_descs_bytes), ...]"""
    body = bytearray()
    body += bytes([(program >> 8) & 0xFF, program & 0xFF])
    body.append(0xC1 | ((version & 0x1F) << 1))
    body += bytes([section_no, last_section])
    body += bytes([0xE0 | ((pcr_pid >> 8) & 0x1F), pcr_pid & 0xFF])
    pd = bytes(prog_descs)
    body += bytes([0xF0 | ((len(pd) >> 8) & 0x0F), len(pd) & 0xFF])
    body += pd
    for epid, stype, descs in es_entries:
        d = bytes(descs)
        body.append(stype)
        body += bytes([0xE0 | ((epid >> 8) & 0x1F), epid & 0xFF])
        body += bytes([0xF0 | ((len(d) >> 8) & 0x0F), len(d) & 0xFF])
        body += d
    return _section(0x02, body)


def build_pes(stream_id, payload, pts_dts_flags=0x80):
    """构造带可选头的非零长度 PES（pts_dts_flags=0x80 表示仅 PTS 标志位、头长 0）。"""
    payload = bytes(payload)
    opt = bytes([0x80, pts_dts_flags & 0xFF, 0x00])  # marker, flags, header_data_len=0
    pes_len = len(opt) + len(payload)
    if pes_len > 0xFFFF:
        raise ValueError("PES too long")
    return b"\x00\x00\x01" + bytes([stream_id, (pes_len >> 8) & 0xFF,
                                    pes_len & 0xFF]) + opt + payload


class TSWriter:
    """按 PID 维护连续性计数，产出 188 字节包列表。"""

    def __init__(self):
        self.packets = []
        self._cc = {}

    def _next_cc(self, pid):
        cc = self._cc.get(pid, 0)
        self._cc[pid] = (cc + 1) % 16
        return cc

    def _raw(self, pid, payload, pusi, cc=None, tei=False, afc=1):
        b0 = (0x40 if pusi else 0x00) | (0x80 if tei else 0x00) | ((pid >> 8) & 0x1F)
        if cc is None:
            cc = self._next_cc(pid)
        header = bytes([SYNC, b0, pid & 0xFF, (afc << 4) | (cc & 0x0F)])
        payload = bytes(payload)
        if afc == 1:
            if len(payload) > 184:
                raise ValueError("payload too large")
            return header + payload + b"\xFF" * (184 - len(payload))
        if afc == 2:
            # 仅适配字段：适配长度 183，全 stuffing
            return header + b"\xB7" + b"\x00" * 183
        if afc == 3:
            # 适配 + 载荷：适配字段长度 1（仅 flags=0）
            if len(payload) > 182:
                raise ValueError("payload too large")
            return (header + b"\x01\x00" + payload
                    + b"\xFF" * (182 - len(payload)))
        raise ValueError("bad afc")

    def psi(self, pid, section, cc=None):
        """PSI 独包零指针：载荷 = 0x00 + section + 0xFF 填充，恰为 184 字节。"""
        body = b"\x00" + bytes(section)
        if len(body) > 184:
            raise ValueError("PSI section does not fit in one packet")
        pkt = self._raw(pid, body, pusi=True, cc=cc)
        self.packets.append(pkt)
        return pkt

    def pat(self, pmt_map, version, cc=None):
        return self.psi(0x0000, build_pat(pmt_map, version), cc=cc)

    def pmt(self, pmt_pid, program, version, pcr_pid, prog_descs, es_entries,
            section_no=0, last_section=0, cc=None):
        sect = build_pmt(program, version, pcr_pid, prog_descs, es_entries,
                         section_no, last_section)
        return self.psi(pmt_pid, sect, cc=cc)

    def pes_packet(self, pid, chunk, pusi):
        """发一个 PES 分片包（手动控制跨表插包顺序）。"""
        pkt = self._raw(pid, chunk, pusi=pusi)
        self.packets.append(pkt)
        return pkt

    def pes_partial(self, pid, pes, n_packets):
        """只发 PES 的前 n_packets 个包，返回 (已发字节, 包列表)。"""
        out = []
        pos = 0
        for i in range(n_packets):
            chunk = pes[pos:pos + 184]
            out.append(self.pes_packet(pid, chunk, pusi=(i == 0)))
            pos += 184
        return pos, out

    def pes_remainder(self, pid, pes, pos):
        """从 pos 字节起发完剩余 PES（续包，无 PUSI）。"""
        out = []
        i = 0
        while pos < len(pes):
            chunk = pes[pos:pos + 184]
            out.append(self.pes_packet(pid, chunk, pusi=False))
            pos += 184
            i += 1
        return out

    def pes(self, pid, pes, cc_start=None, stream_id_for_check=None):
        """把一个完整 PES 切成若干 184 载荷包，首包 PUSI。"""
        out = []
        first = True
        pos = 0
        pes = bytes(pes)
        while pos < len(pes) or first:
            chunk = pes[pos:pos + 184]
            if first:
                pkt = self._raw(pid, chunk, pusi=True)
                first = False
            else:
                pkt = self._raw(pid, chunk, pusi=False)
            self.packets.append(pkt)
            out.append(pkt)
            pos += 184
            if pos >= len(pes):
                break
        return out

    def adaptation_only(self, pid, cc=None):
        pkt = self._raw(pid, b"", pusi=False, cc=cc, afc=2)
        self.packets.append(pkt)
        return pkt

    def tei_packet(self, pid, payload=b"", pusi=False, cc=None):
        pkt = self._raw(pid, payload, pusi=pusi, cc=cc, tei=True)
        self.packets.append(pkt)
        return pkt

    def raw_payload(self, pid, payload, pusi=False, cc=None, afc=1):
        pkt = self._raw(pid, payload, pusi=pusi, cc=cc, afc=afc)
        self.packets.append(pkt)
        return pkt

    def duplicate_last(self, pid):
        for pkt in reversed(self.packets):
            if ((pkt[1] & 0x1F) << 8 | pkt[2]) == pid:
                self.packets.append(pkt)
                return pkt
        raise KeyError(pid)

    def discontinuity(self, pid, payload, pusi=False):
        """发一个跳号包（不推进本地 CC 基线，制造与期望计数不符）。"""
        cur = self._cc.get(pid, 0)
        jump_cc = (cur + 3) % 16
        pkt = self._raw(pid, payload, pusi=pusi, cc=jump_cc)
        self.packets.append(pkt)
        # 之后基线以跳号值为准
        self._cc[pid] = (jump_cc + 1) % 16
        return pkt

    def bytes(self):
        return b"".join(self.packets)
