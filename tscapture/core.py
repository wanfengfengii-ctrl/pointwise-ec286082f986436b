"""Core capture engine: H.222.0 (MPEG-2 TS) parsing, PSI/PES handling, SQLite store."""

import os
import sqlite3

TS_SIZE = 188
SYNC = 0x47
NULL_PID = 0x1FFF
PAT_PID = 0x0000
MAX_SECTION = 1024  # 3 header + 1021

# CRC-32/MPEG-2 (poly 0x04C11DB7, init/refin/refout 0, xorout 0)
_CRC_TABLE = None


def _crc_table():
    global _CRC_TABLE
    if _CRC_TABLE is None:
        table = []
        for i in range(256):
            crc = i << 24
            for _ in range(8):
                if crc & 0x80000000:
                    crc = ((crc << 1) & 0xFFFFFFFF) ^ 0x04C11DB7
                else:
                    crc = (crc << 1) & 0xFFFFFFFF
            table.append(crc)
        _CRC_TABLE = table
    return _CRC_TABLE


def crc32_mpeg2(data):
    table = _crc_table()
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ table[((crc >> 24) ^ b) & 0xFF]
    return crc


def _same_version(v, cur):
    """5 位版本号是否同一已生效版（模 32 比较）。"""
    return (v - cur) % 32 == 0


# ---------------------------------------------------------------------------
# 轻量 PSI 结构（元组化，避免可变状态散落）
# ---------------------------------------------------------------------------

class ES:
    __slots__ = ("pid", "stream_type", "es_descs")

    def __init__(self, pid, stream_type, es_descs):
        self.pid = pid
        self.stream_type = stream_type
        self.es_descs = bytes(es_descs)

    def same(self, other):
        return (self.pid == other.pid and self.stream_type == other.stream_type
                and self.es_descs == other.es_descs)


class PMTInfo:
    """一个节目当前生效的 PMT 信息。"""
    __slots__ = ("program", "version", "pcr_pid", "prog_descs", "streams")

    def __init__(self, program, version, pcr_pid, prog_descs, streams):
        self.program = program
        self.version = version
        self.pcr_pid = pcr_pid
        self.prog_descs = bytes(prog_descs)
        self.streams = streams  # pid -> ES

    def es_pids(self):
        return frozenset(self.streams)


# ---------------------------------------------------------------------------
# 组装中的 PES 件
# ---------------------------------------------------------------------------

class _Piece:
    __slots__ = ("pid", "start_pkt", "end_pkt", "data", "need", "owners", "done")

    def __init__(self, pid, start_pkt, owners):
        self.pid = pid
        self.start_pkt = start_pkt
        self.end_pkt = start_pkt
        self.data = bytearray()
        self.need = None          # 总字节数；None 表示头还没读够
        # {program: (generation, ES, PMTInfo)} 起件时刻冻结的归属快照
        self.owners = owners
        self.done = False


# ---------------------------------------------------------------------------
# 单 PID 的分段重组状态
# ---------------------------------------------------------------------------

class _SectionAsm:
    __slots__ = ("buf", "cur")

    def __init__(self):
        self.buf = bytearray()
        self.cur = None          # 已确定的整节长度

    def reset(self):
        self.buf.clear()
        self.cur = None


class Collector:
    def __init__(self, db):
        self._db_path = os.fspath(db)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        cur = self._conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES('cap_seq', 0)")
        self._conn.execute("UPDATE meta SET v = v + 1 WHERE k = 'cap_seq'")
        row = self._conn.execute("SELECT v FROM meta WHERE k='cap_seq'").fetchone()
        self.cap_id = row[0]
        self._conn.execute("INSERT INTO captures(cap_id) VALUES(?)", (self.cap_id,))
        self._conn.commit()

        self._sealed = False
        self._partial = bytearray()      # 跨 feed 的未成包尾巴
        self._pkt_no = -1                # 已处理的最后包号（零基；无包时 -1）

        # PSI 重组
        self._pat_asm = _SectionAsm()
        self._pmt_asm = {}               # pmt_pid -> _SectionAsm
        # PAT 生效状态
        self._pat_version = None
        self._pat_pmts = {}              # program -> pmt_pid
        self._pmt_pid_prog = {}          # pmt_pid -> program
        # PMT 候选与生效
        self._pmt_cand = {}              # program -> {version: {sec_no: raw}}
        self._pmt = {}                   # program -> PMTInfo
        self._gen_counter = {}           # program -> 节目流集合变动计数
        self._gens = {}                  # program -> {es_pid: 代次}

        # ES 采集状态
        self._cc = {}                    # pid -> 上一个有载荷包 CC
        self._last_pkt = {}              # pid -> 上一个有载荷包完整字节
        self._active = {}                # pid -> _Piece（组装中）
        self._queues = {}                # pid -> [_Piece]（含未完/已完，FIFO）

    # ---------------- schema ----------------
    def _init_schema(self):
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta(
                k TEXT PRIMARY KEY,
                v INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS captures(
                cap_id INTEGER PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS pieces(
                cap_id      INTEGER NOT NULL,
                program     INTEGER NOT NULL,
                generation  INTEGER NOT NULL,
                pid         INTEGER NOT NULL,
                stream_type INTEGER NOT NULL,
                es_desc     BLOB NOT NULL,
                prog_desc   BLOB NOT NULL,
                pcr_pid     INTEGER NOT NULL,
                start_pkt   INTEGER NOT NULL,
                end_pkt     INTEGER NOT NULL,
                pes         BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pieces_read
                ON pieces(cap_id, program, start_pkt, pid);
            """
        )
        self._conn.commit()

    # ---------------- 喂入 ----------------
    def feed(self, data):
        if self._sealed:
            raise ValueError("collector already finished")
        if isinstance(data, memoryview):
            data = bytes(data)
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("feed expects bytes-like input")
        self._partial.extend(data)
        while len(self._partial) >= TS_SIZE:
            pkt = bytes(self._partial[:TS_SIZE])
            del self._partial[:TS_SIZE]
            self._pkt_no += 1
            self._process_packet(pkt, self._pkt_no)

    def finish(self):
        if self._sealed:
            raise ValueError("collector already finished")
        if self._partial:
            # 短尾：结构坏，已发内容保留，直接报错不封口
            raise ValueError("trailing %d bytes are not a full 188-byte packet" % len(self._partial))
        # 弃未完
        for pid in list(self._active.keys()):
            self._active.pop(pid, None)
        for q in self._queues.values():
            q[:] = [p for p in q if p.done]
        self._drain_all()
        self._sealed = True
        self._conn.commit()
        self._conn.close()

    # ---------------- 包级处理 ----------------
    def _process_packet(self, pkt, pkt_no):
        if pkt[0] != SYNC:
            raise ValueError("bad sync byte at packet %d" % pkt_no)

        tei = bool(pkt[1] & 0x80)
        pusi = bool(pkt[1] & 0x40)
        pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
        afc = (pkt[3] >> 4) & 0x03
        cc = pkt[3] & 0x0F

        if pid == NULL_PID:
            return

        # 适配字段
        payload_off = 4
        has_adapt = afc in (2, 3)
        has_payload = afc in (1, 3)
        if afc == 0:
            raise ValueError("reserved adaptation_field_control at packet %d" % pkt_no)
        if has_adapt:
            afl = pkt[4]
            if afl > 183 or 4 + afl > TS_SIZE:
                raise ValueError("adaptation field length out of range at packet %d" % pkt_no)
            payload_off = 5 + afl
            if payload_off > TS_SIZE:
                raise ValueError("adaptation field overruns packet %d" % pkt_no)

        # 传输错误指示：坏包——丢该 PID 未完件与分段重组，包不再解析
        if tei:
            self._pid_anomaly(pid)
            return

        # 仅适配字段：不推进载荷计数
        if not has_payload:
            return

        payload = pkt[payload_off:]

        # 载荷连续性（同计数同包去重，异常丢该 PID 未完件）
        if pid in self._cc:
            if cc == self._cc[pid]:
                if self._last_pkt.get(pid) == pkt:
                    return  # 重传去重
                self._pid_anomaly(pid)
                # 异常处理后继续解析当前包
            elif cc != (self._cc[pid] + 1) % 16:
                self._pid_anomaly(pid)
        self._cc[pid] = cc
        self._last_pkt[pid] = pkt

        # 分流
        if pid == PAT_PID:
            self._handle_psi_packet(pid, pusi, payload, pkt_no, self._pat_asm, self._on_pat_section)
        elif pid in self._pmt_pid_prog:
            asm = self._pmt_asm.get(pid)
            if asm is None:
                asm = _SectionAsm()
                self._pmt_asm[pid] = asm
            self._handle_psi_packet(pid, pusi, payload, pkt_no, asm, self._on_pmt_section)
        else:
            self._handle_es(pid, pusi, payload, pkt_no)

    def _pid_anomaly(self, pid):
        """异常：丢该 PID 的未完件，清空分段重组，已完件/已入库保留。"""
        self._active.pop(pid, None)
        q = self._queues.get(pid)
        if q is not None:
            q[:] = [p for p in q if p.done]
            self._drain_pid(pid)
        if pid == PAT_PID:
            self._pat_asm.reset()
        if pid in self._pmt_asm:
            self._pmt_asm[pid].reset()

    # ---------------- PSI ----------------
    def _handle_psi_packet(self, pid, pusi, payload, pkt_no, asm, on_section):
        if pusi:
            asm.reset()
            if not payload:
                raise ValueError("PSI PUSI packet without pointer_field at packet %d" % pkt_no)
            pointer = payload[0]
            if pointer != 0:
                # 本录制要求 PSI 独包零指针
                raise ValueError("non-zero pointer_field (%d) at packet %d" % (pointer, pkt_no))
            # 零指针：指针字段之后即 section 起点
            asm.buf.extend(payload[1:])
            # PSI 独包：一节必须在起始包内完整，不允许跨包拼接/同包多节
            if len(asm.buf) < 3:
                raise ValueError("truncated PSI section header at packet %d" % pkt_no)
            sect_len = ((asm.buf[1] & 0x0F) << 8) | asm.buf[2]
            if sect_len > 1021:
                raise ValueError("section_length %d exceeds 1021 at packet %d" % (sect_len, pkt_no))
            total = 3 + sect_len
            if total > len(asm.buf):
                raise ValueError("PSI section spans packets (not a sole-packet section)"
                                 " at packet %d" % pkt_no)
            tail = asm.buf[total:]
            if any(b != 0xFF for b in tail):
                raise ValueError("non-stuffing trailing bytes after sole PSI section"
                                 " at packet %d" % pkt_no)
            del asm.buf[total:]  # 独包：节外只允许 0xFF 填充，不参与重组
        else:
            if not asm.buf:
                # 无起始的续包，忽略
                return
            raise ValueError("PSI section continuation packet violates sole-packet rule"
                             " at packet %d" % pkt_no)
        self._try_sections(pid, asm, pkt_no, on_section)
        asm.reset()

    def _try_sections(self, pid, asm, pkt_no, on_section):
        """从重组缓冲中取出所有已齐的整节。"""
        while True:
            buf = asm.buf
            if asm.cur is None:
                if len(buf) < 3:
                    return
                if buf[0] != 0x00 and pid == PAT_PID:
                    raise ValueError("bad PAT table_id 0x%02X at packet %d" % (buf[0], pkt_no))
                if pid != PAT_PID and buf[0] != 0x02:
                    raise ValueError("bad PMT table_id 0x%02X at packet %d" % (buf[0], pkt_no))
                sect_len = ((buf[1] & 0x0F) << 8) | buf[2]
                if sect_len > 1021:
                    raise ValueError("section_length %d exceeds 1021 at packet %d" % (sect_len, pkt_no))
                asm.cur = 3 + sect_len
                if asm.cur > MAX_SECTION:
                    raise ValueError("section too long at packet %d" % pkt_no)
            if len(buf) < asm.cur:
                return
            section = bytes(buf[:asm.cur])
            del buf[:asm.cur]
            asm.cur = None
            # CRC
            if crc32_mpeg2(section) != 0:
                # CRC 错误：丢弃该节，继续后续
                continue
            on_section(section, pkt_no)
            if not buf:
                return

    def _on_pat_section(self, section, pkt_no):
        # table_id(1) + sect_len字段(2) + tsid(2) + reserved/ver/ccni(1) + secn(1) + last(1)
        if len(section) < 12:
            raise ValueError("PAT section too short at packet %d" % pkt_no)
        if section[6] != 0 or section[7] != 0:
            raise ValueError("fixed single-section PAT violated at packet %d" % pkt_no)
        version = (section[5] >> 1) & 0x1F
        if self._pat_version is not None and _same_version(version, self._pat_version):
            return  # 已生效版重传忽略
        body_len = ((section[1] & 0x0F) << 8) | section[2]
        # body = tsid..CRC；节目条目从偏移 8 开始，CRC 4 字节
        pos = 8
        end = 3 + body_len - 4
        pmts = {}
        while pos + 4 <= end:
            prog = (section[pos] << 8) | section[pos + 1]
            pid = ((section[pos + 2] & 0x1F) << 8) | section[pos + 3]
            pos += 4
            if prog == 0:
                continue  # NIT
            pmts[prog] = pid
        self._apply_pat(version, pmts)

    def _apply_pat(self, version, pmts):
        old_prog = self._pat_pmts
        self._pat_version = version
        self._pat_pmts = dict(pmts)
        self._pmt_pid_prog = {pid: prog for prog, pid in pmts.items()}

        # 消失的节目：撤其全部未完资格
        gone = [p for p in old_prog if p not in pmts]
        for prog in gone:
            info = self._pmt.pop(prog, None)
            self._pmt_cand.pop(prog, None)
            if info is not None:
                self._revoke_eligibility(info.es_pids(), {prog})
            self._gen_counter.pop(prog, None)
            self._gens.pop(prog, None)
        # 不再被 PAT 引用的 PMT PID 重组器
        live_pmt_pids = set(pmts.values())
        for pid in list(self._pmt_asm.keys()):
            if pid not in live_pmt_pids:
                self._pmt_asm.pop(pid, None)
        # PMT PID 改绑的旧节目
        for prog, old_pid in list(old_prog.items()):
            if prog in pmts and pmts[prog] != old_pid:
                info = self._pmt.pop(prog, None)
                self._pmt_cand.pop(prog, None)
                if info is not None:
                    self._revoke_eligibility(info.es_pids(), {prog})
                self._gen_counter.pop(prog, None)
                self._gens.pop(prog, None)
                self._pmt_asm.pop(old_pid, None)
        self._conn.commit()

    def _on_pmt_section(self, section, pkt_no):
        if len(section) < 16:
            raise ValueError("PMT section too short at packet %d" % pkt_no)
        body_len = ((section[1] & 0x0F) << 8) | section[2]
        program = (section[3] << 8) | section[4]
        version = (section[5] >> 1) & 0x1F
        sec_no = section[6]
        last_sec = section[7]
        if sec_no > last_sec or last_sec > 1:
            raise ValueError("PMT section numbering invalid at packet %d" % pkt_no)
        pcr_pid = ((section[8] & 0x1F) << 8) | section[9]
        pi_len = ((section[10] & 0x0F) << 8) | section[11]
        end = 3 + body_len - 4
        pos = 12
        if pos + pi_len > end:
            raise ValueError("program_info_length overruns PMT at packet %d" % pkt_no)
        prog_descs = bytes(section[pos:pos + pi_len])
        pos += pi_len
        streams = {}
        while pos + 5 <= end:
            stype = section[pos]
            epid = ((section[pos + 1] & 0x1F) << 8) | section[pos + 2]
            ei_len = ((section[pos + 3] & 0x0F) << 8) | section[pos + 4]
            pos += 5
            if pos + ei_len > end:
                raise ValueError("ES_info_length overruns PMT at packet %d" % pkt_no)
            es_descs = bytes(section[pos:pos + ei_len])
            pos += ei_len
            if epid in streams:
                # 节内 ES PID 重复：候选冲突
                streams = None
                break
            streams[epid] = ES(epid, stype, es_descs)
        if streams is None:
            return
        if pos != end:
            raise ValueError("PMT section trailing bytes at packet %d" % pkt_no)

        # 该节携带的节目必须由 PAT 绑定到某 PMT PID
        bound_pid = self._pat_pmts.get(program)
        if bound_pid is None:
            return  # 无 PAT 绑定，不采

        cand = self._pmt_cand.setdefault(program, {})
        vc = cand.setdefault(version, {})
        # 同节号重传且内容一致：忽略；不一致：冲突，整版作废重来
        if sec_no in vc and vc[sec_no] != section:
            cand.pop(version, None)
            return
        vc[sec_no] = section

        # 收齐判定：节号 0..last_sec 全到
        needed = last_sec + 1
        if needed not in (1, 2) or len(vc) != needed:
            return
        if set(vc.keys()) != set(range(needed)):
            return

        # 齐节：跨节一致性检查
        infos = []
        for sn in range(needed):
            infos.append(self._parse_pmt_body(vc[sn], pkt_no))
        pcr0 = infos[0].pcr_pid
        pd0 = infos[0].prog_descs
        all_streams = {}
        conflict = False
        for info in infos:
            if info.pcr_pid != pcr0 or info.prog_descs != pd0:
                conflict = True
                break
            for epid, es in info.streams.items():
                if epid in all_streams:
                    conflict = True  # ES PID 跨节不唯一
                    break
                all_streams[epid] = es
            if conflict:
                break
        if conflict:
            cand.pop(version, None)
            return

        # 已生效版重传忽略（版本号 5bit 回绕）
        cur = self._pmt.get(program)
        if cur is not None and _same_version(version, cur.version):
            cand.pop(version, None)
            return

        new_info = PMTInfo(program, version, pcr0, pd0, all_streams)
        self._apply_pmt(program, new_info, cand, version)

    def _parse_pmt_body(self, section, pkt_no):
        body_len = ((section[1] & 0x0F) << 8) | section[2]
        program = (section[3] << 8) | section[4]
        pcr_pid = ((section[8] & 0x1F) << 8) | section[9]
        pi_len = ((section[10] & 0x0F) << 8) | section[11]
        end = 3 + body_len - 4
        pos = 12
        prog_descs = bytes(section[pos:pos + pi_len])
        pos += pi_len
        streams = {}
        while pos + 5 <= end:
            stype = section[pos]
            epid = ((section[pos + 1] & 0x1F) << 8) | section[pos + 2]
            ei_len = ((section[pos + 3] & 0x0F) << 8) | section[pos + 4]
            pos += 5
            es_descs = bytes(section[pos:pos + ei_len])
            pos += ei_len
            streams[epid] = ES(epid, stype, es_descs)
        return PMTInfo(program, (section[5] >> 1) & 0x1F, pcr_pid, prog_descs, streams)

    def _apply_pmt(self, program, new_info, cand, version):
        old = self._pmt.get(program)
        old_pids = old.es_pids() if old else frozenset()
        new_pids = new_info.es_pids()

        # 流集合变动判定
        changed = set()
        if old is None:
            changed = set(new_pids)
        else:
            for pid in new_pids:
                if pid not in old.streams or not new_info.streams[pid].same(old.streams[pid]):
                    changed.add(pid)
        removed = old_pids - new_pids
        stream_set_changed = bool(changed or removed)

        gens = self._gens.setdefault(program, {})
        if stream_set_changed:
            nxt = self._gen_counter.get(program, 0) + 1
            self._gen_counter[program] = nxt
            for pid in changed:
                gens[pid] = nxt
            for pid in removed:
                gens.pop(pid, None)
            # 未变流保留代次
        # 无变动：代次表保持

        self._pmt[program] = new_info
        cand.pop(version, None)

        # 换表仅撤改/删流的未完资格（本节目视角）
        if old is not None and (changed or removed):
            self._revoke_eligibility(changed | removed, {program})
        elif old is None:
            pass  # 首版：无旧件可撤
        self._conn.commit()

    def _revoke_eligibility(self, pids, programs):
        """从这些 PID 的未完件上撤销指定节目的资格；资格清空即解阻。"""
        for pid in pids:
            piece = self._active.get(pid)
            if piece is not None:
                for prog in programs:
                    piece.owners.pop(prog, None)
                if not piece.owners:
                    # 未完且无资格：成为死件，移除并解阻
                    self._active.pop(pid, None)
                    q = self._queues.get(pid)
                    if q is not None:
                        q[:] = [p for p in q if p is not piece]
                    self._drain_pid(pid)
            # 队列中未完件同样撤资格
            q = self._queues.get(pid)
            if q is not None:
                for p in q:
                    if not p.done:
                        for prog in programs:
                            p.owners.pop(prog, None)
                dead = [p for p in q if not p.done and not p.owners]
                if dead:
                    q[:] = [p for p in q if p not in dead]
                    self._drain_pid(pid)

    # ---------------- ES / PES ----------------
    def _eligible_programs(self, pid):
        """起件时刻冻结归属：代次、ES 信息、节目信息均取当前生效表。"""
        out = {}
        for prog, info in self._pmt.items():
            if pid in info.streams:
                gen = self._gens.get(prog, {}).get(pid)
                if gen is not None:
                    out[prog] = (gen, info.streams[pid], info)
        return out

    def _handle_es(self, pid, pusi, payload, pkt_no):
        if pusi:
            owners = self._eligible_programs(pid)
            if not owners:
                # 非本录制节目的 PID：不起件
                return
            if len(payload) < 6:
                raise ValueError("PES header truncated at packet %d" % pkt_no)
            if payload[0] != 0 or payload[1] != 0 or payload[2] != 1:
                raise ValueError("bad PES start code at packet %d" % pkt_no)
            stream_id = payload[3]
            pes_len = (payload[4] << 8) | payload[5]
            if pes_len == 0:
                return  # 仅收非零长度 PES
            needs_optional = stream_id not in (0xBC, 0xBE, 0xBF, 0xF0, 0xF1,
                                               0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
                                               0xF7, 0xF8, 0xFF)
            if needs_optional:
                if len(payload) < 9:
                    raise ValueError("PES optional header truncated at packet %d" % pkt_no)
                if (payload[7] & 0xC0) != 0x80:
                    raise ValueError("PES optional header marker invalid at packet %d" % pkt_no)
                hdr_data_len = payload[8]
                if 9 + hdr_data_len > len(payload):
                    raise ValueError("PES header data length overruns packet %d" % pkt_no)
            # 新 PES 起件；同 PID 旧未完件保留（有资格的未完早件挡晚完件）
            piece = _Piece(pid, pkt_no, dict(owners))
            piece.data.extend(payload)
            piece.need = 6 + pes_len
            if len(piece.data) >= piece.need:
                self._complete(piece, pkt_no)
            else:
                self._active[pid] = piece
                self._queues.setdefault(pid, []).append(piece)
        else:
            piece = self._active.get(pid)
            if piece is None:
                return  # 没有组装中的件，续包丢弃
            if piece.need is not None and len(piece.data) >= piece.need:
                return
            piece.data.extend(payload)
            piece.end_pkt = pkt_no
            if piece.need is not None and len(piece.data) >= piece.need:
                self._complete(piece, pkt_no)

    def _complete(self, piece, pkt_no):
        if len(piece.data) > piece.need:
            del piece.data[piece.need:]
        piece.end_pkt = pkt_no
        piece.done = True
        self._active.pop(piece.pid, None)
        q = self._queues.setdefault(piece.pid, [])
        if piece not in q:
            q.append(piece)
        self._drain_pid(piece.pid)

    # ---------------- 队列出件 ----------------
    def _drain_pid(self, pid):
        """队头只要是有资格的件（含未完）就阻挡；放行其前的连续完件。"""
        q = self._queues.get(pid)
        if not q:
            return
        while q:
            head = q[0]
            if not head.done:
                if head.owners:
                    return  # 有资格的未完早件挡晚完件
                # 无资格死件（理论上撤销时已清，兜底）
                q.pop(0)
                continue
            self._emit(head)
            q.pop(0)

    def _drain_all(self):
        for pid in list(self._queues.keys()):
            self._drain_pid(pid)

    def _emit(self, piece):
        pes = bytes(piece.data)
        for prog, (gen, es, info) in piece.owners.items():
            self._conn.execute(
                "INSERT INTO pieces(cap_id, program, generation, pid, stream_type,"
                " es_desc, prog_desc, pcr_pid, start_pkt, end_pkt, pes)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (self.cap_id, prog, gen, piece.pid, es.stream_type,
                 bytes(es.es_descs), bytes(info.prog_descs), info.pcr_pid,
                 piece.start_pkt, piece.end_pkt, pes),
            )
        self._conn.commit()


# ---------------------------------------------------------------------------
# 查询
# ---------------------------------------------------------------------------

def read(db, program):
    path = os.fspath(db)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT cap_id, generation, pid, stream_type, es_desc, prog_desc,"
            " pcr_pid, start_pkt, end_pkt, pes"
            " FROM pieces WHERE program = ?"
            " ORDER BY cap_id ASC, start_pkt ASC, pid ASC",
            (program,),
        ).fetchall()
    finally:
        conn.close()
    return [
        (
            r[0], r[1], r[2],
            (r[3], bytes(r[4]), bytes(r[5]), r[6]),
            r[7], r[8], bytes(r[9]),
        )
        for r in rows
    ]
