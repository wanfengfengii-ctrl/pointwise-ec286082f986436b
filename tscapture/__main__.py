"""tscapture 命令行入口：verify（换表核验）/ demo（出档演示）。"""

import os
import sys
import tempfile

from .core import Collector, read, TS_SIZE
from .builder import TSWriter, build_pes


# 题目示例中的固定 PID
PID_PMT1 = 0x0100
PID_PMT2 = 0x0101
PID_300 = 300
PID_301 = 301
PROG1 = 1
PROG2 = 2


def _pes_ab(tag, size):
    """构造内容可辨识的 PES：stream_id=0xE0（视频，需可选头）。"""
    return build_pes(0xE0, bytes([tag]) * size)


def _build_example_stream():
    """复刻题目场景：PID300 共用；A 首包→节目1两节改描述→A 尾包→B。"""
    w = TSWriter()

    # PAT v1：节目1→PMT1，节目2→PMT2
    w.pat({PROG1: PID_PMT1, PROG2: PID_PMT2}, version=1)

    # 节目1 PMT v1（单节）：300 描述 D1a；PCR=300
    w.pmt(PID_PMT1, PROG1, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"\x09\x01D1a")])
    # 节目2 PMT v1（两节）：300 描述 D2a，301 描述 X
    w.pmt(PID_PMT2, PROG2, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"\x09\x01D2a")],
          section_no=0, last_section=1)
    w.pmt(PID_PMT2, PROG2, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_301, 0x0F, b"\x09\x01X00")],
          section_no=1, last_section=1)

    # A 首包（PES 跨多包；起件时 A 同时归属节目1/2，代次均为 1）
    pes_a = _pes_ab(0xA1, 700)
    pos, a_first = w.pes_partial(PID_300, pes_a, 1)
    a_start = len(w.packets) - 1

    # 节目1 换表 v2（两节）：300 改描述 D1b；节目2 不动
    w.pmt(PID_PMT1, PROG1, version=2, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"\x09\x01D1b")],
          section_no=0, last_section=1)
    w.pmt(PID_PMT1, PROG1, version=2, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[],
          section_no=1, last_section=1)
    # v2 重传：应被忽略
    w.pmt(PID_PMT1, PROG1, version=2, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"\x09\x01D1b")],
          section_no=0, last_section=1)
    w.pmt(PID_PMT1, PROG1, version=2, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[],
          section_no=1, last_section=1)

    # A 尾包：续包完成 A（节目1 资格已撤 → A 仅入节目2）
    w.pes_remainder(PID_300, pes_a, pos)
    a_end = len(w.packets) - 1

    # B：完整 PES（节目1 代次2、节目2 代次1）
    pes_b = _pes_ab(0xB2, 200)
    b_pkts = w.pes(PID_300, pes_b)
    b_start = len(w.packets) - len(b_pkts)
    b_end = b_start + len(b_pkts) - 1

    return w, pes_a, pes_b, (a_start, a_end), (b_start, b_end)


def _check(cond, msg, failures):
    if cond:
        print("  ok -", msg)
    else:
        print("FAIL -", msg)
        failures.append(msg)


def cmd_verify(argv):
    failures = []
    tmpdir = tempfile.mkdtemp(prefix="tscapture-verify-")
    db = os.path.join(tmpdir, "cap.db")
    print("[1] 构造换表场景（PID300 共用，节目1 两节 PMT 改描述，A 跨表，B 表后）")
    w, pes_a, pes_b, a_span, b_span = _build_example_stream()
    stream = w.bytes()
    assert len(stream) % TS_SIZE == 0

    print("[2] 任意切块喂入（7/188/1000 字节混切）")
    c = Collector(db)
    cap_id = c.cap_id
    chunks = []
    i = 0
    widths = (7, 188, 1000, 33, 500)
    k = 0
    while i < len(stream):
        n = widths[k % len(widths)]
        c.feed(stream[i:i + n])
        chunks.append(stream[i:i + n])
        i += n
        k += 1

    print("[3] 中途查询：A、B 均未完/部分时不应提前出档")
    # 重新构造一个只喂到 A 首包的采集器（A 首包后即换表前，A 未完）
    db_mid = os.path.join(tmpdir, "mid.db")
    cm = Collector(db_mid)
    cut = (a_span[0] + 1) * TS_SIZE  # 只含 A 的首包
    cm.feed(stream[:cut])
    mid2 = read(db_mid, PROG2)
    mid1 = read(db_mid, PROG1)
    _check(mid2 == [] and mid1 == [], "未完 PES 不入档", failures)
    cm.finish()
    _check(read(db_mid, PROG2) == [], "finish 弃未完，节目2 无行", failures)

    print("[4] 封口后核验归属/代次/排序/原字节")
    c.finish()
    r1 = read(db, PROG1)
    r2 = read(db, PROG2)

    _check(len(r1) == 1, "节目1 仅出 B（A 被撤资格），实际 %d 行" % len(r1), failures)
    _check(len(r2) == 2, "节目2 出 A、B 两行，实际 %d 行" % len(r2), failures)

    if r1:
        row = r1[0]
        _check(row[0] == cap_id and row[2] == PID_300, "节目1 B 采次/PID 正确", failures)
        _check(row[1] == 2, "节目1 B 代次=2", failures)
        _check(row[4] == b_span[0] and row[5] == b_span[1], "节目1 B 起/止包正确", failures)
        _check(row[6] == pes_b, "节目1 B PES 原字节完整", failures)
        _check(row[3] == (0x1B, b"\x09\x01D1b", b"", PID_300),
               "节目1 B 流类型/ES描述符/节目描述符/PCR_PID 正确", failures)
    if len(r2) == 2:
        ra, rb = r2
        _check(ra[1] == 1 and rb[1] == 1, "节目2 A、B 代次均=1（流未变，代次保留）", failures)
        _check(ra[4] == a_span[0] and ra[5] == a_span[1], "节目2 A 起/止包正确", failures)
        _check(rb[4] == b_span[0] and rb[5] == b_span[1], "节目2 B 起/止包正确", failures)
        _check(ra[6] == pes_a and rb[6] == pes_b, "节目2 A、B PES 原字节完整", failures)
        _check(ra[3][1] == b"\x09\x01D2a", "节目2 A 冻结改表前 ES 描述符 D2a", failures)
        _check((ra[4], ra[2]) <= (rb[4], rb[2]), "按采次、起包排序", failures)

    print("[5] 重开库只读查询，结果一致")
    r1b = read(db, PROG1)
    r2b = read(db, PROG2)
    _check(r1b == r1 and r2b == r2, "重开查询结果一致", failures)

    print("[6] 第二个 Collector 实例采次自增")
    db2 = os.path.join(tmpdir, "cap2.db")
    # 复制同一库语义：新库采次从 1；同库再开才自增
    c2 = Collector(db)
    _check(c2.cap_id == cap_id + 1, "同库新实例采次=%d（上一采次 %d）" % (c2.cap_id, cap_id),
           failures)
    c2.feed(stream[:TS_SIZE])
    c2.finish()
    rows = read(db, PROG1)
    _check(all(r[0] in (cap_id, cap_id + 1) for r in rows), "多采次共存于同一库", failures)

    print("[7] 去重、连续性异常、坏包、短尾")
    _check_robustness(tmpdir, failures)

    print("[8] 有资格未完早件挡晚完件，资格清空解阻")
    _check_blocking(tmpdir, failures)

    if failures:
        print("\nVERIFY FAILED: %d 项" % len(failures))
        for f in failures:
            print(" -", f)
        return 1
    print("\nVERIFY OK：全部换表核验通过。库文件：%s" % db)
    return 0


def _check_robustness(tmpdir, failures):
    # 去重：同 CC 同包重传被忽略；同 CC 不同包触发异常丢未完件
    db = os.path.join(tmpdir, "robust.db")
    c = Collector(db)
    w = TSWriter()
    w.pat({PROG1: PID_PMT1}, version=1)
    w.pmt(PID_PMT1, PROG1, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"")])
    long_pes = build_pes(0xE0, b"\x55" * 500)
    pkts = w.pes(PID_300, long_pes)
    # 在中段插入一个完全相同的重传包
    dup = pkts[1]
    stream_pkts = list(w.packets)
    stream_pkts.insert(stream_pkts.index(dup) + 1, dup)
    for p in stream_pkts:
        c.feed(p)
    c.finish()
    rows = read(db, PROG1)
    _check(len(rows) == 1 and rows[0][6] == long_pes, "同计数同包去重，PES 仍完整", failures)

    # 跳号异常：未完件丢弃；之后新 PUSI 起的件正常入档
    db2 = os.path.join(tmpdir, "disc.db")
    c = Collector(db2)
    w = TSWriter()
    w.pat({PROG1: PID_PMT1}, version=1)
    w.pmt(PID_PMT1, PROG1, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"")])
    w.pes(PID_300, build_pes(0xE0, b"\x66" * 400))  # 已完件，保留对照
    # 再造一个跨多包的未完长件，跳号将其丢弃
    w.pes_partial(PID_300, build_pes(0xE0, b"\x77" * 900), 2)
    w.discontinuity(PID_300, b"\x78" * 100)         # 跳号 → 丢未完
    good = build_pes(0xE0, b"\x88" * 100)
    w.pes(PID_300, good)                            # 新件正常
    for p in w.packets:
        c.feed(p)
    c.finish()
    rows = read(db2, PROG1)
    _check(len(rows) == 2 and rows[-1][6] == good,
           "连续性异常丢该 PID 未完件（已完件与新件保留），实际 %d 行" % len(rows),
           failures)

    # 坏 sync / 短尾 ValueError，已发保留
    db3 = os.path.join(tmpdir, "bad.db")
    c = Collector(db3)
    w = TSWriter()
    w.pat({PROG1: PID_PMT1}, version=1)
    w.pmt(PID_PMT1, PROG1, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"")])
    one = build_pes(0xE0, b"\x99" * 50)
    w.pes(PID_300, one)
    good_bytes = w.bytes()
    c.feed(good_bytes)
    bad = bytearray(TS_SIZE)
    bad[0] = 0x48
    try:
        c.feed(bytes(bad))
        _check(False, "坏 sync 抛 ValueError", failures)
    except ValueError:
        _check(True, "坏 sync 抛 ValueError", failures)
    try:
        c.feed(b"\x47" * 7)
        c.finish()
        _check(False, "短尾 finish 抛 ValueError", failures)
    except ValueError:
        _check(True, "短尾 finish 抛 ValueError", failures)
    # 已发保留：用完整尾巴封口后能查到第一件
    c.feed(b"")  # no-op，短尾仍在
    # 短尾未清无法 finish；重开库验证已提交行仍在
    rows = read(db3, PROG1)
    _check(len(rows) == 1 and rows[0][6] == one, "报错前已发完件保留入库", failures)

    # 非零指针 PSI 报 ValueError
    db4 = os.path.join(tmpdir, "ptr.db")
    c = Collector(db4)
    w = TSWriter()
    w.raw_payload(0, b"\x05" + b"\x00" * 183, pusi=True)
    try:
        c.feed(w.bytes())
        _check(False, "非零指针报 ValueError", failures)
    except ValueError:
        _check(True, "非零指针报 ValueError", failures)


def _check_blocking(tmpdir, failures):
    db = os.path.join(tmpdir, "block.db")
    c = Collector(db)
    w = TSWriter()
    w.pat({PROG1: PID_PMT1, PROG2: PID_PMT2}, version=1)
    # 节目1、2 都含 300
    w.pmt(PID_PMT1, PROG1, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"1")])
    w.pmt(PID_PMT2, PROG2, version=1, pcr_pid=PID_300,
          prog_descs=b"", es_entries=[(PID_300, 0x1B, b"2")])

    # 早件 E（跨 8 包，只发 4 包，保持未完）
    early = build_pes(0xE0, b"\xEE" * 1400)
    w.pes_partial(PID_300, early, 4)
    # 晚件 L 完整
    late = build_pes(0xE0, b"\x4C" * 80)
    w.pes(PID_300, late)
    # 喂到 L 完成、E 未完
    data = w.bytes()
    c.feed(data)
    blocked = read(db, PROG1)
    _check(blocked == [], "有资格的未完早件挡住晚完件", failures)

    # 换表：两节目同时移除 300（PAT 升版保持绑定，PMT 升版删流）→ 资格清空解阻
    w.pat({PROG1: PID_PMT1, PROG2: PID_PMT2}, version=2)
    w.pmt(PID_PMT1, PROG1, version=2, pcr_pid=PID_301,
          prog_descs=b"", es_entries=[(PID_301, 0x0F, b"")])
    w.pmt(PID_PMT2, PROG2, version=2, pcr_pid=PID_301,
          prog_descs=b"", es_entries=[(PID_301, 0x0F, b"")])
    c.feed(w.bytes()[len(data):])
    c.finish()
    rows1 = read(db, PROG1)
    rows2 = read(db, PROG2)
    _check(len(rows1) == 1 and rows1[0][6] == late, "资格清空后晚完件放行（节目1）",
           failures)
    _check(len(rows2) == 1 and rows2[0][6] == late, "资格清空后晚完件放行（节目2）",
           failures)
    _check(rows1[0][3][1] == b"1" and rows2[0][3][1] == b"2",
           "完件冻结起件时归属与描述符", failures)


def cmd_demo(argv):
    outdir = argv[0] if argv else tempfile.mkdtemp(prefix="tscapture-demo-")
    os.makedirs(outdir, exist_ok=True)
    db = os.path.join(outdir, "capture.db")
    w, pes_a, pes_b, a_span, b_span = _build_example_stream()
    c = Collector(db)
    stream = w.bytes()
    # 演示任意切块
    i = 0
    while i < len(stream):
        n = 257
        c.feed(stream[i:i + n])
        i += n
    c.finish()

    print("出档演示（库：%s）" % db)
    for prog in (PROG1, PROG2):
        rows = read(db, prog)
        print("\n节目 %d：%d 条 PES 原件" % (prog, len(rows)))
        for r in rows:
            cap_id, gen, pid, sinfo, s, e, pes = r
            stype, es_desc, prog_desc, pcr = sinfo
            print("  采次=%d 代次=%d PID=%d 流类型=0x%02X 起包=%d 止包=%d"
                  " PES=%dB ES描述符=%r 节目描述符=%r PCR_PID=%d"
                  % (cap_id, gen, pid, stype, s, e, len(pes),
                     es_desc, prog_desc, pcr))
    archive = os.path.join(outdir, "program2_pid300.pes")
    rows2 = read(db, PROG2)
    with open(archive, "wb") as f:
        for r in rows2:
            if r[2] == PID_300:
                f.write(r[6])
    print("\n已导出节目2/PID300 全部 PES 原件到：%s（%d 件）" % (archive, len(rows2)))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m tscapture {verify|demo} [outdir]")
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "verify":
        return cmd_verify(rest)
    if cmd == "demo":
        return cmd_demo(rest)
    print("unknown command: %s" % cmd)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
