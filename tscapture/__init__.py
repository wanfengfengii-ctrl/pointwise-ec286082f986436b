"""tscapture — H.222.0 transport stream PES capture into SQLite.

Collector(db)      每个实例对应一次新的采集（采次自增）
feed(bytes)        任意切块喂入 188 字节 TS
finish()           封口：弃未完、放行完件
read(db, program)  中途或重开查询，按采次、起包排序
"""

from .core import Collector, read

__all__ = ["Collector", "read"]
