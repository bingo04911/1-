# 1-

Surfboard 节点安全加固配置与审计工具。

- 加固配置模板：[`surfboard/surfboard.conf`](surfboard/surfboard.conf)
- 抗封锁手册：[`surfboard/anti-blocking.md`](surfboard/anti-blocking.md)
- 单机实战方案（自有 VPS + 第三方订阅）：[`surfboard/deployment-single-origin.md`](surfboard/deployment-single-origin.md)
- 配置安全审计脚本：[`scripts/audit_surfboard_conf.py`](scripts/audit_surfboard_conf.py)
- 说明与加固清单：[`surfboard/README.md`](surfboard/README.md)

```bash
python3 scripts/audit_surfboard_conf.py /path/to/your.conf
```
