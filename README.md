# 1-

Surfboard 节点安全加固配置与审计工具。

- 加固配置模板：[`surfboard/surfboard.conf`](surfboard/surfboard.conf)
- 抗封锁手册：[`surfboard/anti-blocking.md`](surfboard/anti-blocking.md)
- 单机实战方案（自有 VPS + 第三方订阅）：[`surfboard/deployment-single-origin.md`](surfboard/deployment-single-origin.md)
- 手机端泄漏检查（DNS / WebRTC）：[`surfboard/android-leaks.md`](surfboard/android-leaks.md)
- 立即可用的修漏配置：[`surfboard/examples/leakfix-now.conf`](surfboard/examples/leakfix-now.conf)
- 配置生成器（零占位符）：[`scripts/gen_surfboard_conf.py`](scripts/gen_surfboard_conf.py)
- 服务端一键部署：[`server/setup.sh`](server/setup.sh)
- 配置安全审计脚本：[`scripts/audit_surfboard_conf.py`](scripts/audit_surfboard_conf.py)
- 说明与加固清单：[`surfboard/README.md`](surfboard/README.md)

```bash
python3 scripts/audit_surfboard_conf.py /path/to/your.conf
```
