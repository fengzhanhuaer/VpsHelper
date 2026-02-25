## 💻 源码调试与编译构建

**针对 Windows (PowerShell 首选开发套件测试环境)**:
您可以采用现成的封装批处理或原生 IDE 进行，只需先进入 `goapp` 模块。
```powershell
.\VpsHelper.bat
# 当您只需快速执行热代码重启验证时：
cd goapp
go run ./cmd/server
```

**针对 Linux/macOS (Bash 测试环境)**:
执行权限是首要的。
```bash
chmod +x VpsHelper.sh
./VpsHelper.sh
# 或是直接定位进源码目录跑起 Go Service
cd goapp
go run ./cmd/server/-c 配置文件
```

**手工指定跨平台 CGO 开关及架构出包编译 (Release态式)**:
VpsHelper 内嵌支持在无任何环境交叉打包跨越 ARMv8 和 AMD64 的探针子核算资源。
```bash
cd goapp
CGO_ENABLED=1 go build -o ../bin/vpshelper ./cmd/server
```

## 🔧 运行服务时的自选定制（环境变量）
| 定义名称 | 功能描述 | 缺省行为值 |
|-------------|-------------|---------|
| `VPSHELPER_LISTEN` | Web 服务层网关向对外暴露监听的具体地址范围与默认服务端口 | `:15018` |
| `VPSHELPER_DATA_DIR` | 整个平台运行时的 SQLite 归档、监控时序数据存储目录与证书热层 | `./userdata` |
| `TZ` 或 `VPSHELPER_TZ` | 为应用进程提供覆盖性质的系统地理时区纠偏参考 | `Asia/Shanghai` |

如果您采用了 Docker / OCI 结构容器化的环境套件进行服务载入，挂载落盘目录是保证您 SQLite 缓存池的命根子。
