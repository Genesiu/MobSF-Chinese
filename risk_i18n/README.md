# 风险正文汉化与升级适配

这是显示层补丁，当前覆盖 Android 的 52 条代码规则、53 条清单规则（158 个文字字段）。APK、源码 ZIP 页面及 Android PDF 使用同一词典。它不改检测逻辑、风险级别、CVSS、抑制规则标识、数据库或 API JSON；历史报告无需重新扫描。另已覆盖安全计分卡的界面，以及 iOS 二进制、Mach-O 防护和通用摘要中的已审校文案；普通分析报告也支持 iOS 和 Windows 的已审校风险文案，详见“常规报告”。

规则 ID 是 MobSF 自带的标识，不保证跨版本永远不变。本工具同时检查 ID、字段原文及 SHA-256；未知规则、变更原文、无法匹配的历史文字保留英文。版本号只用于标记是否验证过，不替代原文检查。当前实机验证为 4.5.2。本地 4.5.4 通过模板结构检查，发生变更的文案来源已列入兼容性报告。新增规则域可沿用 `rules.<domain>.<id>.<field>` 格式及独立过滤器。

## 新部署或计划内升级

`install.sh` 用于新部署或主动升级，默认启用本功能。为已有实例补汉化时，先按下一节确认实际版本。安装程序会在无网络、无数据库的临时容器内从所选镜像重新生成九个模板（包含安全计分卡），结构不兼容时停止启动步骤。规则原文变化仅关闭对应字段的翻译，结果会列在 `risk_i18n/generated/current/compatibility.json` 中，仍允许原始英文正常展示。

单独生成与启动：

```bash
export MOBSF_IMAGE=opensecurity/mobile-security-framework-mobsf:v4.5.2
bash risk_i18n/prepare.sh "$MOBSF_IMAGE"
docker compose -f docker-compose.v4.5.yml -f docker-compose.risk-i18n.yml up -d
```

也可以直接用 `MOBSF_IMAGE=opensecurity/mobile-security-framework-mobsf:v4.5.2 bash install.sh` 固定版本，由安装脚本选择基础 Compose 文件。独立生成时，必须让 `prepare.sh` 和 Compose 选择同一镜像，4.6.x 选用 `docker-compose.v4.6.yml`。`prepare.sh` 使用本地镜像。生成的 PDF 基于该镜像原始模板，覆盖旧的整页 PDF 挂载；旧模板中本功能范围外的自定义改动不会自动继承。导航、登录等其他现有挂载沿用原配置。以后更新这些其他挂载时仍需各自验证。本工具的挂载只是部署附件，不会消除 MobSF 自身升级所需的数据迁移或备份。

关闭风险正文翻译可用 `MOBSF_RISK_I18N=0 bash install.sh`（不加载风险覆盖文件），或在服务环境中将 `MOBSF_RISK_LOCALE` 改成 `en` 后重建服务。后一种方式保留中文静态表头、恢复英文正文。安装补丁或更新词典后需重载服务进程，避免旧的模板或词典缓存继续生效。

## 已有独立容器：按当前版本安装外挂

先读取目标容器内实际运行的 MobSF 版本，再选用该版本的模板和词典。独立容器直接更新显示层文件，沿用原容器、镜像及数据。下面以目标版本为 `4.5.2` 为例。将整个 `risk_i18n` 目录复制到容器，再在应用根目录执行：

```bash
python3 /tmp/mobsf-risk-i18n/overlay.py check
python3 /tmp/mobsf-risk-i18n/overlay.py apply --expect-version 4.5.2 \
  --backup-dir /tmp/mobsf-risk-i18n-backups
```

`--expect-version` 与实际版本不同会拒绝修改文件。需要可写的模板目录；只读挂载请用目标实例的同一镜像生成 Compose 外挂，并沿用原数据卷。`check` 无写操作，核对九个模板的结构及当前规则。`apply` 先计算所有文件，再备份，写入失败自动恢复。重复执行无变化时不重复备份。将输出中的备份目录复制到宿主机持久保存，再按实际运行方式平滑重载 Gunicorn。为已有独立容器补汉化时，使用上述流程，避免运行全量安装脚本或切换到 `latest`。

回滚前先检查有无后续人工修改：

```bash
python3 /tmp/mobsf-risk-i18n/overlay.py rollback --backup /tmp/mobsf-risk-i18n-backups/实际备份目录
```

回滚拒绝覆盖安装后的新改动；恢复成功后同样需要重载进程。Compose 升级时应保留旧镜像和原挂载配置；`generated/previous` 仅保留上一次生成文件，不能代替完整的版本及数据回滚。

## 补译与验证

- `sources/4.5.2.json` 是公开规则原文快照，不含扫描数据。
- `translations.zh-CN.json` 是人工可审校译文；`catalog.zh-CN.json` 是带原文指纹的生成产物。
- 修改译文后运行 `python3 risk_i18n/build_catalog.py`；检查产物用 `--check`。新版本完成审校后可用 `--source risk_i18n/sources/版本.json` 指定新的完整原文快照。
- 用 `python3 -m unittest discover -s risk_i18n -p 'test_*.py'` 验证参数保留、英文回退、模板作用范围及备份回滚。
- 支持 Python 3.12+（与 MobSF 一致），使用 MobSF 自带的 PyYAML、Django。

动态 `%s` / `%d` 参数通过固定文本边界提取，中文使用 `{0}` 等编号保留参数，限制输入长度并继续使用 Django 自动转义，不将译文标记为 HTML。原文 `A%s %s` 的首参数只是英语冠词后缀，显式记录 `ignored_slots: [0]`；其他参数必须全部保留。JSON 构建会检查缺失规则及占位参数；更换上游原文必须同步审校译文、更新源快照及验证记录，不能只改指纹来绕过检查。

升级验收建议用已有报告检查页面、实际导出 PDF 的中文字体，以及 API/原始结果不变。当前版本的代码规则用合成样例验证了显示与安全转义；实机历史代码分析字段为空，不能据此声称验证了真实代码命中结果。

风险正文补丁与基础界面汉化是两层独立内容。升级验收时不能只检查页面返回成功：还应确认 `/recent_scans/` 的“最近扫描记录”、导航及登录文字实际为中文。已有独立容器没有 Compose 挂载时，重建后需要重新安装基础界面模板；原容器内复制的文件不会自动进入新容器。验证范围见 [验证记录](VALIDATION.md)。


## 安全计分卡

`static_analysis/appsec_dashboard.html` 的标题、图表图例、风险分组及提示均在显示层翻译。`scorecard.zh-CN.json` 包含 58 个字段匹配模式、23 个 iOS 内置权限说明。计分卡上游已去掉部分原始规则 ID，因此这层使用来源文件指纹和完整原文模式匹配，不把新编号当作 MobSF 自带规则 ID。来源文件变化时对应整组译文回退英文，兼容性检查会列出 `scorecard_changed_origins`。

Android 计分卡复用常规报告的清单规则、系统权限、签名证书和 Firebase 译文。清单匹配同时核对标题和详情，保留计分卡移入详情的原始权限证据。未知、变更或匹配有歧义时显示原文。

动态域名、计数、函数符号、文件路径、原始密钥证据和应用作者填写的权限用途说明均保留；地理数据仅更换字段标签，国家或城市等原始值保留。较大的证据文本只翻译固定开头，不扫描或改写证据。所有输出继续经过模板自动转义。此层不修改评分算法、风险分级、API 或扫描数据库。

## 常规报告

Android 网页和 PDF 加入网络安全、签名证书、ELF 原生库、文件检查与 Firebase 风险文案。Android 网页还涵盖内置 API 名称，网页和 PDF 都支持已审校的 Android 系统权限说明。常规报告的侧栏、章名、操作和表头由服务端模板直接输出中文。iOS 的 IPA、源码网页及 PDF 覆盖 ATS、代码规则、二进制、Mach-O 与库防护、文件检查及 Firebase。源码报告的内置 API 标题和 iOS 内置权限说明也可本地化。Windows 网页和 PDF 覆盖风险表头、状态及已审校的 MobSF 内置二进制提示。外部 BinSkim、BinScope 文案、自定义规则、未审校的独立规则正文及原始证据按原文显示。

静态风险补充词典 `report.zh-CN.json` 记录原文、译文和上游来源。iOS 源码规则同时匹配 ID 和原文，其他字段仅匹配已审校的原文格式。升级检查的 `report_changed_origins` 指出需要复核的来源文件，对应译文回退英文。根据目标镜像的上游模板生成补丁，缺少必要的模板定位点时停止安装。Windows 样例验证不能替代实际扫描报告验收。
