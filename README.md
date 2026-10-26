# MobSF-Chinese (移动安全框架中文高保真汉化补丁)

<p align="center">
  <img src="https://raw.githubusercontent.com/MobSF/Mobile-Security-Framework-MobSF/master/mobsf/static/img/mobsf_logo.png" width="220" alt="MobSF Logo">
</p>

<p align="center">
  <b>针对 Mobile Security Framework (MobSF) 的现代化、零侵入、生产级中文汉化解决方案</b>
</p>

<p align="center">
  <a href="https://github.com/Genesiu/MobSF-Chinese/releases"><img src="https://img.shields.io/badge/Release-v4.6.1-blue.svg?style=flat-square" alt="Release"></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPL%20v3.0-green.svg?style=flat-square" alt="License"></a>
  <a href="https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf"><img src="https://img.shields.io/badge/Docker-Official%20Image-2496ED.svg?style=flat-square&logo=docker" alt="Docker"></a>
  <a href="https://github.com/Genesiu/MobSF-Chinese/stargazers"><img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome"></a>
</p>

---

## 🌟 核心特性与设计哲学

许多团队在汉化 MobSF 时直接硬编码 Python 源码或分发第三方重打包镜像，这不仅破坏了版本升级能力，更存在引入不可信后门代码的安全风险。**MobSF-Chinese 坚决采用“架构解耦与非侵入外挂（Overlay）”设计理念：**

- 🛡️ **100% 官方可信基线**：直接基于官方最新的 `opensecurity/mobile-security-framework-mobsf:latest` 原版 Docker 镜像运行，**不夹带任何第三方预编译黑盒镜像**，满足严苛的企业与合规审计安全要求。
- ⚡ **零破坏底层分析引擎**：底层 8,000+ 条 Android/iOS 安全检测规则、APKTool、JADX、Ghidra 等二进制反编译引擎 100% 保持官方原汁原味，直接享受官方最新分析能力升级。
- 🎯 **全域深度汉化覆盖**：
  - **核心门户**：静态拖拽分析首页、历史扫描记录面板、用户认证与管理全套页面。
  - **交互看板**：侧边栏 40+ 专项导航、主看板卡片、四大组件（Activity/Service/Receiver/Provider）统计、风险评级与指标徽章、安全合规标准（OWASP/CWE/MASVS）列头。
  - **安全审计报告**：全量重构中文 PDF 导出模版，内置 CJK 字体映射配置，彻底根除 wkhtmltopdf 生成 PDF 时的**“中文豆腐块/乱码”**顽疾。
- 🔄 **智能多版本自适应**：原生适配 MobSF >= 4.6.0 现代架构与 <= 4.5.x 经典架构，安装升级脚本自带版本探针与动态切换能力。

---

## 📦 版本对应关系与升级兼容矩阵 (Compatibility Matrix)

| MobSF 官方版本 | 架构类型 | 模板架构目录 | 对应编排文件 | 核心技术差异与特性 |
| :--- | :--- | :--- | :--- | :--- |
| **MobSF >= 4.6.0**<br>(包含 **4.6.1 / latest**) | **现代模块化架构**<br>*(当前最新主干)* | `templates/`<br>(含 `general/includes/`) | `docker-compose.yml`<br>`docker-compose.v4.6.yml` | 1. 首页升级为 `.home-shell` 与 `.home-main`<br>2. 导航与页脚模块化拆分为 `landing_nav.html`、`landing_footer.html`<br>3. 上传重构为 `<label class="drop-zone">`，支持多文件并发队列与进度追踪<br>4. 顶部导航栏增加深色/浅色模式切换按钮 |
| **MobSF <= 4.5.x**<br>(如 4.2.x - 4.5.4) | **经典单体架构**<br>*(历史兼容分支)* | `templates_v4.5/`<br>`templates/` (共享部分) | `docker-compose.v4.5.yml` | 1. 首页采用经典 Bootstrap 4 Flex 居中布局 (`.d-flex.h-100`)<br>2. 单体 `home.html` 内嵌所有导航与页脚<br>3. 常规按钮上传与 `#package` 在线包名下载输入框 |

> [!IMPORTANT]
> **升级排坑：为什么首页点击任何按钮都弹出上传窗口？**
> MobSF 从 **v4.6.0** 起将上传区重构为 `<label class="fileUpload drop-zone">`，镜像内置的 `home.css` 定义了 `.fileUpload input { position: absolute; inset: 0; width: 100%; height: 100%; }`。若将老版（v4.5.x）的 `home.html` 挂载到新版镜像，由于缺失父级布局约束，隐藏的透明文件输入框会铺满整个视口，导致用户点击页面任意链接或按钮时均触发上传事件。**升级至本仓库最新版后，此问题已被彻底修复！**

---

## 🚀 快速上手 (Quick Start)

### 场景 A：从零全新启动（开箱即用）

如果你尚未部署 MobSF，请克隆本仓库后运行安装脚本，准备真实的 JADX 工具、数据目录与模板挂载：

```bash
git clone https://github.com/Genesiu/MobSF-Chinese.git
cd MobSF-Chinese
sudo bash install.sh
```
启动后访问：`http://<服务器IP>:8000` 即可进入中文版 MobSF。默认凭据：`mobsf` / `mobsf`。

首次安装需下载官方 JADX 1.5.0。服务器访问 GitHub 较慢时，可先下载官方的
`jadx-1.5.0.zip`，再用 `sudo MOBSF_JADX_ZIP=/绝对路径/jadx-1.5.0.zip bash install.sh`
离线安装。安装脚本会检查压缩包和实际工具文件，不会用空目录冒充安装成功。

三个 Compose 配置均将 `${MOBSF_DATA_DIR:-/data/mobsf_data}` 挂载到
`/home/mobsf/.MobSF`，保存工具、数据库与扫描结果。已有容器若未挂载该目录，
请先备份容器内 `/home/mobsf/.MobSF` 并迁移数据，再重建容器。

---

### 场景 B：为已有 MobSF 实例一键安装/升级汉化

如果你的服务器上已经通过 Docker 运行了官方 MobSF，或者需要平滑升级汉化包：

```bash
# 1. 进入 MobSF-Chinese 目录并拉取最新补丁
cd /opt/MobSF-Chinese  # 或你克隆的目录，如 ~/MobSF-Chinese
git pull origin main

# 2. 执行自适应安装脚本（自动探测镜像架构、配置 CJK 字体、挂载新版模板并重启）
sudo bash install.sh
```

脚本将自动执行以下操作：
1. 探测宿主机 MobSF 版本与模板特性，自动匹配挂载 `>=4.6.0` 或 `<=4.5.x` 模板；
2. 检查并准备文泉驿微米黑 CJK 字体；
3. 配置非特权 UID 9901 属主权限，避免 `PermissionError`；
4. 平滑重启容器，仅监听 `8000` 端口。

---

## 🔄 一键平滑卸载 (Rollback)

如果你需要切换回官方原版英文界面，只需运行卸载脚本：

```bash
cd /opt/MobSF-Chinese
sudo bash uninstall.sh
```
该操作仅移除模板挂载并重启容器，**绝不会删除任何已有扫描记录与分析产物（`/data/mobsf_data/`）**。

---

## 📁 仓库目录结构

```text
MobSF-Chinese/
├── README.md                   # 项目介绍、版本对应关系与部署指南
├── LICENSE                     # GNU GPL v3.0 开源协议
├── docker-compose.yml          # 开箱即用 Docker Compose (默认适配 >=4.6.0)
├── docker-compose.v4.6.yml     # MobSF >= 4.6.0 现代架构专用配置
├── docker-compose.v4.5.yml     # MobSF <= 4.5.x 经典架构兼容配置
├── install.sh                  # 带版本自动探针的一键安装与升级脚本
├── uninstall.sh                # 一键卸载与恢复脚本
├── templates/                  # >= 4.6.0 现代架构汉化模板
│   ├── base/
│   │   └── nav.html            # 导航栏 + 深色模式切换 + 全局侧边栏汉化引擎
│   ├── general/
│   │   ├── home.html           # 现代外壳拖拽分析首页 (防点击劫持)
│   │   ├── recent.html         # 历史扫描记录面板
│   │   └── includes/           # 模块化包含组件
│   │       ├── landing_nav.html    # 首页顶部中文导航
│   │       └── landing_footer.html # 首页底部信息与状态栏
│   ├── auth/
│   │   ├── login.html          # 用户登录页
│   │   ├── change_password.html # 密码修改页
│   │   └── users.html          # 用户管理页
│   └── pdf/
│       └── android_report.html # 中文 PDF 报告（内置 CJK 字体声明）
└── templates_v4.5/             # <= 4.5.x 经典架构归档模板
    └── general/
        └── home.html           # 经典单体首页模板
```

---

## 🛠️ 技术原理与常见排坑 (FAQ)

<details>
<summary><b>1. 为什么修改了挂载模板，界面文字没有发生变化？</b></summary>
<br>
MobSF 在生产模式下默认启用了 Django 的 <code>cached.Loader</code> 模板缓存机制。编译后的 HTML 会常驻 Gunicorn 内存中。因此，每次修改模板文件后，<b>必须重启容器（<code>docker compose restart</code>）</b>清空进程缓存方可生效。
</details>

<details>
<summary><b>2. 为什么挂载后容器启动报 <code>PermissionError: [Errno 13]</code> 权限拒绝？</b></summary>
<br>
MobSF 容器出于安全最佳实践，以非特权用户 <code>mobsf</code>（UID 9901，GID 9901）运行。宿主机上所有被挂载的模板文件及目录必须确保赋权：
<pre><code>chmod -R 755 /data/mobsf_custom
chown -R 9901:9901 /data/mobsf_custom</code></pre>
本项目的 <code>install.sh</code> 脚本已自动为你处理好此权限边界。
</details>

<details>
<summary><b>3. PDF 导出的中文为什么会变成方形方块（豆腐块）？</b></summary>
<br>
MobSF 内部使用 <code>wkhtmltopdf</code> 渲染 PDF 报告。官方 Docker 镜像基于精简的 Debian 镜像，未打包中文字体。本项目通过在宿主机部署 <b>文泉驿微米黑 (WenQuanYi Micro Hei)</b> 字体文件并挂载至容器 <code>/usr/share/fonts/truetype/custom:ro</code>，同时在 PDF 模板中强制设定 CJK 字体族，完美消除乱码。
</details>

---

## 🤝 贡献与致谢 (Contributing & Credits)

- 核心框架归属于原作者 **[Ajin Abraham](https://github.com/ajinabraham)** 及 **[OpenSecurity](https://opensecurity.in)** 的开源项目 [Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)。
- 汉化及部署编排由 **[Genesiu Security Lab](https://github.com/Genesiu)** 维护与开源。
- 欢迎提交 Issue 反馈翻译建议，或提交 Pull Request 完善更多分析报告场景！

---

## 📜 开源协议

本项目遵循 **[GNU General Public License v3.0 (GPL-3.0)](LICENSE)** 协议开源。
