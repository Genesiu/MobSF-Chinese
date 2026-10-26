# MobSF-Chinese (移动安全框架中文高保真汉化补丁)

<p align="center">
  <img src="https://raw.githubusercontent.com/MobSF/Mobile-Security-Framework-MobSF/master/mobsf/static/img/mobsf_logo.png" width="220" alt="MobSF Logo">
</p>

<p align="center">
  <b>针对 Mobile Security Framework (MobSF) 的现代化、零侵入、生产级中文汉化解决方案</b>
</p>

<p align="center">
  <a href="https://github.com/Genesiu/MobSF-Chinese/releases"><img src="https://img.shields.io/badge/Release-v4.5.4-blue.svg?style=flat-square" alt="Release"></a>
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
- 🔄 **秒级安装与平滑回退**：提供自动化一键挂载脚本与原生恢复脚本，无需改动现有数据库或扫描产物。

---

## 📸 汉化效果速览

| 模块区域 | 汉化覆盖说明 |
| :--- | :--- |
| **顶部导航与侧边栏** | 静态/动态分析、资产侦察、恶意行为、合规基线、SBOM 等 40+ 菜单项全中文支持 |
| **静态分析仪表盘** | 综合安全评分卡、平均 CVSS 评分、应用基本特征、加壳与混淆识别卡片 |
| **漏洞与合规表格** | 风险级别（高危/中危/提示/安全）、OWASP MASVS 对齐、涉及文件与详细描述 |
| **PDF 审计报告** | 封面标题、摘要等级、二十余个安全检测章节及文泉驿微米黑高清排版 |

---

## 🚀 快速上手 (Quick Start)

### 场景 A：从零全新启动（开箱即用）

如果你尚未部署 MobSF，只需克隆本仓库并执行 `docker compose up -d` 即可秒级启动已完整汉化的 MobSF：

```bash
git clone https://github.com/Genesiu/MobSF-Chinese.git
cd MobSF-Chinese
docker compose up -d
```
启动后访问：`http://<服务器IP>:8000` 即可进入中文版 MobSF。默认凭据：`mobsf` / `mobsf`。

---

### 场景 B：为已有 MobSF 实例一键应用汉化

如果你的服务器上已经通过 Docker 运行了官方 MobSF，无需停止或重新初始化数据库：

```bash
# 1. 克隆汉化包
git clone https://github.com/Genesiu/MobSF-Chinese.git /opt/MobSF-Chinese

# 2. 执行一键安装脚本（自动安装 CJK 字体、挂载模板并重启容器）
cd /opt/MobSF-Chinese
sudo bash install.sh
```

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
├── README.md                   # 项目介绍与部署指南
├── LICENSE                     # GNU GPL v3.0 开源协议
├── docker-compose.yml          # 开箱即用的 Docker 编排配置
├── install.sh                  # 一键挂载与字体配置脚本
├── uninstall.sh                # 一键卸载与恢复脚本
└── templates/                  # 高保真汉化模板资产
    ├── base/
    │   └── nav.html            # 顶部导航 + 全局侧边栏 + 看板指标 DOM 汉化引擎
    ├── general/
    │   ├── home.html           # 静态分析拖拽上传首页
    │   └── recent.html         # 最近扫描记录与版本对比弹窗
    ├── auth/
    │   ├── login.html          # 用户登录页
    │   ├── change_password.html # 密码修改页
    │   └── users.html          # 用户管理页
    └── pdf/
        └── android_report.html # 中文 PDF 报告（内置 CJK 字体声明）
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
