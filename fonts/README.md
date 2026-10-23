# CJK 中文字体说明 (Fonts)

为解决 `wkhtmltopdf` 在精简版 Docker 容器中导出 PDF 时的中文方块乱码（豆腐块）问题，本项目需要挂载 CJK 中文字体。

- 推荐字体：**文泉驿微米黑 (`wqy-microhei.ttc`)**
- 运行 `install.sh` 或 `docker compose up -d` 时，脚本会自动：
  1. 优先通过 `apt-get install -y fonts-wqy-microhei` 获取系统字体。
  2. 若系统无可用字体包，则自动从开源加速镜像下载并放入本目录。
- 容器内挂载映射至 `/usr/share/fonts/truetype/custom:ro`。
