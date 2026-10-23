#!/bin/bash
# ==============================================================================
# MobSF-Chinese 一键卸载与官方原版恢复脚本
# GitHub: https://github.com/Genesiu/MobSF-Chinese
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "  MobSF-Chinese 恢复官方原版"
echo "=========================================================="
echo "该操作将停止当前的中文挂载容器，并启动无挂载的官方原版 MobSF。"
echo "注：您的所有扫描记录与数据库数据将完好保留在 Docker 卷中。"
echo ""

docker compose down

echo "启动官方原版 (无汉化模板挂载)..."
docker run -d \
  --name mobsf-official \
  --restart unless-stopped \
  -p 8000:8000 \
  -v mobsf_chinese_mobsf_data:/home/mobsf/.MobSF \
  opensecurity/mobile-security-framework-mobsf:latest

echo "=========================================================="
echo "✅ 已成功回退至官方原版 MobSF！"
echo "🌐 访问地址: http://localhost:8000"
echo "=========================================================="
