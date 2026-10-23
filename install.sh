#!/bin/bash
# ==============================================================================
# MobSF-Chinese 一键安装与汉化挂载脚本
# GitHub: https://github.com/Genesiu/MobSF-Chinese
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "  🚀 欢迎使用 MobSF-Chinese (移动安全框架中文高保真补丁)"
echo "=========================================================="

# 1. 准备字体支持
mkdir -p "$SCRIPT_DIR/fonts"
if [ ! -f "$SCRIPT_DIR/fonts/wqy-microhei.ttc" ]; then
  echo "[1/4] 检测中文字体支持..."
  if command -v apt-get > /dev/null 2>&1; then
    echo "  -> 正在通过 apt-get 安装文泉驿微米黑字体..."
    apt-get update -qq && apt-get install -y -qq fonts-wqy-microhei || true
    if [ -f /usr/share/fonts/truetype/wqy/wqy-microhei.ttc ]; then
      cp /usr/share/fonts/truetype/wqy/wqy-microhei.ttc "$SCRIPT_DIR/fonts/"
    fi
  fi
  # 若 apt 失败或非 Debian/Ubuntu，下载 fallback
  if [ ! -f "$SCRIPT_DIR/fonts/wqy-microhei.ttc" ]; then
    echo "  -> 从开源镜像源加速下载文泉驿微米黑字体..."
    curl -fsSL -o "$SCRIPT_DIR/fonts/wqy-microhei.ttc" "https://ghproxy.net/https://raw.githubusercontent.com/anthonyfok/fonts-wqy-microhei/master/wqy-microhei.ttc" || \
    curl -fsSL -o "$SCRIPT_DIR/fonts/wqy-microhei.ttc" "https://raw.githubusercontent.com/anthonyfok/fonts-wqy-microhei/master/wqy-microhei.ttc" || true
  fi
fi

if [ -f "$SCRIPT_DIR/fonts/wqy-microhei.ttc" ]; then
  echo "  ✅ 中文字体就绪 ($(ls -lh "$SCRIPT_DIR/fonts/wqy-microhei.ttc" | awk '{print $5}'))"
fi

# 2. 检查权限边界 (针对 MobSF 非特权用户 UID 9901)
echo "[2/4] 配置非特权容器运行权限 (UID 9901)..."
chmod -R 755 "$SCRIPT_DIR/templates" "$SCRIPT_DIR/fonts"
if command -v chown > /dev/null 2>&1; then
  chown -R 9901:9901 "$SCRIPT_DIR/templates" "$SCRIPT_DIR/fonts" 2>/dev/null || true
fi

# 3. 启动或重启容器
echo "[3/4] 启动/重启 MobSF 容器以清空 Django 模板缓存..."
docker compose down 2>/dev/null || true
docker compose up -d

# 4. 轮询健康状态
echo "[4/4] 等待服务初始化与数据库迁移 (预计需 15~30 秒)..."
SUCCESS=0
for i in {1..35}; do
  if curl -sf http://127.0.0.1:8000/ > /dev/null 2>&1 || curl -sf http://127.0.0.1/ > /dev/null 2>&1; then
    SUCCESS=1
    break
  fi
  echo "  等待服务就绪中... ($i/35)"
  sleep 2
done

if [ $SUCCESS -eq 1 ]; then
  echo "=========================================================="
  echo "🎉 MobSF 中文版已成功启动并就绪！"
  echo "🌐 访问地址: http://localhost:8000 (或你的服务器公网/内网IP)"
  echo "🔑 默认账号: mobsf / mobsf"
  echo "=========================================================="
else
  echo "⚠️ 容器未能在预期时间内响应，输出最近 30 行容器日志排查："
  docker logs --tail 30 mobsf
fi
