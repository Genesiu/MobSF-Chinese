#!/bin/bash
# ==============================================================================
# MobSF-Chinese 一键安装、升级与汉化挂载脚本 (带版本自适应架构探测)
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
  echo "[1/6] 检测中文字体支持..."
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

# 2. 检查并准备数据持久化目录 (统一规范至 /data/mobsf_data，彻底避免 UID 9901 权限问题)
echo "[2/6] 准备数据持久化目录与权限 (UID 9901)..."
mkdir -p /data/mobsf_data
# 必须安装真实工具，空目录会让 MobSF 误判为已安装，实际扫描仍会失败。
JADX_DIR=/data/mobsf_data/tools/jadx/jadx-1.5.0
if [ ! -s "$JADX_DIR/lib/jadx-1.5.0-all.jar" ] || [ ! -x "$JADX_DIR/bin/jadx" ]; then
  command -v unzip >/dev/null || { echo "请先安装 unzip。"; exit 1; }
  JADX_TMP=$(mktemp -d)
  trap 'rm -rf "$JADX_TMP"' EXIT
  JADX_ZIP=${MOBSF_JADX_ZIP:-$SCRIPT_DIR/cache/jadx-1.5.0.zip}
  if [ ! -f "$JADX_ZIP" ]; then
    echo "  -> 下载官方 JADX 1.5.0（可用 MOBSF_JADX_ZIP 指定离线安装包）..."
    JADX_ZIP="$JADX_TMP/jadx.zip"
    curl -fL --connect-timeout 15 --max-time 300 --retry 1 \
      -o "$JADX_ZIP" https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
  fi
  unzip -tq "$JADX_ZIP" >/dev/null
  unzip -q "$JADX_ZIP" -d "$JADX_TMP/extracted"
  test -s "$JADX_TMP/extracted/lib/jadx-1.5.0-all.jar"
  test -s "$JADX_TMP/extracted/bin/jadx"
  mkdir -p "$JADX_DIR"
  cp -a "$JADX_TMP/extracted/." "$JADX_DIR/"
  chmod 755 "$JADX_DIR/bin/jadx" "$JADX_DIR/bin/jadx-gui"
  rm -rf "$JADX_TMP"
  trap - EXIT
fi
if [ ! -f /data/mobsf_data/secret ]; then
  (umask 077; head -c 32 /dev/urandom | base64 > /data/mobsf_data/secret)
fi
chmod 750 /data/mobsf_data
chmod 600 /data/mobsf_data/secret
if command -v chown > /dev/null 2>&1; then
  chown -R 9901:9901 /data/mobsf_data 2>/dev/null || true
fi
echo "MOBSF_DATA_DIR=/data/mobsf_data" > "$SCRIPT_DIR/.env"
echo "  -> 持久化目录与真实 JADX 工具已就绪。"

# 3. 检查权限边界 (针对 MobSF 非特权用户 UID 9901)
echo "[3/6] 配置非特权容器运行权限 (UID 9901)..."
chmod -R 755 "$SCRIPT_DIR/templates" "$SCRIPT_DIR/templates_v4.5" "$SCRIPT_DIR/fonts" 2>/dev/null || chmod -R 755 "$SCRIPT_DIR/templates" "$SCRIPT_DIR/fonts" 2>/dev/null || true
if command -v chown > /dev/null 2>&1; then
  chown -R 9901:9901 "$SCRIPT_DIR/templates" "$SCRIPT_DIR/templates_v4.5" "$SCRIPT_DIR/fonts" 2>/dev/null || true
fi

# 4. MobSF 版本检测与汉化架构自适应判断 (Version Compatibility Matrix)
echo "[4/6] 智能检测 MobSF 镜像与架构版本..."
MOBSF_IMAGE="opensecurity/mobile-security-framework-mobsf:latest"

# 优先拉取或确认镜像存在
if ! docker image inspect "$MOBSF_IMAGE" >/dev/null 2>&1; then
  echo "  -> 本地未检测到 $MOBSF_IMAGE，正在拉取最新镜像..."
  docker pull "$MOBSF_IMAGE" || true
fi

IS_V46_PLUS=1
DETECTED_VER=""

# 静态读取目标镜像版本，不能导入 settings（会触发初始化和后台下载）。
if docker image inspect "$MOBSF_IMAGE" >/dev/null 2>&1; then
  DETECTED_VER=$(docker run --rm --network none --entrypoint python3 "$MOBSF_IMAGE" -c "import ast,pathlib; print([ast.literal_eval(n.value) for n in ast.parse(pathlib.Path('mobsf/MobSF/init.py').read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in n.targets)][0])" 2>/dev/null || true)
fi

# 判定规则 3: 架构特征探测 (检查镜像内是否存在 landing_nav.html)
if docker image inspect "$MOBSF_IMAGE" >/dev/null 2>&1; then
  if docker run --rm --network none --entrypoint test "$MOBSF_IMAGE" -f /home/mobsf/Mobile-Security-Framework-MobSF/mobsf/templates/general/includes/landing_nav.html 2>/dev/null; then
    IS_V46_PLUS=1
  else
    IS_V46_PLUS=0
  fi
else
  # 兜底默认按最新版
  IS_V46_PLUS=1
fi

# 如果拿到了版本号，结合版本号双重校验
if [ -n "$DETECTED_VER" ]; then
  MAJOR=$(echo "$DETECTED_VER" | cut -d. -f1 | tr -cd '0-9')
  MINOR=$(echo "$DETECTED_VER" | cut -d. -f2 | tr -cd '0-9')
  if [ -n "$MAJOR" ] && [ -n "$MINOR" ]; then
    if [ "$MAJOR" -gt 4 ] || ([ "$MAJOR" -eq 4 ] && [ "$MINOR" -ge 6 ]); then
      IS_V46_PLUS=1
    else
      IS_V46_PLUS=0
    fi
  fi
fi

if [ "$IS_V46_PLUS" -eq 1 ]; then
  echo "  ✅ 匹配架构: MobSF ${DETECTED_VER:-4.6.1+} (>= 4.6.0 新版架构)"
  echo "  -> 激活最新模块化汉化套件 (独立导航、拖拽上传防劫持、深色模式切换)"
  if [ -f "$SCRIPT_DIR/docker-compose.v4.6.yml" ]; then
    cp "$SCRIPT_DIR/docker-compose.v4.6.yml" "$SCRIPT_DIR/docker-compose.yml"
  fi
else
  echo "  ℹ️ 匹配架构: MobSF ${DETECTED_VER:-4.5.x} (<= 4.5.x 经典架构)"
  echo "  -> 激活经典兼容汉化套件 (templates_v4.5)"
  if [ -f "$SCRIPT_DIR/docker-compose.v4.5.yml" ]; then
    cp "$SCRIPT_DIR/docker-compose.v4.5.yml" "$SCRIPT_DIR/docker-compose.yml"
  fi
fi

# 5. 安全启动容器 (仅监听 8000 端口，防御性清理历史残留端点)
echo "[5/6] 停止旧容器并以 8000 端口启动 MobSF 汉化版..."
docker compose up -d

# 6. 轮询健康状态 (仅探活 8000 端口)
echo "[6/6] 等待服务初始化与数据库迁移 (网络较慢时可能需要数分钟)..."
SUCCESS=0
for i in {1..90}; do
  if curl -sf --max-time 3 http://127.0.0.1:8000/login/ > /dev/null 2>&1; then
    SUCCESS=1
    break
  fi
  echo "  等待服务就绪中... ($i/90)"
  sleep 2
done

if [ $SUCCESS -eq 1 ]; then
  echo "=========================================================="
  echo "🎉 MobSF 中文版已成功启动并就绪！"
  echo "🌐 访问地址: http://<你的服务器IP>:8000"
  echo "🔑 默认账号: mobsf / mobsf"
  echo "=========================================================="
else
  echo "⚠️ 容器未能在预期时间内响应，输出最近 30 行容器日志排查："
  docker logs --tail 30 mobsf
  exit 1
fi
