#!/usr/bin/env bash
# lixi-reverse · xdc.sh — 不依赖 Python 的第一响应（Linux / macOS / Termux）
# 用法: bash xdc.sh <目标> [需求]
# 作用: 头判型 + 大小 + sha256 + （ZIP/APK）条目分组 + 分层判定 + 下一步命令
# 纪律: 只读；深度分析走 python3 scripts/autoexec.py

set -u
TARGET="${1:-}"
NEED="${2:-}"
if [ -z "$TARGET" ] || [ ! -e "$TARGET" ]; then
  echo "[X] 用法: bash xdc.sh <目标> [需求]   （目标不存在: ${TARGET:-空}）" >&2
  exit 2
fi

SIZE=$(wc -c <"$TARGET" | tr -d ' ')
MB=$(awk -v s="$SIZE" 'BEGIN{printf "%.2f", s/1048576}')
if command -v sha256sum >/dev/null 2>&1; then
  SHA=$(sha256sum "$TARGET" | cut -c1-64)
elif command -v shasum >/dev/null 2>&1; then
  SHA=$(shasum -a 256 "$TARGET" | cut -c1-64)
else
  SHA="(无 sha256 工具)"
fi

# 读头 16 字节（od 通用）
HEAD=$(od -An -tx1 -N16 "$TARGET" | tr -s ' ' | sed 's/^ //')
KIND="未知/文本/其它"
case "$HEAD" in
  "7f 45 4c 46"*) KIND="ELF" ;;
  "50 4b 03 04"*|"50 4b 05 06"*) KIND="ZIP/APK/JAR" ;;
  "64 65 78 0a"*) KIND="DEX" ;;
  "1f 8b 08"*)    KIND="gzip" ;;
  "fd 37 7a 58"*) KIND="xz" ;;
  "42 5a 68"*)    KIND="bzip2" ;;
  "4d 5a"*)       KIND="PE(Windows)" ;;
  "25 50 44 46"*) KIND="PDF" ;;
esac

echo "== lixi-reverse · 第一响应（bash 版）"
echo "   目标: $TARGET"
echo "   大小: $SIZE B ($MB MB)   SHA256: $(echo "$SHA" | cut -c1-16)"
echo "   头16: $HEAD"
echo "   形态: $KIND"

if [ "$KIND" = "ELF" ]; then
  # e_type @0x10, e_machine @0x12（小端假设，常见情况足够）
  ET=$(od -An -tu2 -j16 -N2 "$TARGET" | tr -d ' ')
  EM=$(od -An -tu2 -j18 -N2 "$TARGET" | tr -d ' ')
  case "$ET" in
    1) TDESC="REL(内核模块/可重定位)" ;;
    2) TDESC="EXEC" ;;
    3) TDESC="DYN(PIE/so)" ;;
    *) TDESC="?" ;;
  esac
  case "$EM" in
    183) MDESC="AARCH64" ;; 62) MDESC="X86_64" ;; 40) MDESC="ARM" ;; *) MDESC="?" ;;
  esac
  echo "   ELF: type=$TDESC machine=$MDESC"
  echo "   >> 下一步: python3 scripts/elfprobe.py \"$TARGET\"   # 熵/自解密四指纹/大块高熵段"
  echo "             python3 scripts/container.py \"$TARGET\"  # 追加容器/节表"
  echo "             python3 scripts/rkprobe.py \"$TARGET\"     # 运行时打桩点"
  echo "             python3 scripts/jniprobe.py \"$TARGET\"    # JNI 动态注册"
fi

if [ "$KIND" = "ZIP/APK/JAR" ]; then
  if command -v unzip >/dev/null 2>&1; then
    DEXCNT=$(unzip -l "$TARGET" 2>/dev/null | grep -c 'classes[0-9]*\.dex$')
    SOCNT=$(unzip -l "$TARGET" 2>/dev/null | grep -c '\.so$')
    LUACNT=$(unzip -l "$TARGET" 2>/dev/null | grep -c '\.lua$')
    echo "   dex=$DEXCNT  so=$SOCNT  lua=$LUACNT"
    [ "$LUACNT" -ge 5 ] && echo "   [!] 成规模 .lua ⇒ 可能是脚本壳（闸门在脚本里）"
    unzip -l "$TARGET" 2>/dev/null | awk '/classes[0-9]*\.dex$/ {printf "     %-18s %12s B\n", $4, $1}'
  else
    echo "   [!] 没有 unzip，跳过条目统计（用 python3 scripts/autotriage.py 看）"
  fi
  echo "   >> 下一步: python3 scripts/autoexec.py \"$TARGET\" --need \"$NEED\""
  echo "             python3 scripts/luaq.py \"$TARGET\""
fi

if [ "$KIND" = "gzip" ]; then
  echo "   >> 下一步: python3 scripts/payload.py \"$TARGET\" --dump out"
fi
[ "$KIND" = "PE(Windows)" ] && echo "   >> Windows PE，本技能不覆盖（走 win-flow）"

[ -n "$NEED" ] && echo "   需求: $NEED"
echo ""
echo "   深度分析: python3 scripts/autoexec.py \"$TARGET\" --need \"$NEED\""
