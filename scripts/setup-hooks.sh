#!/bin/sh
# 一次性装配提交信息规范（CONTRIBUTING.md §5）：
#   core.hooksPath  -> .githooks/     提交信息不合规当场拒收
#   commit.template -> .gitmessage    编辑器里预填骨架
# 两者都是**本地**配置（.git/config），不随 clone 传播——每个 clone 跑一次。
# 幂等；scripts/acceptance.sh 结尾会提示是否漏跑。
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

chmod +x .githooks/commit-msg
git config core.hooksPath .githooks
git config commit.template .gitmessage

# 自检：钩子可执行、校验器真能跑（不真提交，只喂一条合规信息）
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf 'fix(fuse): 装配自检\n\n以实现：确认 .githooks/commit-msg 与校验器可用。\n' > "$tmp"
python3 scripts/commit_msg.py lint "$tmp"

echo "已装配：core.hooksPath=$(git config --get core.hooksPath)  commit.template=$(git config --get commit.template)"
echo "未装配的 clone 不会被强制——想跳过校验用 git commit --no-verify。"
