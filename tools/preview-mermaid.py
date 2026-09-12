#!/usr/bin/env python3
"""把 Markdown 里的 Mermaid 图渲染成 PNG，用于提交前预览。

Mermaid 的排版依赖浏览器的文本测量（SVG getBBox），纯 Python / jsdom
都给不出可信布局——标签压住子图标题、文字被框体截断这类问题只有真正
渲染出来才看得见。本脚本用 Playwright 驱动 headless Chromium，结果与
GitHub 的渲染一致。

依赖（一次性，约 150MB，仅本地预览用，不参与项目构建）：

    python3 -m venv /tmp/mmdvenv
    /tmp/mmdvenv/bin/pip install playwright
    /tmp/mmdvenv/bin/playwright install chromium
    npm install --prefix /tmp mermaid@11     # 或靠下面的 CDN 回退

用法：

    /tmp/mmdvenv/bin/python tools/preview-mermaid.py docs/architecture.md
    /tmp/mmdvenv/bin/python tools/preview-mermaid.py docs/architecture.md -i 1 -o /tmp/x.png

常见布局问题与对策：
  - 子图标题被连线标签遮挡 → 别拿 subgraph 当连线端点，改连子图内的节点
  - 标签被相邻节点框截断     → 缩短标签，或改变 flowchart 方向（TB/LR）
"""
import argparse
import json
import pathlib
import re
import sys

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("缺少 playwright，见本文件头部的依赖安装说明")

# 本地 mermaid 优先，缺失时回退 CDN（需要网络）
LOCAL_MERMAID = pathlib.Path("/tmp/node_modules/mermaid/dist/mermaid.min.js")
CDN_MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"


def extract(md_path: pathlib.Path, index: int) -> str:
    blocks = re.findall(r"```mermaid\n(.*?)\n```", md_path.read_text(encoding="utf-8"), re.S)
    if not blocks:
        sys.exit(f"{md_path} 中没有 mermaid 代码块")
    if index >= len(blocks):
        sys.exit(f"{md_path} 只有 {len(blocks)} 个 mermaid 块，索引 {index} 越界")
    return blocks[index]


def render(code: str, out_png: pathlib.Path, scale: float) -> None:
    if LOCAL_MERMAID.exists():
        script = f"<script>{LOCAL_MERMAID.read_text(encoding='utf-8')}</script>"
    else:
        script = f'<script src="{CDN_MERMAID}"></script>'
        print(f"本地未找到 mermaid，改用 CDN：{CDN_MERMAID}")

    html = (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><style>'
        'body{margin:0;background:#fff;'
        'font-family:"Noto Sans CJK SC","Source Han Sans SC",sans-serif}'
        f"</style>{script}</head><body><div id=out></div></body></html>"
    )

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1200},
                                device_scale_factor=scale)
        page.set_content(html, wait_until="load")
        dim = json.loads(page.evaluate(
            """async (code) => {
                mermaid.initialize({startOnLoad:false, theme:'default', securityLevel:'loose'});
                const {svg} = await mermaid.render('d', code);
                document.getElementById('out').innerHTML = svg;
                const el = document.querySelector('#out svg');
                el.removeAttribute('style');     // 去掉 max-width，按真实尺寸截图
                const bb = el.getBBox();
                return JSON.stringify({w: Math.ceil(bb.width), h: Math.ceil(bb.height)});
            }""",
            code,
        ))
        print(f"图尺寸：{dim['w']} x {dim['h']} px")
        page.locator("#out svg").screenshot(path=str(out_png))
        browser.close()
    print("已输出：", out_png)


def main() -> None:
    ap = argparse.ArgumentParser(description="渲染 Markdown 中的 Mermaid 图为 PNG")
    ap.add_argument("markdown", nargs="?", default="docs/architecture.md")
    ap.add_argument("-i", "--index", type=int, default=0, help="第几个 mermaid 块（默认 0）")
    ap.add_argument("-o", "--out", default="/tmp/mermaid-preview.png")
    ap.add_argument("-s", "--scale", type=float, default=2.0, help="缩放倍率（默认 2.0）")
    args = ap.parse_args()

    md = pathlib.Path(args.markdown)
    if not md.is_file():
        sys.exit(f"找不到文件：{md}")
    render(extract(md, args.index), pathlib.Path(args.out), args.scale)


if __name__ == "__main__":
    main()
