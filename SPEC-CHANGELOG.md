# 插件市场规范变更历史

规范全文见 desktop-cc-gui 仓库 `docs/plugin-development-guide.zh-CN.md`。
本文件只记录规范的演进；每次规范变更（新权限、新字段、规则收紧）在此追加一段。

## v0.2 — 2026-09-22（索引条目新增 updatedAt）

- `plugins/<id>.json` 新增必填字段 `updatedAt`：该版本 Release 的发布时间（RFC 3339 UTC，如 `2026-09-20T08:30:00Z`）。
- 写入方：版本登记机器人从 GitHub Release API 读取；API 不可用时用登记时刻兜底（与真实发布时间最多差一个 cron 周期）。人工提「版本登记 PR」时自行填写。
- CI：字段必填、格式合法；PR 模式下版本号变更时必须随之更新（防把旧时间抄到新版本）；只刷新 `updatedAt`、其余字段不变的 PR（回填/校正）不算版本登记。
- App 端：插件详情页用它显示「最近更新时间」；条目缺字段时只是不渲染该行（不拿本机安装时间冒充）。

## v0.1 — 2026-09-12（初始版本）

- 分发模式（Obsidian 同款）：中央索引仓 + 每插件独立 GitHub repo + GitHub Releases 发版，零自建服务器。
- 索引结构：`community-plugins.json`（列表：id/repo/name/description/author，按 id 字典序）+ `plugins/<id>.json`（版本登记：version/tier/permissions/sha256/minAppVersion/sdkVersion/delisted/pubkey）。
- 发版约定：Release tag == manifest.json 的 `version`（无 `v` 前缀）；Release 附件固定 `main.js`（Tier-0 可无）/ `manifest.json` / `styles.css`（可选）/ `checksums.txt`。
- 体积：bundle ≤ 512KB（CI 警告）/ 2MB（硬上限，gzip 前）。
- 安全：索引登记 SHA256 为信任锚；bundle 黑名单扫描（`eval(` / `new Function(` / `__TAURI__` / `localStorage` / 远程 `import(`）；CSS 禁 `@import` 与远程 `url()`。
- 权限白名单以 desktop-cc-gui `packages/plugin-sdk/spec/permissions.json` 为单一事实源（基座 14 项 + `network:`/`exec:` 授权）。
- 流程：首次上架 = 人工审核；版本登记（只改 `plugins/<id>.json`、无权限新增、CI 通过、PR 作者 = 插件仓库所有者）= 机器人自动合并；权限新增 = 转人工。
