#!/usr/bin/env node
/**
 * ccgui-plugins 索引仓校验器（PR CI / main 全量复检共用，零依赖，Node ≥ 20）。
 *
 * 校验层级：
 *  1. 结构：community-plugins.json 唯一性/字典序 ↔ plugins/<id>.json 交叉引用
 *  2. 登记条目 schema（id/repo/tier/version/permissions/sha256/minAppVersion/sdkVersion）
 *  3. 远端：下载 GitHub Release 产物（tag 必须 == version，无 v 前缀）→
 *     SHA256 比对、体积上限、黑名单扫描、CSS 静态解析、README/LICENSE 存在性、
 *     Release manifest 与登记条目一致性、权限-代码比对（ctx 调用启发式）
 *  4. PR 模式（--base）：version 单调递增、权限新增标记（新增 → 禁止自动合并）
 *
 * 用法：
 *   node scripts/validate.mjs --all                          # 全量（push to main）
 *   node scripts/validate.mjs --base origin/main             # PR：远端核查只跑变动条目
 *   附加：--report <path>（Markdown 审核报告） --result <path>（机器可读结果）
 *
 * 权限白名单镜像 desktop-cc-gui packages/plugin-sdk/spec/permissions.json
 * （单一事实源）；宿主升级白名单时此处必须同步。
 */
import { readFileSync, readdirSync, existsSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const COMMUNITY_FILE = "community-plugins.json";
const PLUGINS_DIR = "plugins";
/** 编辑精选（客户端市场页首屏轮播，方案 A）。文件可缺省 = 没有精选区。 */
const FEATURED_FILE = "featured.json";
/** 客户端同一上限（desktop-cc-gui src-tauri/src/plugins/market.rs 的
 *  MAX_FEATURED_ROWS）：多出来的行客户端会静默忽略，所以在登记入口就拦下。 */
const FEATURED_MAX_ROWS = 8;
const FEATURED_KEYS = new Set(["id", "tagline", "note", "image"]);

// ---------------------------------------------------------------------------
// 权限白名单（镜像 plugin-sdk/spec/permissions.json，SDK 0.3.20；勿在此独断修改）
// ---------------------------------------------------------------------------
const KNOWN_PERMISSIONS = new Set([
  "storage",
  "ui:settings-section",
  "ui:add-menu",
  "ui:composer-status",
  "ui:panel-tab",
  "ui:status-bar",
  "ui:overlay",
  "ui:command",
  "ui:markdown",
  "ui:page",
  "ui:timeline-row",
  "ui:workspace-menu",
  "ui:session-menu",
  "ui:sidebar-entry",
  "ui:center-tab",
  "ui:conversation-mode",
  "agent",
  "theme",
  "i18n",
  "events",
  "network:none",
  "composer:draft",
  "host:session",
  "host:workspace",
  "host:workspace:remote",
  "host:worktree",
  "host:window",
  "host:models",
  "session.lifecycle.read",
  "runtime.events.read",
  "runtime.switch.observe",
  "prompt.contribute.internal",
  "workspace.metadata.read",
  "plugin.storage",
  "assets:bundle",
  "assets:directory",
]);

/** network: 授权体：<host>（任意端口）/ <host>:<port> / <host>:<a>-<b>（含端点）。 */
// $(?![\s\S]) 要求真正的字符串尾，不能让 $ 放过末尾换行。
const NETWORK_GRANT_RE = /^([A-Za-z0-9.-]+)(?::(\d+)(?:-(\d+))?)?$(?![\s\S])/;
/** exec: 授权的二进制名：裸名，禁路径分隔符。 */
const EXEC_BIN_RE = /^[A-Za-z0-9._-]+$(?![\s\S])/;

export function isKnownPermission(p) {
  if (KNOWN_PERMISSIONS.has(p)) return true;
  if (p.startsWith("network:")) {
    const body = p.slice("network:".length);
    const m = NETWORK_GRANT_RE.exec(body);
    if (!m || m[1].toLowerCase() === "none") return false; // none 仅是基座权限，不能带端口变成授权
    if (m[2] === undefined) return true;
    const from = Number(m[2]);
    const to = m[3] === undefined ? from : Number(m[3]);
    return from >= 1 && to <= 65535 && from <= to;
  }
  if (p.startsWith("exec:")) return EXEC_BIN_RE.test(p.slice("exec:".length));
  return false;
}

// ---------------------------------------------------------------------------
// semver（规范只允许三段数字，无 pre-release）
// ---------------------------------------------------------------------------
const SEMVER_RE = /^\d+\.\d+\.\d+$/;

export function parseSemver(v) {
  if (typeof v !== "string" || !SEMVER_RE.test(v)) return null;
  return v.split(".").map(Number);
}

export function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// schema 常量
// ---------------------------------------------------------------------------
/**
 * 插件 id：镜像 plugin-sdk/spec/permissions.json 的 pluginIdShapes
 * （与 Rust src-tauri/src/plugins/manifest.rs::is_valid_id 逐字节一致）。
 * 总长 2..=64；点分段，每段 [a-z0-9][a-z0-9-]*。id 同时是安装目录名，
 * 故该规则也是路径穿越护栏（禁 `/`、`\`、`..`、首尾点、空段）。
 * 无需 `m` 的 `$` 只保证「行尾」，尾巴上盖 (?![\s\S]) 才是真正的字符串尾：
 * 否则 "ab\n" / "ab\u2028" 这类带尾随换行的 id 会被放行。
 */
const ID_RE = /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*$(?![\s\S])/;
const ID_MIN_BYTES = 2;
const ID_MAX_BYTES = 64;

/**
 * Release 附件名：镜像宿主 src-tauri/src/plugins/market.rs::is_valid_asset_name。
 * 客户端把每个固定附件按原名平铺写进 staging 树，所以只接受扁平名
 * （禁子目录、禁 `.`/`..`），字符集 [A-Za-z0-9._-]。
 */
const ASSET_NAME_RE = /^[A-Za-z0-9._-]+$/;

export function isValidAssetName(name) {
  return typeof name === "string" && name !== "." && name !== ".." && ASSET_NAME_RE.test(name);
}
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SDK_RANGE_RE = /^(\^|~|>=)?\d+\.\d+(\.\d+)?$|^\*$/;
const TIERS = new Set(["declarative", "js"]);
const ENTRY_KEYS = new Set([
  // updatedAt：宿主 IndexDetail 读取的固定发布时间（规范 §10.3，机器人登记
  // 新版本时写入）。原先缺这一键，带它的条目会被判「未知字段」。
  "id", "repo", "tier", "version", "updatedAt", "minAppVersion", "sdkVersion",
  "permissions", "sha256", "delisted", "pubkey", "icon", "screenshots",
]);
/** RFC 3339 UTC，与宿主 updated_at 的渲染口径一致。 */
const UPDATED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const COMMUNITY_KEYS = new Set(["id", "repo", "name", "description", "author"]);

/** 与宿主的插件目录名/路径穿越护栏一致，登记与自动升级共用。 */
export function isValidPluginId(id) {
  if (typeof id !== "string") return false;
  const bytes = Buffer.byteLength(id, "utf8");
  return bytes >= ID_MIN_BYTES && bytes <= ID_MAX_BYTES && ID_RE.test(id);
}

/** 展示素材（SPEC-CHANGELOG v0.2）：manifest 声明，机器人镜像进索引。 */
const MAX_SCREENSHOTS = 5;
const MAX_MEDIA_PATH_CHARS = 1024;
const IMAGE_EXT_RE = /\.(png|jpe?g|webp|gif|svg|avif)$/i;

/**
 * 校验一条展示素材路径并归一化：接受仓库内相对路径或绝对 https URL。
 * 拒绝其他 scheme、协议相对/绝对路径、反斜杠、控制字符、`..` 逃逸与
 * 非图片扩展名——与宿主 `resolve_asset_url` 的放行面一致，多一条扩展名
 * 检查（App 遇到非图片只会渲染成破图，在登记入口拦下）。
 * @returns {string|null} 归一化后的路径；null = 不合法。
 */
export function normalizeMediaPath(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_MEDIA_PATH_CHARS) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return null;
  if (trimmed.includes("\\")) return null;
  if (!IMAGE_EXT_RE.test(trimmed.split(/[?#]/, 1)[0])) return null;
  if (/^https:\/\//i.test(trimmed)) {
    try {
      return new URL(trimmed).toString();
    } catch {
      return null;
    }
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed) || trimmed.startsWith("//") || trimmed.startsWith("/")) {
    return null;
  }
  if (trimmed.split("/").some((segment) => segment === "..")) return null;
  return trimmed;
}

/** manifest 里的 icon / screenshots 共用的形状校验；返回错误句子或 null。 */
export function mediaFieldProblem(label, value) {
  if (label === "icon") {
    return normalizeMediaPath(value) === null
      ? `icon 不合法（需仓库内相对路径或 https URL，图片扩展名，≤ ${MAX_MEDIA_PATH_CHARS} 字符）`
      : null;
  }
  if (!Array.isArray(value)) return `${label} 必须是字符串数组`;
  if (value.length > MAX_SCREENSHOTS) return `${label} 超过 ${MAX_SCREENSHOTS} 张`;
  for (const shot of value) {
    if (normalizeMediaPath(shot) === null) return `${label} 含不合法路径 ${JSON.stringify(shot)}`;
  }
  return null;
}

/**
 * 去掉展示素材字段后的规范化 JSON：判断「同版本的 PR 是否只在登记素材」。
 * 字段顺序归一化后比较，避免 JSON 键序差异造成误判。
 */
function canonicalEntryWithoutMedia(entry) {
  const copy = {};
  for (const key of Object.keys(entry).sort()) {
    if (key === "icon" || key === "screenshots") continue;
    const value = entry[key];
    copy[key] =
      value && typeof value === "object" && !Array.isArray(value)
        ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, value[k]]))
        : value;
  }
  return JSON.stringify(copy);
}

export const MAIN_WARN_BYTES = 512 * 1024; // 规范 §4：bundle ≤ 512KB 警告
export const MAIN_MAX_BYTES = 2 * 1024 * 1024; // 规范 §4：2MB 硬上限（gzip 前）
const REPORT_MAX_CHARS = 60_000; // GitHub 评论上限 65536

// bundle 黑名单（规范 §9.1 门禁）
export const JS_BLACKLIST = [
  { re: /\beval\s*\(/, label: "eval(" },
  { re: /new\s+Function\s*\(/, label: "new Function(" },
  { re: /__TAURI__/, label: "__TAURI__" },
  { re: /\blocalStorage\b/, label: "localStorage" },
  { re: /import\s*\(\s*['"`]https?:\/\//, label: "远程 import(" },
];

/**
 * localStorage 例外插件（仓库维护者审核后手动登记，插件作者无法在自己
 * manifest/代码里自行声明豁免）：ctx.storage 是插件私有 KV，物理上读不到
 * 宿主自己的 UI 持久化键（ccgui-next.* 等），部分插件靠读写这些公开约定
 * 键实现「获取当前 tab/会话状态」等能力，没有替代的官方 API。
 *
 * 豁免是整体放行（不逐 key 静态解析）：压缩后的 bundle 里字符串常被拼接/
 * 模板化（如 `prefix + key`），正则无法可靠还原运行时真实访问的 key，
 * 伪装成精确检测反而是假的安全感。真正的把关在登记环节——只有仓库维护者
 * 改这份脚本才能新增豁免，插件作者无法自行在 manifest/代码里声明绕过；
 * 新增前必须人工审过该插件的源码，确认用途确实是访问
 * ALLOWED_LOCALSTORAGE_KEY_PREFIXES 描述的宿主约定键，不是任意读写。
 */
const LOCALSTORAGE_EXEMPT_PLUGIN_IDS = new Set(["model-switcher"]);
/** 豁免插件实际访问的 key 前缀（文档性说明，供审核者核对源码时参考，
 *  不参与自动化判定）：宿主 UI 状态（ccgui-next.*）与插件自身的远程
 *  降级缓存（ccgui.plugin.remote:<pluginId>:*，remote-storage.ts 对
 *  ctx.storage 的封装层，与直接绕过沙箱无关）。 */
const ALLOWED_LOCALSTORAGE_KEY_PREFIXES = ["ccgui-next.", "ccgui.plugin.remote:"];
export const CSS_BLACKLIST = [
  { re: /@import\b/i, label: "@import" },
  { re: /url\(\s*['"]?https?:\/\//i, label: "url(http…)" },
];

// SDK 能力面 → 权限（权限-代码比对启发式；事实源 plugin-sdk references/api.md）
//
// 匹配从成员路径开始，不绑定接收者名字：打包后的 bundle 会把 activate 的
// 上下文参数压缩成任意标识符（CCB 1.0.2 是 `t.ui.registerSettingsSection`），
// 写死 `ctx.` 会让「调用了却没声明」这条错误判定对所有压缩产物失效。
//
// - requires：匹配到却没声明 = 错误。只给能唯一确定权限的调用点。
// - satisfies：算作「该权限在用」，只用于抑制「声明了但没用到」的警告。
//   一个调用点对应多个候选权限（宿主按入参字段分别门禁，静态无法区分）时
//   只填 satisfies，避免误报错误。
const CTX_PERMISSION_MAP = [
  { api: "ui.registerSettingsSection", re: /\.ui\.registerSettingsSection\s*\(/, requires: "ui:settings-section" },
  { api: "ui.registerAddMenuRow", re: /\.ui\.registerAddMenuRow\s*\(/, requires: "ui:add-menu" },
  { api: "ui.registerComposerSlot", re: /\.ui\.registerComposerSlot\s*\(/, requires: "ui:composer-status" },
  { api: "ui.registerComposerStatusItem", re: /\.ui\.registerComposerStatusItem\s*\(/, requires: "ui:composer-status" },
  { api: "ui.registerPanelTab", re: /\.ui\.registerPanelTab\s*\(/, requires: "ui:panel-tab" },
  { api: "ui.registerStatusBarItem", re: /\.ui\.registerStatusBarItem\s*\(/, requires: "ui:status-bar" },
  { api: "ui.registerCommand", re: /\.ui\.registerCommand\s*\(/, requires: "ui:command" },
  { api: "ui.registerMarkdownRenderer", re: /\.ui\.registerMarkdownRenderer\s*\(/, requires: "ui:markdown" },
  { api: "ui.registerPage", re: /\.ui\.registerPage\s*\(/, requires: "ui:page" },
  { api: "ui.registerTimelineRowRenderer", re: /\.ui\.registerTimelineRowRenderer\s*\(/, requires: "ui:timeline-row" },
  { api: "ui.registerSidebarNav", re: /\.ui\.registerSidebarNav\s*\(/, requires: "ui:sidebar-entry" },
  { api: "ui.registerCenterTab", re: /\.ui\.registerCenterTab\s*\(/, requires: "ui:center-tab" },
  { api: "ui.openCenterTab", re: /\.ui\.openCenterTab\s*\(/, requires: "ui:center-tab" },
  { api: "ui.registerWorkspaceMenuItem", re: /\.ui\.registerWorkspaceMenuItem\s*\(/, requires: "ui:workspace-menu" },
  { api: "ui.registerSessionMenuItem", re: /\.ui\.registerSessionMenuItem\s*\(/, requires: "ui:session-menu" },
  { api: "ui.registerOverlay", re: /\.ui\.registerOverlay\s*\(/, requires: "ui:overlay" },
  { api: "ui.registerConversationMode", re: /\.ui\.registerConversationMode\s*\(/, requires: "ui:conversation-mode" },
  // 通用名字的 namespace（models / sessions / window / storage / events …）必须
  // 连同 SDK 真实方法名一起匹配：裸 `.models.` 会打到 API 响应里的数据字段
  // （实测 `d.models.map`、`k.models.length`）、内部 Map（`this.sessions.get`）
  // 和特性探测（`e.window.getState` 之外的 `e.window &&`），把合规插件判死。
  // SDK 方法名与 Array/Map 的成员名不重叠，所以绑方法名既避免误报也不漏真调用。
  { api: "agent.*", re: /\.agent\.(catalog|start|interrupt)\s*\(/, requires: "agent" },
  { api: "theme.*", re: /\.theme\.(injectCss|setTokens)\s*\(/, requires: "theme" },
  { api: "i18n.addBundle", re: /\.i18n\.addBundle\s*\(/, requires: "i18n" },
  { api: "storage.*", re: /\.storage\.(get|set|delete)\s*\(/, requires: "storage" },
  { api: "events.*", re: /\.events\.(on|emit)\s*\(/, requires: "events" },
  { api: "composer.setDraft", re: /\.composer\.setDraft\s*\(/, requires: "composer:draft" },
  { api: "documentStorage.*", re: /\.documentStorage\.[A-Za-z]+\s*\(/, requires: "plugin.storage" },
  { api: "workspace.getMetadata", re: /\.workspace\.getMetadata\s*\(/, requires: "workspace.metadata.read" },
  { api: "workspaces.add", re: /\.workspaces\.add\s*\(/, requires: "host:workspace" },
  { api: "workspaces.list", re: /\.workspaces\.list\s*\(/, requires: "host:workspace" },
  { api: "worktrees.*", re: /\.worktrees\.(create|remove)\s*\(/, requires: "host:worktree" },
  {
    api: "sessions.*",
    re: /\.sessions\.(selectSession|refresh|setEffort|startRun|interruptRun|registerSource|list)\s*\(/,
    requires: "host:session",
  },
  {
    api: "window.*",
    re: /\.window\.(getState|setNormalBounds|sampleWechat)\s*\(/,
    requires: "host:window",
  },
  {
    api: "models.*",
    re: /\.models\.(listEngines|listEngineModels|catalog)\s*\(/,
    requires: "host:models",
  },
  { api: "hooks.registerSessionHooks", re: /\.hooks\.registerSessionHooks\s*\(/, requires: "session.lifecycle.read" },
  { api: "hooks.registerRuntimeSwitchHooks", re: /\.hooks\.registerRuntimeSwitchHooks\s*\(/, requires: "runtime.switch.observe" },
  // 同一调用点按 hooks 字段分别门禁（onRuntimeEvent/afterTurn 要
  // runtime.events.read，beforeTurn/onInternalMessage 要
  // prompt.contribute.internal），静态分不开，故不作硬性错误。
  {
    api: "hooks.registerTurnHooks",
    re: /\.hooks\.registerTurnHooks\s*\(/,
    satisfies: ["runtime.events.read", "prompt.contribute.internal"],
  },
];
const BRIDGE_NETWORK_RE = /plugin_http_request/;
const BRIDGE_EXEC_RE = /plugin_exec_(run|spawn)/;

/**
 * 权限声明 vs 产物代码比对（纯函数，便于直接测试）。
 * 漏声明 = 错误；声明了但未检出调用 = 警告（交审核员裁量，启发式不足以判死）。
 */
export function comparePermissionsWithCode(id, permissions, text) {
  const errors = [];
  const warnings = [];
  const declared = new Set(permissions);
  for (const { api, re, requires } of CTX_PERMISSION_MAP) {
    if (requires && re.test(text) && !declared.has(requires)) {
      errors.push(`${id}: 代码使用 ${api} 但未声明权限 "${requires}"`);
    }
  }
  if (BRIDGE_NETWORK_RE.test(text) && ![...declared].some((p) => p.startsWith("network:"))) {
    errors.push(`${id}: 代码调用 plugin_http_request 但未声明任何 network: 授权`);
  }
  if (BRIDGE_EXEC_RE.test(text) && ![...declared].some((p) => p.startsWith("exec:"))) {
    errors.push(`${id}: 代码调用 plugin_exec_* 但未声明任何 exec: 授权`);
  }
  const used = new Set(
    CTX_PERMISSION_MAP.filter(({ re }) => re.test(text)).flatMap((m) => m.satisfies ?? [m.requires]),
  );
  // host:workspace:remote 是 workspaces.add 携带 wsl meta 时的升级修饰，
  // 同一调用点，无法靠静态启发式区分；host:workspace 已检出即视为在用。
  if (used.has("host:workspace")) used.add("host:workspace:remote");
  for (const p of declared) {
    if (KNOWN_PERMISSIONS.has(p) && p !== "network:none" && !used.has(p)) {
      warnings.push(`${id}: 声明了权限 "${p}" 但未在代码中检出对应调用（请审核员确认是否多余）`);
    }
  }
  return { errors, warnings };
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function fmtSize(n) {
  return n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(2)} MB` : `${(n / 1024).toFixed(1)} KB`;
}

function loadJson(relPath, errors) {
  try {
    return JSON.parse(readFileSync(path.join(ROOT, relPath), "utf8"));
  } catch (err) {
    errors.push(`${relPath} 解析失败：${err.message}`);
    return null;
  }
}

function gitShow(base, relPath) {
  const r = spawnSync("git", ["show", `${base}:${relPath}`], {
    cwd: ROOT, encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
  });
  return r.status === 0 ? r.stdout : null;
}

function gitChangedFiles(base) {
  const r = spawnSync("git", ["diff", "--name-only", `${base}...HEAD`], {
    cwd: ROOT, encoding: "utf8",
  });
  if (r.status !== 0) return null;
  return r.stdout.split("\n").map((s) => s.trim()).filter(Boolean);
}

// 瞬时故障退避重试：传输层错误与 408/429/5xx 重试，404 等确定性响应立刻返回。
const RETRYABLE_STATUS = new Set([408, 429, 500, 502, 503, 504]);
/** fetchRaw 的第三态：连接不通，既不能断定存在也不能断定缺失。 */
export const UNREACHABLE = "unreachable";

export async function fetchWithRetry(url, { timeoutMs, attempts = 3, backoffMs = 400 } = {}) {
  let last = "网络错误：未发起请求";
  for (let i = 0; i < attempts; i += 1) {
    if (i > 0) await new Promise((r) => setTimeout(r, backoffMs * 2 ** (i - 1)));
    let res;
    try {
      res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      last = `网络错误：${err.message}`;
      continue;
    }
    if (res.ok || !RETRYABLE_STATUS.has(res.status)) return { res };
    last = `HTTP ${res.status}`;
  }
  return { error: `${last}（已重试 ${attempts} 次）` };
}

/** 下载 Release 附件；404 与其他错误分开报。 */
export async function downloadAsset(repo, tag, file) {
  const url = `https://github.com/${repo}/releases/download/${tag}/${file}`;
  const { res, error } = await fetchWithRetry(url, { timeoutMs: 30_000 });
  if (error) return { error };
  if (!res.ok) return { error: `HTTP ${res.status}`, status: res.status };
  return { buf: Buffer.from(await res.arrayBuffer()) };
}

/**
 * 仓库根文件是否存在。三态：true 存在、false 确定缺失（404）、
 * UNREACHABLE 连接不通。不可达绝不能当成「缺文件」判错——否则网络抽风
 * 会把合规 PR 判死（2026-10-08 实测 raw.githubusercontent 偶发连接失败，
 * 同一 tag 的 README 连续请求里一次 200、一次 HTTP 000）。
 */
async function fetchRaw(repo, ref, file) {
  const url = `https://raw.githubusercontent.com/${repo}/${ref}/${file}`;
  const { res, error } = await fetchWithRetry(url, { timeoutMs: 15_000 });
  if (error) return UNREACHABLE;
  return res.ok ? true : res.status === 404 ? false : UNREACHABLE;
}

/** 三态存在性的报告标记：✅ 存在 / ❌ 缺失 / ⚠️ 连不上（未能确认）。 */
function presenceMark(state) {
  if (state === true) return "✅";
  if (state === UNREACHABLE) return "⚠️ 未能确认（连接失败）";
  return "❌";
}

// ---------------------------------------------------------------------------
// community-plugins.json 全局校验
// ---------------------------------------------------------------------------
export function validateCommunityList(list, errors, warnings) {
  if (!Array.isArray(list)) {
    errors.push(`${COMMUNITY_FILE} 必须是数组`);
    return;
  }
  const seen = new Set();
  let prev = null;
  for (const [i, item] of list.entries()) {
    const where = `${COMMUNITY_FILE}[${i}]`;
    if (typeof item !== "object" || item === null) {
      errors.push(`${where} 必须是对象`);
      continue;
    }
    for (const k of Object.keys(item)) {
      if (!COMMUNITY_KEYS.has(k)) warnings.push(`${where} 含未知字段 "${k}"`);
    }
    for (const k of ["id", "repo", "name", "description", "author"]) {
      if (typeof item[k] !== "string" || !item[k].trim()) errors.push(`${where}.${k} 缺失或不是非空字符串`);
    }
    if (typeof item.id === "string") {
      if (!isValidPluginId(item.id)) errors.push(`${where}.id "${item.id}" 不合法（2..64 字节，${ID_RE}）`);
      if (seen.has(item.id)) errors.push(`${where}.id "${item.id}" 重复`);
      seen.add(item.id);
      if (prev !== null && item.id.localeCompare(prev) <= 0) {
        errors.push(`${COMMUNITY_FILE} 未按 id 字典序排列："${prev}" 之后出现 "${item.id}"`);
      }
      prev = item.id;
    }
    if (typeof item.repo === "string" && !REPO_RE.test(item.repo)) {
      errors.push(`${where}.repo "${item.repo}" 不合法（需 owner/repo 形式）`);
    }
  }
  return seen;
}

// ---------------------------------------------------------------------------
// featured.json 校验（编辑精选：id + 编辑文案 + 可选封面）
// ---------------------------------------------------------------------------
/**
 * 精选条目只是「指向索引里已有插件的编辑文案」，所以规则很短：
 * id 必须已在 community-plugins.json 里（否则客户端整条丢掉）、不重复、
 * 不超过客户端上限；tagline/note 要么是非空文案要么整字段不写；image 走与
 * icon 相同的素材路径规则（相对路径按**插件仓库**解析，绝对 https 直连）。
 */
export function validateFeatured(list, knownIds, errors, warnings) {
  if (list === null) return;
  if (!Array.isArray(list)) {
    errors.push(`${FEATURED_FILE} 必须是数组（或整个文件不写）`);
    return;
  }
  if (list.length > FEATURED_MAX_ROWS) {
    errors.push(`${FEATURED_FILE} 有 ${list.length} 条，超过客户端上限 ${FEATURED_MAX_ROWS} 条（多出的不会显示）`);
  }
  const seen = new Set();
  for (const [i, row] of list.entries()) {
    const where = `${FEATURED_FILE}[${i}]`;
    if (typeof row !== "object" || row === null) {
      errors.push(`${where} 必须是对象`);
      continue;
    }
    for (const k of Object.keys(row)) {
      if (!FEATURED_KEYS.has(k)) warnings.push(`${where} 含未知字段 "${k}"（客户端会忽略）`);
    }
    if (typeof row.id !== "string" || !row.id.trim()) {
      errors.push(`${where}.id 缺失或不是非空字符串`);
      continue;
    }
    if (seen.has(row.id)) errors.push(`${where}.id "${row.id}" 重复（同一插件只该出现一次）`);
    seen.add(row.id);
    if (!knownIds.has(row.id)) {
      errors.push(`${where}.id "${row.id}" 不在 ${COMMUNITY_FILE} 里 —— 客户端会把这一条静默丢掉，等于白写`);
    }
    for (const key of ["tagline", "note"]) {
      if (row[key] === undefined) continue;
      if (typeof row[key] !== "string" || !row[key].trim()) {
        errors.push(`${where}.${key} 必须是非空字符串（没有就整字段不写）`);
      } else if (/[\u0000-\u001f\u007f]/.test(row[key])) {
        errors.push(`${where}.${key} 含控制字符`);
      }
    }
    if (row.image !== undefined && normalizeMediaPath(row.image) === null) {
      errors.push(`${where}.image 不合法（插件仓库内相对路径或 https URL，图片扩展名，≤ ${MAX_MEDIA_PATH_CHARS} 字符）`);
    }
  }
}

// ---------------------------------------------------------------------------
// plugins/<id>.json schema 校验
// ---------------------------------------------------------------------------
export function validateEntry(entry, fileName, errors, warnings) {
  const where = `${PLUGINS_DIR}/${fileName}`;
  if (typeof entry !== "object" || entry === null) {
    errors.push(`${where} 必须是对象`);
    return;
  }
  for (const k of Object.keys(entry)) {
    if (!ENTRY_KEYS.has(k)) warnings.push(`${where} 含未知字段 "${k}"`);
  }
  if (!isValidPluginId(entry.id)) {
    errors.push(`${where}.id 不合法（2..64 字节，${ID_RE}）`);
  } else if (entry.id !== fileName.replace(/\.json$/, "")) {
    errors.push(`${where}.id "${entry.id}" 与文件名 "${fileName}" 不一致`);
  }
  if (typeof entry.repo !== "string" || !REPO_RE.test(entry.repo)) {
    errors.push(`${where}.repo 不合法（需 owner/repo 形式）`);
  }
  if (!TIERS.has(entry.tier)) {
    errors.push(`${where}.tier "${entry.tier}" 不合法：只能是 "declarative" 或 "js"`);
  }
  if (!parseSemver(entry.version)) {
    errors.push(`${where}.version "${entry.version}" 不合法：semver 三段数字`);
  }
  if (entry.updatedAt !== undefined && !UPDATED_AT_RE.test(entry.updatedAt)) {
    errors.push(`${where}.updatedAt "${entry.updatedAt}" 不合法：需 RFC 3339 UTC（如 2026-09-20T08:30:00Z）`);
  }
  if (entry.minAppVersion !== undefined && !parseSemver(entry.minAppVersion)) {
    errors.push(`${where}.minAppVersion "${entry.minAppVersion}" 不合法`);
  }
  if (entry.sdkVersion !== undefined && !SDK_RANGE_RE.test(entry.sdkVersion)) {
    errors.push(`${where}.sdkVersion "${entry.sdkVersion}" 不合法：支持 "*"、精确三段、"^x.y(.z)"、"~x.y.z"、">=x.y.z"`);
  }
  if (entry.delisted !== undefined && typeof entry.delisted !== "boolean") {
    errors.push(`${where}.delisted 必须是布尔值`);
  }
  for (const field of ["icon", "screenshots"]) {
    if (entry[field] === undefined) continue;
    const problem = mediaFieldProblem(field, entry[field]);
    if (problem) errors.push(`${where}.${problem}`);
  }
  const permissions = entry.permissions ?? [];
  if (!Array.isArray(permissions)) {
    errors.push(`${where}.permissions 必须是字符串数组`);
  } else {
    for (const p of permissions) {
      if (typeof p !== "string" || !isKnownPermission(p)) {
        errors.push(`${where}.permissions 含未知权限 "${p}"`);
      }
    }
  }
  const sha = entry.sha256;
  if (typeof sha !== "object" || sha === null) {
    errors.push(`${where}.sha256 缺失（必须登记每个 Release 附件的 SHA256）`);
  } else {
    if (typeof sha["manifest.json"] !== "string" || !SHA256_RE.test(sha["manifest.json"])) {
      errors.push(`${where}.sha256["manifest.json"] 缺失或不合法（64 位小写 hex）`);
    }
    if (entry.tier === "js" && (typeof sha["main.js"] !== "string" || !SHA256_RE.test(sha["main.js"]))) {
      errors.push(`${where}.sha256["main.js"] 缺失或不合法（tier=js 必须有 main.js）`);
    }
    for (const [file, hash] of Object.entries(sha)) {
      if (!isValidAssetName(file)) {
        errors.push(
          `${where}.sha256 含非法附件名 "${file}"` +
          `（需扁平文件名 [A-Za-z0-9._-]，禁子目录与 . / ..——客户端把附件平铺进 staging 树）`,
        );
      } else if (file === "manifest.json" || (file === "main.js" && entry.tier === "js")) {
        continue; // 已在上方必填检查中报过
      } else if (typeof hash !== "string" || !SHA256_RE.test(hash)) {
        errors.push(`${where}.sha256["${file}"] 不合法（64 位小写 hex）`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// 远端核查：Release 产物 / SHA256 / 体积 / 黑名单 / manifest 一致性
// ---------------------------------------------------------------------------
async function checkRelease(entry, errors, warnings, report) {
  const { id, repo, version, tier } = entry;
  const tag = version; // 规范 §4：tag 必须 == version，无 v 前缀
  // 客户端安装会下载索引固定的**每一个**附件（market.rs::install_from_marketplace
  // 遍历 entry.sha256 的全部键），所以远端核查范围必须与固定集一致，
  // 否则多余/漏传的附件要到用户安装时才暴露。
  const pinned = Object.keys(entry.sha256 ?? {}).filter(isValidAssetName).sort();
  const assets = [
    "manifest.json",
    ...(tier === "js" ? ["main.js"] : []),
    ...pinned.filter((name) => name !== "manifest.json" && name !== "main.js"),
  ];

  const downloaded = {};
  for (const file of assets) {
    const r = await downloadAsset(repo, tag, file);
    if (r.error) {
      errors.push(
        `${id}: 下载 ${file} 失败（${r.error}）：https://github.com/${repo}/releases/download/${tag}/${file}` +
        (r.status === 404 ? ` —— 检查 Release tag 是否恰好等于 version "${version}"（无 v 前缀）且附件已上传` : ""),
      );
      return;
    }
    downloaded[file] = r.buf;
    const hash = sha256Hex(r.buf);
    if (hash !== entry.sha256[file]) {
      errors.push(
        `${id}: ${file} SHA256 不符（索引 ${entry.sha256[file].slice(0, 12)}… ≠ 实际 ${hash.slice(0, 12)}…）` +
        `——产物必须由仓库 release.yml Action 从源码构建，禁止手工替换`,
      );
    }
    report.artifacts.push(`${file} ${fmtSize(r.buf.length)} ${hash === entry.sha256[file] ? "✅" : "❌ sha256"}`);
  }

  // 体积
  const main = downloaded["main.js"];
  if (main) {
    if (main.length > MAIN_MAX_BYTES) {
      errors.push(`${id}: main.js ${fmtSize(main.length)} 超过 2MB 硬上限`);
    } else if (main.length > MAIN_WARN_BYTES) {
      warnings.push(`${id}: main.js ${fmtSize(main.length)} 超过 512KB 警告阈值`);
    }
  }

  // 黑名单扫描
  if (main) {
    const text = main.toString("utf8");
    for (const { re, label } of JS_BLACKLIST) {
      if (!re.test(text)) continue;
      if (label === "localStorage" && LOCALSTORAGE_EXEMPT_PLUGIN_IDS.has(id)) {
        // 整体豁免而非逐 key 静态解析：压缩后的 bundle 里字符串常被拼接/
        // 模板化（如 remote-storage.ts 的 `prefix + key`），正则无法可靠
        // 还原运行时真实访问的 key，伪装成精确检测反而是假的安全感。
        // 豁免登记于 LOCALSTORAGE_EXEMPT_PLUGIN_IDS，只有仓库维护者改脚本
        // 才能新增——插件作者无法自行在 manifest/代码里声明绕过。
        warnings.push(`${id}: main.js 使用 localStorage（已登记豁免——读写宿主 UI 状态公开约定键 ${ALLOWED_LOCALSTORAGE_KEY_PREFIXES.join("/")}*，无替代官方 API，人工审核过，见 scripts/validate.mjs 注释）`);
        continue;
      }
      errors.push(`${id}: main.js 命中黑名单 "${label}"（规范 §9.1 门禁）`);
    }
  }
  const css = downloaded["styles.css"];
  if (css) {
    const text = css.toString("utf8");
    for (const { re, label } of CSS_BLACKLIST) {
      if (re.test(text)) errors.push(`${id}: styles.css 命中禁止项 "${label}"`);
    }
  }

  // Release manifest 与登记条目一致性
  let manifest = null;
  try {
    manifest = JSON.parse(downloaded["manifest.json"].toString("utf8"));
  } catch (err) {
    errors.push(`${id}: Release manifest.json 解析失败：${err.message}`);
    return;
  }
  if (manifest.id !== id) errors.push(`${id}: Release manifest.id "${manifest.id}" ≠ 索引 id`);
  if (manifest.version !== version) {
    errors.push(`${id}: Release manifest.version "${manifest.version}" ≠ 索引 version "${version}"（tag/manifest/索引三者必须一致）`);
  }
  if (manifest.tier !== tier) errors.push(`${id}: Release manifest.tier "${manifest.tier}" ≠ 索引 tier "${tier}"`);
  if (manifest.repo !== undefined && manifest.repo !== repo) {
    errors.push(`${id}: Release manifest.repo "${manifest.repo}" ≠ 索引 repo "${repo}"`);
  }
  if (manifest.repo === undefined) warnings.push(`${id}: Release manifest 缺 repo 字段（规范 §5 要求）`);
  const mp = [...(manifest.permissions ?? [])].sort();
  const ep = [...(entry.permissions ?? [])].sort();
  if (JSON.stringify(mp) !== JSON.stringify(ep)) {
    errors.push(`${id}: 权限清单不一致——manifest [${mp.join(", ")}] ≠ 索引 [${ep.join(", ")}]`);
  }
  if (manifest.minAppVersion !== undefined && manifest.minAppVersion !== entry.minAppVersion) {
    errors.push(`${id}: manifest.minAppVersion "${manifest.minAppVersion}" 与索引 "${entry.minAppVersion}" 不一致`);
  }
  if (typeof manifest.name === "string" && [...manifest.name].length > 30) {
    errors.push(`${id}: manifest.name 超过 30 字符（规范 §5）`);
  }
  if (typeof manifest.description === "string" && [...manifest.description].length > 120) {
    errors.push(`${id}: manifest.description 超过 120 字符（规范 §5）`);
  }
  if (Array.isArray(manifest.keywords) && manifest.keywords.length > 8) {
    errors.push(`${id}: manifest.keywords 超过 8 个（规范 §5）`);
  }
  // 展示素材：索引里的值可能是索引侧单独维护的（只改素材不改版本的 PR），
  // 所以不要求与 Release manifest 相等；但 manifest 里写了就必须合法，
  // 否则下一次版本登记会把坏路径镜像进索引。
  for (const field of ["icon", "screenshots"]) {
    if (manifest[field] === undefined) continue;
    const problem = mediaFieldProblem(field, manifest[field]);
    if (problem) errors.push(`${id}: manifest.${problem}（规范 §5.1）`);
  }

  // 权限-代码比对（启发式，漏声明 = 错误；多声明 = 警告请审核员裁量）
  if (main && Array.isArray(manifest.permissions)) {
    const verdict = comparePermissionsWithCode(id, manifest.permissions, main.toString("utf8"));
    errors.push(...verdict.errors);
    warnings.push(...verdict.warnings);
  }

  // README / LICENSE（规范 §4 必须）
  const [hasReadme, hasLicense] = await Promise.all([
    fetchRaw(repo, tag, "README.md"),
    fetchRaw(repo, tag, "LICENSE"),
  ]);
  for (const [file, state, why] of [
    ["README.md", hasReadme, "市场详情页直接渲染它"],
    ["LICENSE", hasLicense, "规范 §4 必须"],
  ]) {
    if (state === false) errors.push(`${id}: 仓库根缺 ${file}（${why}）`);
    // 不可达也判错（校验门禁必须 fail closed），但措辞要让审核员一眼看出
    // 是连不上而非文件缺失，重跑即可，不要去给插件作者提"补文件"的 issue。
    else if (state === UNREACHABLE) {
      errors.push(`${id}: 无法确认仓库根 ${file} 是否存在——raw.githubusercontent 连接失败（非作者问题，重跑本校验）`);
    }
  }
  report.readme = hasReadme;
  report.license = hasLicense;
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------
async function main() {
  const argv = process.argv.slice(2);
  const opt = { all: false, base: null, report: null, result: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--all") opt.all = true;
    else if (argv[i] === "--base") opt.base = argv[++i];
    else if (argv[i] === "--report") opt.report = argv[++i];
    else if (argv[i] === "--result") opt.result = argv[++i];
    else { console.error(`未知参数：${argv[i]}`); process.exit(2); }
  }
  if (!opt.all && !opt.base) {
    console.error("用法：validate.mjs --all | --base <git-ref> [--report p] [--result p]");
    process.exit(2);
  }

  const errors = [];
  const warnings = [];
  const reportSections = [];
  const resultEntries = [];
  const permissionsAdded = [];
  const mediaOnlyEntries = [];

  // 1. 全局结构
  const community = loadJson(COMMUNITY_FILE, errors);
  const communityIds = community ? validateCommunityList(community, errors, warnings) ?? new Set() : new Set();
  const pluginFiles = existsSync(path.join(ROOT, PLUGINS_DIR))
    ? readdirSync(path.join(ROOT, PLUGINS_DIR)).filter((f) => f.endsWith(".json"))
    : [];
  const pluginIds = new Set(pluginFiles.map((f) => f.replace(/\.json$/, "")));
  for (const id of communityIds) {
    if (!pluginIds.has(id)) errors.push(`${COMMUNITY_FILE} 列出了 "${id}" 但缺 ${PLUGINS_DIR}/${id}.json`);
  }
  for (const id of pluginIds) {
    if (!communityIds.has(id)) errors.push(`${PLUGINS_DIR}/${id}.json 存在但未登记进 ${COMMUNITY_FILE}`);
  }

  // featured.json：编辑精选指向的必须是已登记的 id（缺文件 = 没有精选区）
  const featured = existsSync(path.join(ROOT, FEATURED_FILE))
    ? loadJson(FEATURED_FILE, errors)
    : null;
  validateFeatured(featured, communityIds, errors, warnings);

  // 2. 决定远端核查范围
  let changedFiles = null;
  if (opt.base) {
    changedFiles = gitChangedFiles(opt.base);
    if (changedFiles === null) {
      errors.push(`git diff ${opt.base}...HEAD 失败（CI 需 fetch-depth: 0）`);
    }
  }
  const idsToCheck = opt.all
    ? [...pluginIds].sort()
    : [...new Set((changedFiles ?? [])
        .filter((f) => /^plugins\/[^/]+\.json$/.test(f))
        .map((f) => f.replace(/^plugins\//, "").replace(/\.json$/, "")))].sort();

  // 3. 逐条目核查
  for (const id of idsToCheck) {
    const file = `${id}.json`;
    const entry = loadJson(`${PLUGINS_DIR}/${file}`, errors);
    if (!entry) continue;
    validateEntry(entry, file, errors, warnings);
    if (!entry.repo || !entry.version || !entry.tier) continue; // schema 已挂，远端无意义

    const report = { id, version: entry.version, tier: entry.tier, artifacts: [], readme: null, license: null, addedPerms: [] };

    // PR 模式：单调版本 + 权限 diff
    if (opt.base) {
      const baseText = gitShow(opt.base, `${PLUGINS_DIR}/${file}`);
      if (baseText) {
        let baseEntry = null;
        try { baseEntry = JSON.parse(baseText); } catch { /* 旧文件坏也由新校验兜底 */ }
        if (baseEntry) {
          const cmp = compareSemver(entry.version, baseEntry.version);
          const delistOnly = entry.delisted !== baseEntry.delisted && cmp === 0;
          // 同版本上只动 icon/screenshots（索引侧单独登记素材，见
          // SPEC-CHANGELOG v0.2）：允许，但排除在自动合并之外——素材是用户
          // 可见内容，不在「产物 SHA256 已核对」的自动信任范围内。
          const mediaOnly =
            cmp === 0 &&
            canonicalEntryWithoutMedia(entry) === canonicalEntryWithoutMedia(baseEntry);
          if (mediaOnly) mediaOnlyEntries.push(id);
          if (cmp !== null && cmp <= 0 && !delistOnly && !mediaOnly) {
            errors.push(`${id}: version "${entry.version}" 未严格大于已登记版本 "${baseEntry.version}"（规范 §5 单调规则）`);
          }
          if (baseEntry.delisted === true && cmp !== null && cmp > 0) {
            errors.push(`${id}: 已下架（delisted）插件不接受版本登记，请先由维护者恢复`);
          }
          const basePerms = new Set(baseEntry.permissions ?? []);
          for (const p of entry.permissions ?? []) {
            if (!basePerms.has(p)) report.addedPerms.push(p);
          }
        }
      }
    }
    if (report.addedPerms.length) {
      warnings.push(`${id}: 新增权限 ${report.addedPerms.map((p) => `+${p}`).join(" ")} —— 需人工审核，禁止自动合并`);
      permissionsAdded.push(`${id}: ${report.addedPerms.join(", ")}`);
    }

    // 远端核查
    await checkRelease(entry, errors, warnings, report);
    resultEntries.push({ id, repo: entry.repo, version: entry.version });

    // 审核报告段落
    const netPerms = (entry.permissions ?? []).filter((p) => p.startsWith("network:"));
    const execPerms = (entry.permissions ?? []).filter((p) => p.startsWith("exec:"));
    reportSections.push([
      `### \`${id}\` v${entry.version}（${entry.tier}）`,
      ``,
      `- 仓库：[${entry.repo}](https://github.com/${entry.repo}) · Release tag \`${entry.version}\``,
      `- 产物：${report.artifacts.join(" · ") || "（下载失败）"}`,
      `- 权限（${(entry.permissions ?? []).length}）：${(entry.permissions ?? []).join(", ") || "无"}`,
      netPerms.length ? `- 网络域名：${netPerms.map((p) => p.slice(8)).join(", ")}` : null,
      execPerms.length ? `- ⚠️ 进程执行：${execPerms.map((p) => p.slice(5)).join(", ")}（任意代码执行能力，重点审核）` : null,
      report.readme === null
        ? null
        : `- README：${presenceMark(report.readme)} · LICENSE：${presenceMark(report.license)}`,
      entry.icon || (entry.screenshots ?? []).length
        ? `- 展示素材：${entry.icon ? "icon ✅" : "icon —"} · 效果图 ${(entry.screenshots ?? []).length} 张`
        : null,
      report.addedPerms.length ? `- ⚠️ 相对上一版本新增权限：${report.addedPerms.map((p) => `\`${p}\``).join(" ")}` : null,
      ``,
    ].filter((l) => l !== null).join("\n"));
  }

  // 4. 输出
  const summary = [
    `## 插件索引审核报告`,
    ``,
    `- 模式：${opt.all ? "全量" : `PR（base ${opt.base}）`} · 远端核查 ${idsToCheck.length} 个条目`,
    `- 结果：${errors.length ? `❌ ${errors.length} 个错误` : "✅ 通过"}${warnings.length ? ` · ⚠️ ${warnings.length} 个警告` : ""}`,
    ``,
  ];
  if (errors.length) summary.push(`### ❌ 错误`, ...errors.map((e) => `- ${e}`), ``);
  if (warnings.length) summary.push(`### ⚠️ 警告`, ...warnings.map((w) => `- ${w}`), ``);
  let md = [...summary, ...reportSections].join("\n");
  if (md.length > REPORT_MAX_CHARS) md = `${md.slice(0, REPORT_MAX_CHARS)}\n\n…（报告过长已截断）`;

  const versionRegistrationOnly =
    changedFiles !== null &&
    changedFiles.length === 1 &&
    /^plugins\/[^/]+\.json$/.test(changedFiles[0]) &&
    mediaOnlyEntries.length === 0;
  const result = {
    ok: errors.length === 0,
    errors: errors.length,
    warnings: warnings.length,
    changedFiles,
    versionRegistrationOnly,
    permissionsAdded,
    entries: resultEntries,
  };

  if (opt.report) writeFileSync(opt.report, md);
  if (opt.result) writeFileSync(opt.result, JSON.stringify(result, null, 2));
  console.log(md);
  process.exit(errors.length ? 1 : 0);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((err) => {
    console.error(`校验器自身异常：${err.stack ?? err}`);
    process.exit(2);
  });
}
