// The ONLY module that imports the MCP SDK (plan §5.3 rule 4, D-01: TypeScript SDK v2).
//
// It serves stdio in both protocol eras (2025-11-25 via `initialize`, 2026-07-28 via
// `server/discover`; `serveStdio` pins one era per connection) with low-level `tools/list`
// and `tools/call` handlers, so the MCP layer validates arguments itself and every result —
// errors included — carries `structuredContent` (plan §11.1). Client roots are advisory:
//  - 2025 era: fetched with `roots/list` after initialization and on list_changed;
//  - 2026 era (no server→client requests): requested inside a tool call as a multi-round-
//    trip `input_required` result, only when a tool needs them, and only when the request's
//    declared client capabilities include roots.
// stdout carries only MCP messages; nothing here writes to it directly.

import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, McpServer, PROTOCOL_VERSION_META_KEY, inputRequired, inputResponse, type CallToolResult } from "@modelcontextprotocol/server";
import { serveStdio as sdkServeStdio, type StdioServerHandle } from "@modelcontextprotocol/server/stdio";

export interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean };
}

export interface CallContext {
  /** The CALL's cancellation (notifications/cancelled or transport loss): ends waits only. */
  signal: AbortSignal;
  /** Progress notification (no-op when the client sent no progress token). */
  progress(message: string, progress: number): void;
  protocolVersion: string | null;
  era: "legacy" | "modern";
  clientInfo: { name: string; version: string } | null;
  /** The client declared the roots capability (for this request on the 2026 era). */
  clientSupportsRoots: boolean;
  /** Roots returned by the client for a multi-round-trip request in this call (2026 era); null if none. */
  rootsResponse: string[] | null;
  /** 2025 era: ask the client for its roots now (`roots/list`); null when unsupported or failed. */
  listRootsNow(): Promise<string[] | null>;
}

export type ToolOutcome = { kind: "result"; structuredContent: Record<string, unknown>; isError: boolean } | { kind: "need_roots" };

export interface SessionHooks {
  tools(): ToolDefinition[];
  call(name: string, args: unknown, ctx: CallContext): Promise<ToolOutcome>;
  /** Legacy-era roots (raw local paths), whenever they are (re)fetched; null when unavailable. */
  rootsChanged(roots: string[] | null): void;
  closed(): void;
}

export interface ServeOptions {
  name: string;
  version: string;
  instructions: string;
  /** Called once per connection with the pinned era's session. */
  session(): SessionHooks;
  onError(e: Error): void;
}

const MODERN = "2026-07-28";
const ROOTS_KEY = "roots";

/**
 * `file:` URI → local path (advisory only; invalid URIs are dropped). Windows: drive and UNC
 * paths with backslashes. Linux: the decoded absolute path; a URI naming another host is not a
 * local root and is dropped (plan §1.13).
 */
export function fileUriToPath(uri: string, platform: NodeJS.Platform = process.platform): string | null {
  try {
    const u = new URL(uri);
    if (u.protocol !== "file:") return null;
    const p = decodeURIComponent(u.pathname);
    if (platform !== "win32") {
      if (u.host && u.host !== "localhost") return null;
      return p.startsWith("/") && !p.includes("\0") ? p : null;
    }
    if (u.host) return `\\\\${u.host}${p.replace(/\//g, "\\")}`;
    return p.replace(/^\/([A-Za-z]:)/, "$1").replace(/\//g, "\\");
  } catch {
    return null;
  }
}

function rootsFrom(list: { uri: string }[] | undefined): string[] {
  return (list ?? []).map((r) => fileUriToPath(r.uri)).filter((p): p is string => p !== null);
}

export function serveStdio(o: ServeOptions): StdioServerHandle {
  return sdkServeStdio(
    () => {
      const hooks = o.session();
      const mcp = new McpServer({ name: o.name, version: o.version }, { capabilities: { tools: { listChanged: false } }, instructions: o.instructions });
      const server = mcp.server;
      const outputSchemas = new Map<string, Record<string, unknown>>();

      const listRootsNow = async (): Promise<string[] | null> => {
        try {
          if (!server.getClientCapabilities()?.roots) return null;
          return rootsFrom((await server.listRoots(undefined, { timeout: 10_000 })).roots);
        } catch {
          return null;
        }
      };
      const fetchRoots = async () => {
        hooks.rootsChanged(await listRootsNow());
      };
      server.oninitialized = () => {
        void fetchRoots();
      };
      server.setNotificationHandler("notifications/roots/list_changed", () => {
        void fetchRoots();
      });
      server.onclose = () => hooks.closed();

      server.setRequestHandler("tools/list", () => ({
        tools: hooks.tools().map((t) => {
          outputSchemas.set(t.name, t.outputSchema);
          return { name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema as never, outputSchema: t.outputSchema as never, annotations: t.annotations };
        }),
      }));

      server.setRequestHandler("tools/call", async (request, ctx) => {
        const name = request.params.name;
        // 2026 era: identity and capabilities ride every request's `_meta` envelope; 2025 era:
        // they were declared once at `initialize`.
        const envelope = (ctx.mcpReq.envelope ?? {}) as Record<string, unknown>;
        const envVersion = typeof envelope[PROTOCOL_VERSION_META_KEY] === "string" ? (envelope[PROTOCOL_VERSION_META_KEY] as string) : null;
        const protocolVersion = envVersion ?? server.getNegotiatedProtocolVersion() ?? null;
        const era: "legacy" | "modern" = protocolVersion !== null && protocolVersion >= MODERN ? "modern" : "legacy";
        const caps = (era === "modern" ? envelope[CLIENT_CAPABILITIES_META_KEY] : server.getClientCapabilities()) as { roots?: unknown } | undefined;
        const info = (era === "modern" ? envelope[CLIENT_INFO_META_KEY] : server.getClientVersion()) as { name?: unknown; version?: unknown } | undefined;
        const progressToken = (request.params as { _meta?: { progressToken?: string | number } })._meta?.progressToken ?? ctx.mcpReq._meta?.progressToken;
        const view = inputResponse(ctx.mcpReq.inputResponses, ROOTS_KEY);
        const callCtx: CallContext = {
          signal: ctx.mcpReq.signal,
          progress: (message, progress) => {
            if (progressToken === undefined) return;
            void ctx.mcpReq.notify({ method: "notifications/progress", params: { progressToken, progress, message } }).catch(() => undefined);
          },
          protocolVersion,
          era,
          clientInfo: info && typeof info.name === "string" ? { name: info.name, version: typeof info.version === "string" ? info.version : "" } : null,
          clientSupportsRoots: !!caps?.roots,
          rootsResponse: view.kind === "roots" ? rootsFrom(view.roots) : null,
          listRootsNow: era === "legacy" ? listRootsNow : async () => null,
        };
        const out = await hooks.call(name, request.params.arguments ?? {}, callCtx);
        if (out.kind === "need_roots") return inputRequired({ inputRequests: { [ROOTS_KEY]: inputRequired.listRoots() } }) as never;
        const result: CallToolResult = {
          content: [{ type: "text", text: JSON.stringify(out.structuredContent) }],
          structuredContent: out.structuredContent,
          ...(out.isError ? { isError: true } : {}),
        };
        return server.projectCallToolResult(result, outputSchemas.get(name) ?? hooks.tools().find((t) => t.name === name)?.outputSchema);
      });
      return mcp;
    },
    { onerror: (e) => o.onError(e) },
  );
}
