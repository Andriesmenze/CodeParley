// Where same-session continuation keeps its store-wide records (Phase 3.3a): the session index. Light
// on purpose: the hook adapter checks the session index with this module alone, before it loads the
// engine, in every session of the user. (The operator's loop grants are held by the Windows custodian
// since P3.4C-0; a grants.json left here by an earlier version is never read.)

import { join } from "node:path";
import { sha256OfString } from "../common/hash.js";

export function continuationDir(dataHome: string): string {
  return join(dataHome, "continuation");
}

export function sessionsDir(dataHome: string): string {
  return join(continuationDir(dataHome), "sessions");
}

/** A session's index key: a hash, so a host-supplied id never names a path. */
export function sessionKey(sessionId: string): string {
  return sha256OfString(`codeparley.session.v1:${sessionId}`).slice(0, 32);
}

export function sessionIndexPath(dataHome: string, sessionId: string): string {
  return join(sessionsDir(dataHome), `${sessionKey(sessionId)}.json`);
}
