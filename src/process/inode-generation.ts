// The inode generation of a directory on Linux (Phase 5, contract §4.6 F5-13): the simulated custodian's identity adds
// it to (dev, ino), so an immediately recreated directory that reuses the inode number is another identity, as the real
// custodian's file handle already makes it. `lsattr -vd` (e2fsprogs, FS_IOC_GETVERSION) prints it in decimal before the
// flags. Null where it cannot be read (not Linux, no lsattr, a filesystem without the ioctl such as tmpfs): the
// simulator then identifies by (dev, ino, birth time) alone. The real custodian refuses such filesystems (fail closed).

import { execFileSync } from "node:child_process";

const LSATTR = "/usr/bin/lsattr";

export function inodeGenerationSync(dir: string): bigint | null {
  if (process.platform !== "linux") return null;
  let out: string;
  try {
    out = execFileSync(LSATTR, ["-vd", "--", dir], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
  } catch {
    return null;
  }
  const m = /^\s*(\d+)\s/.exec(out);
  return m ? BigInt(m[1]!) : null;
}
