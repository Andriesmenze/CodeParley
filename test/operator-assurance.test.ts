// Phase 5 (contract §4.5): the Linux custodian labels operator records `local_operator_account` (a separate operator
// account, SO_PEERCRED), not the Windows `local_admin_elevation`. The engine recognizes either custodian label as user
// authority ONLY on a record the custodian served to this process; the same label in the user-writable store is not.

import { describe, it, expect } from "vitest";
import { isUserChannelRecord } from "../src/policy/amendments.js";
import { CUSTODIAN_SERVED, USER_ASSURANCES, hostOperatorAssurance } from "../src/schemas/user-authority.js";

const rec = (assurance: string, channel = "custodian_operator") => ({ recorded_by: { role: "user", channel, assurance } });
const served = <T extends object>(r: T): T => Object.assign(r, { [CUSTODIAN_SERVED]: true });

describe("Phase 5: the Linux operator assurance", () => {
  it("is a defined custodian pair, recognized only when the custodian served the record", () => {
    expect(USER_ASSURANCES["local_operator_account"]?.channel).toBe("custodian_operator");
    expect(isUserChannelRecord(served(rec("local_operator_account")))).toBe(true);
    expect(isUserChannelRecord(rec("local_operator_account"))).toBe(false);
    expect(isUserChannelRecord(served(rec("local_admin_elevation")))).toBe(true);
    expect(isUserChannelRecord(rec("local_admin_elevation"))).toBe(false);
  });

  it("never pairs with another channel, and an unknown label is never authority", () => {
    expect(isUserChannelRecord(served(rec("local_operator_account", "local_cli")))).toBe(false);
    expect(isUserChannelRecord(served(rec("local_operator_acount")))).toBe(false);
    expect(isUserChannelRecord(rec("local_operator", "local_cli"))).toBe(true);
  });

  it("the CLI names this host's label", () => {
    expect(hostOperatorAssurance()).toBe(process.platform === "linux" ? "local_operator_account" : "local_admin_elevation");
  });
});
