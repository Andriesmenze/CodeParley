// The custodian's terminal-safety rule for text it renders (Ledger/FixRendering.cs MustEscape and Escape), in one place
// for the simulated custodian's rendering (simulated-render.ts) and the operator's `fix review`, which refuses to show a
// rendering or a listed path that breaks it (Step 7.1).
//
// Every control character but a tab, DEL, the C1 controls, and the zero-width, bidirectional and other invisible
// formatting characters are shown as <U+XXXX>; a lone surrogate is U+FFFD (as .NET's rune enumeration gives it).

/** Is this code point shown escaped (FixRendering.MustEscape)? */
export function mustEscape(cp: number): boolean {
  return (cp < 0x20 && cp !== 0x09) || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e)
    || (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff || (cp >= 0xfff9 && cp <= 0xfffb);
}

/** The text as the operator's terminal must show it (FixRendering.Escape). */
export function escapeText(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xd800 && cp <= 0xdfff) out += "�";
    else if (mustEscape(cp)) out += `<U+${cp.toString(16).toUpperCase().padStart(4, "0")}>`;
    else out += ch;
  }
  return out;
}

/** The first code point in `line` the rule would escape (a lone surrogate included), or null: a custodian rendering or
 * listed text is shown only when every line passes. */
export function unescapedIn(line: string): number | null {
  for (const ch of line) {
    const cp = ch.codePointAt(0)!;
    if ((cp >= 0xd800 && cp <= 0xdfff) || mustEscape(cp)) return cp;
  }
  return null;
}
