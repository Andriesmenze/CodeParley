// The engine's hard per-run caps, applied by the starts and — P3.4C-3 C4 — by every report and the routing, so a
// report never offers an operation a start would refuse.

/** Reviews per run, whatever the configuration (plan §13.5). */
export const HARD_MAX_REVIEWS_PER_RUN = 20;
/** Check executions per run, whatever the configuration (plan §15.3). */
export const HARD_MAX_EXECUTIONS_PER_RUN = 100;
