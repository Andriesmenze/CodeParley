// Test seam (Phase 4): what a simulated process death throws. A delegated fix or an application that catches it runs
// none of its own cleanup — no rollback, no finish, no teardown, the lock left held — which is what a killed process
// leaves behind for recovery to deal with.

export class SimulatedKill extends Error {
  constructor() {
    super("simulated process death");
  }
}
