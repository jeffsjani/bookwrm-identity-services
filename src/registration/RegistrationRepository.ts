import type { CompleteRegistrationInput, RegistrationOutcome } from "./RegistrationTypes.js";

// Storage/transaction contract for H3 registration completion. A single implementation method
// spans the full atomic unit of work (Task 9): verification lock/read, identity resolution/create,
// claim establishment, verification consumption, and registration audit. There must never be a
// committed state where the challenge is CONSUMED but identity creation failed, or vice versa.
export interface RegistrationRepository {
		complete(input: CompleteRegistrationInput): Promise<RegistrationOutcome>;
}
