import type { RegistrationRepository } from "./RegistrationRepository.js";
import type { CompleteRegistrationInput, RegistrationOutcome } from "./RegistrationTypes.js";

// Thin orchestration: the atomic unit of work itself lives in RegistrationRepository (Task 9).
// This class exists so routes/composition never depend on Postgres/InMemory specifics directly.
export class RegistrationService {
		constructor(private readonly repository: RegistrationRepository) {}

		complete(input: CompleteRegistrationInput): Promise<RegistrationOutcome> {
				return this.repository.complete(input);
		}
}
