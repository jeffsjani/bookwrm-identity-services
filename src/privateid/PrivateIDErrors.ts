export class PrivateIDError extends Error {
		constructor(message: string, options?: ErrorOptions) {
				super(message, options);
				this.name = "PrivateIDError";
		}
}

export class PrivateIDTimeoutError extends PrivateIDError {
		constructor(message = "PrivateID polling timed out") {
				super(message);
				this.name = "PrivateIDTimeoutError";
		}
}

export class PrivateIDCancelledError extends PrivateIDError {
		constructor(message = "PrivateID authentication was cancelled") {
				super(message);
				this.name = "PrivateIDCancelledError";
		}
}
