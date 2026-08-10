export type ApiErrorDetails = Record<string, unknown>;

export class ApiError extends Error {
		readonly statusCode: number;
		readonly details?: ApiErrorDetails;

		constructor(statusCode: number, message: string, details?: ApiErrorDetails) {
				super(message);
				this.name = "ApiError";
				this.statusCode = statusCode;
				this.details = details;
		}

		static unauthorized(details?: ApiErrorDetails): ApiError {
				return new ApiError(401, "Unauthorized", details);
		}

		static forbidden(details?: ApiErrorDetails): ApiError {
				return new ApiError(403, "Forbidden", details);
		}

		static notFound(details?: ApiErrorDetails): ApiError {
				return new ApiError(404, "Not Found", details);
		}

		static timeout(details?: ApiErrorDetails): ApiError {
				return new ApiError(408, "Request Timeout", details);
		}

		static internal(details?: ApiErrorDetails): ApiError {
				return new ApiError(500, "Internal Server Error", details);
		}

		static unavailable(details?: ApiErrorDetails): ApiError {
				return new ApiError(503, "Service Unavailable", details);
		}
}