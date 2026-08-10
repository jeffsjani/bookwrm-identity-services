export interface IdentityPolicy {
		id: string;
		name: string;
		enabled: boolean;
		requiredConfidence: number;
		maximumRisk: number;
}
