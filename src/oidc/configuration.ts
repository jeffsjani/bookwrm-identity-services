export const oidcConfiguration = {
		clients: [],
		features: {
				devInteractions: {
						enabled: false
				},
				revocation: {
						enabled: true
				},
				introspection: {
						enabled: true
				}
			}
} as const;
