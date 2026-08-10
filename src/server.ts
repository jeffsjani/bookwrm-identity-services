import Fastify from "fastify";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";

import { registerHealthRoutes } from "./routes/health.js";

const app = Fastify({
		logger: {
				level: process.env.LOG_LEVEL || "info"
		}
});

// Security
await app.register(helmet);

// CORS
await app.register(cors, {
		origin: true,
		credentials: true
});

// Routes
await registerHealthRoutes(app);

app.get("/", async () => {
		return {
				service: "Bookwrm Identity Services",
				version: "6A.1",
				status: "healthy",
				environment: process.env.NODE_ENV || "development"
		};
});

const port = Number(process.env.PORT || 3000);

try {

		await app.listen({
				host: "0.0.0.0",
				port
		});

		app.log.info(`Bookwrm Identity Services running on ${port}`);

} catch (err) {

		app.log.error(err);

		process.exit(1);

}
