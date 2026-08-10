import Fastify from "fastify";

const app = Fastify({
		logger: true
});

app.get("/", async () => {
		return {
				service: "Bookwrm Identity Services",
				version: "1.0"
		};
});

const port = Number(process.env.PORT || 3000);

app.listen({
		port,
		host: "0.0.0.0"
});
