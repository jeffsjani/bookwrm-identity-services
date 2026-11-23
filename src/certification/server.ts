import { createPrivateOIDCCertificationApp } from "./PrivateOIDCCertificationClient.js";

const port = Number(process.env.PORT ?? "3000");
const app = await createPrivateOIDCCertificationApp({ env: process.env });
await app.listen({ port, host: "0.0.0.0" });
