import { FastifyInstance } from "fastify";

import { Base44IdentityAdapter }
from "../adapters/Base44IdentityAdapter.js";

const adapter = new Base44IdentityAdapter();

export async function registerDiagnosticsRoutes(
		app: FastifyInstance
){

		app.get(

				"/diagnostics/base44",

				async ()=>{

						const result =
								await adapter.health();

						return result;

				}

		);

}