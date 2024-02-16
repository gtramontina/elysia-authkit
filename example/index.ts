import { WorkOS } from "@workos-inc/node";
import { Elysia } from "elysia";
import { authKit } from "../";

process.env.WORKOS_CLIENT_ID = "client_…";
process.env.WORKOS_API_KEY = "sk_test_…";
process.env.JWT_SECRET_KEY = "a very secret jwt secret key";

new Elysia()
	.use(
		authKit({
			workos: new WorkOS(process.env.WORKOS_API_KEY),
			clientId: process.env.WORKOS_CLIENT_ID,
			jwtSecret: process.env.JWT_SECRET_KEY,
			redirectUri: "http://localhost:8080/callback",
		}),
	)
	.onError(({ code, error, set }) => {
		if (code === "Unauthorized") {
			set.redirect = "/login";
		}
	})
	.get("/", ({ user }) => {
		return `Hello, ${user.email}!`;
	})
	.listen(8080, () => {
		console.info("Listening on http://localhost:8080");
	});
