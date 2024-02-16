# Elysia AuthKit

Elysia plugin to integrate with [AuthKit](https://www.authkit.com/).

> [!NOTE]  
> This package is not affiliated with AuthKit or WorkOS.
> It currently only implements the flow described in the [AuthKit Getting Started guide](https://workos.com/docs/user-management) (hosted sign up and sign in forms).
> 


## Installation

```sh
bun add --exact @gtramontina.com/elysia-authkit
```

## Usage

Follow the initial steps of the AuthKit [documentation](https://workos.com/docs/user-management) to get an account and keys setup.

```typescript
import { authKit } from "@gtramontina.com/elysia-authkit";
import { WorkOS } from "@workos-inc/node";
import { Elysia } from "elysia";

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
		if (code === "UnauthorizedError") {
			set.redirect = "/login";
		}
	})
	.get("/", ({ user }) => {
		return `Hello, ${user.firstName ?? "world"}!`;
	})
	.listen(8080, () => {
		console.info("Listening on http://localhost:8080");
	});
```

Please feel free to explore the [example](./example) for a more complete usage and the [Options](./types.d.ts) type for more details and options on how to customize the plugin for your needs.
