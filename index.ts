import { jwt } from "@elysiajs/jwt";
import type { AuthenticationResponse } from "@workos-inc/node";
import { Elysia } from "elysia";
import type { AuthenticatedUser, Options, SerializedUser } from "./types";

export const authKit = <User = AuthenticatedUser>({
	workos,
	prefix,
	clientId,
	jwtSecret,
	jwtExp = "1d",
	redirectUri,
	paths: { login = "/login", logout = "/logout", callback = "/callback" } = {},
	serializeUser = defaultSerializeUser,
	deserializeUser = (user: SerializedUser): Promise<User> => {
		return Promise.resolve(user as User);
	},
}: Options<User>) => {
	return (
		new Elysia({
			name: "@gtramontina.com/elysia-authkit",
			prefix,
			seed: {
				prefix,
				clientId,
				jwtSecret,
				jwtExp,
				redirectUri,
				paths: { login, logout, callback },
			},
		})
			.use(jwt({ name: "jwt", secret: jwtSecret, exp: jwtExp }))

			// Login Route
			.get(login, ({ set }) => {
				set.redirect = workos.userManagement.getAuthorizationUrl({
					provider: "authkit",
					redirectUri: redirectUri,
					clientId,
				});
			})

			// Logout Route
			.get(logout, ({ cookie, set }) => {
				cookie.authToken.set({
					value: "",
					path: "/",
					secure: true,
					httpOnly: true,
					expires: new Date(0),
				});
				set.redirect = "/";
			})

			// Callback Route
			.get(callback, async ({ query, jwt, cookie, set }) => {
				const code = query.code ?? "";
				const response = await workos.userManagement.authenticateWithCode({
					code,
					clientId,
				});

				cookie.authToken.set({
					value: await jwt.sign(await serializeUser(response)),
					path: "/",
					secure: true,
					httpOnly: true,
				});

				set.redirect = cookie.authDestination.value ?? "/";
			})
			.error({ Unauthorized })

			// Derive Authenticated User
			.derive(async ({ request, jwt, cookie }) => {
				const token = await jwt.verify(cookie.authToken.value);

				if (token === false) {
					cookie.authDestination.set({
						value: request.url,
						path: "/",
						secure: true,
						httpOnly: true,
					});

					throw new Unauthorized();
				}

				return { user: await deserializeUser(token) };
			})
	);
};

class Unauthorized extends Error {
	readonly status = 401;
	readonly message = "You are not authorized to access this resource.";
}

const defaultSerializeUser = (
	response: AuthenticationResponse,
): Promise<SerializedUser> => {
	const {
		user: { id, email, firstName, lastName },
		organizationId,
	} = response;

	const record: SerializedUser = { id, email };

	if (firstName) {
		record.firstName = firstName;
	}
	if (lastName) {
		record.lastName = lastName;
	}
	if (organizationId) {
		record.organizationId = organizationId;
	}

	return Promise.resolve(record);
};
