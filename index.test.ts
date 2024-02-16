import { describe, expect, it } from "bun:test";
import { Elysia } from "elysia";
import { jwtVerify } from "jose";
import { authKit } from "./index";
import { FakeWorkOS, fakeConstants } from "./workos.fake";

describe("AuthKit Elysia Plugin", () => {
	const workos = new FakeWorkOS();
	const app = new Elysia()
		.mount("/", workos.fakeServer())
		.use(
			authKit({
				workos,
				clientId: fakeConstants.clientId,
				jwtSecret: "jwt-secret",
				redirectUri: "/callback",
			}),
		)
		.get("/", ({ user }) => `Welcome home, ${user.firstName}`)
		.get("/somewhere", ({ user }) => `Welcome somewhere, ${user.firstName}`);

	describe("when the user is not authenticated", () => {
		it("returns 401 when hitting a protected route", async () => {
			{
				const response = await app.handle(req("/"));
				expect(response.status).toBe(401);
				expect(response.json()).resolves.toEqual({
					name: "Error",
					message: "You are not authorized to access this resource.",
				});
			}
			{
				const response = await app.handle(req("/somewhere"));
				expect(response.status).toBe(401);
				expect(response.json()).resolves.toEqual({
					name: "Error",
					message: "You are not authorized to access this resource.",
				});
			}
		});

		it("sets the authDestination cookie so when the user logs in, they are redirected to the original destination", async () => {
			const response = await app.handle(req("/somewhere"));
			const jar = parseCookieJar(response);
			expect(response.status).toBe(401);
			expect(jar[0].authDestination).toEqual(
				encodeURIComponent("http://localhost/somewhere"),
			);
			expect(jar[0].Path).toBe("/");
			expect(jar[0].Secure).toBe(true);
			expect(jar[0].HttpOnly).toBe(true);
		});
	});

	it("redirects to authentication url when logging in", async () => {
		const response = await app.handle(req("/login"));
		expect(response.status).toBe(302);
		expect(response.headers.get("location")).toBe(
			"/__fake_authorization_url/?callback=/callback",
		);
	});

	describe("when authenticating with code on callback", () => {
		it("returns 400 when the code is invalid", async () => {
			{
				const response = await app.handle(req("/callback?"));
				expect(response.status).toBe(400);
				expect(response.json()).resolves.toStrictEqual({
					name: "Error",
					message:
						"WorkOS - Fake AuthKit: The code '' has expired or is invalid.",
				});
			}
			{
				const response = await app.handle(req("/callback?code=WRONG"));
				expect(response.status).toBe(400);
				expect(response.json()).resolves.toStrictEqual({
					name: "Error",
					message:
						"WorkOS - Fake AuthKit: The code 'WRONG' has expired or is invalid.",
				});
			}
		});

		it("redirects to / when successful", async () => {
			const response = await app.handle(
				req(`/callback?code=${fakeConstants.authCode}`),
			);
			expect(response.status).toBe(302);
			expect(response.headers.get("location")).toBe("/");
		});

		it("sets the authToken cookie when successful", async () => {
			const response = await app.handle(
				req(`/callback?code=${fakeConstants.authCode}`),
			);

			const jar = parseCookieJar(response);

			const token = await jwtVerify(
				jar[0].authToken as string,
				new TextEncoder().encode("jwt-secret"),
			);
			expect(token.payload).toMatchObject({
				id: fakeConstants.userId,
				email: fakeConstants.email,
				firstName: fakeConstants.firstName,
				lastName: fakeConstants.lastName,
				organizationId: fakeConstants.organizationId,
			});
			expect(jar[0].Path).toBe("/");
			expect(jar[0].Secure).toBe(true);
			expect(jar[0].HttpOnly).toBe(true);
		});

		it("redirects to where the user was trying to go when successful", async () => {
			const cookie = `authDestination=${encodeURIComponent("/admin")};`;
			const headers = { cookie };
			const response = await app.handle(
				req(`/callback?code=${fakeConstants.authCode}`, { headers }),
			);
			expect(response.status).toBe(302);
			expect(response.headers.get("location")).toBe("/admin");
		});
	});

	it("removes the authToken cookie when logging out", async () => {
		const response = await app.handle(req("/logout"));
		const jar = parseCookieJar(response);
		expect(response.status).toBe(302);
		expect(jar[0].authToken).toBe("");
		expect(jar[0].Path).toBe("/");
		expect(jar[0].Secure).toBe(true);
		expect(jar[0].HttpOnly).toBe(true);
		expect(jar[0].Expires).toBe("Thu, 01 Jan 1970 00:00:00 GMT");
	});

	it("returns 401 when the user is not authenticated", async () => {
		const response = await app.handle(req("/"));
		expect(response.status).toBe(401);
	});

	describe("flowing through the authentication process", () => {
		it("redirects to / when successful", async () => {
			const response = await handleRedirects(app, req("/login"));
			expect(response.status).toBe(200);
			expect(response.text()).resolves.toBe(
				`Welcome home, ${fakeConstants.firstName}`,
			);
		});

		it("redirects to where the user was trying to go when successful", async () => {
			const cookie = `authDestination=${encodeURIComponent(
				"http://localhost/somewhere",
			)};`;
			const headers = { cookie };
			const response = await handleRedirects(app, req("/login", { headers }));
			expect(response.status).toBe(200);
			expect(response.text()).resolves.toBe(
				`Welcome somewhere, ${fakeConstants.firstName}`,
			);
		});
	});

	describe("configuring the plugin", () => {
		it("allows for customizing the mounted login path", async () => {
			const response = await new Elysia()
				.mount("/", workos.fakeServer())
				.use(
					authKit({
						workos,
						clientId: "dummy",
						jwtSecret: "dummy",
						redirectUri: "/callback",
						paths: { login: "/sign-in" },
					}),
				)
				.handle(req("/sign-in"));
			expect(response.status).toBe(302);
			expect(response.headers.get("location")).toBe(
				"/__fake_authorization_url/?callback=/callback",
			);
		});

		it("allows for customizing the mounted logout path", async () => {
			const response = await new Elysia()
				.mount("/", workos.fakeServer())
				.use(
					authKit({
						workos,
						clientId: "dummy",
						jwtSecret: "dummy",
						redirectUri: "/callback",
						paths: { logout: "/sign-out" },
					}),
				)
				.handle(req("/sign-out"));
			const jar = parseCookieJar(response);
			expect(response.status).toBe(302);
			expect(jar[0].authToken).toBe("");
			expect(jar[0].Path).toBe("/");
			expect(jar[0].Expires).toBe("Thu, 01 Jan 1970 00:00:00 GMT");
		});

		it("allows for customizing the mounted callback path", async () => {
			const response = await new Elysia()
				.mount("/", workos.fakeServer())
				.use(
					authKit({
						workos,
						clientId: fakeConstants.clientId,
						jwtSecret: "dummy",
						redirectUri: "/kallbak",
						paths: { callback: "/kallbak" },
					}),
				)
				.handle(req(`/kallbak?code=${fakeConstants.authCode}`));
			expect(response.status).toBe(302);
			expect(response.headers.get("location")).toBe("/");
		});
	});

	describe("plugin metadata", () => {
		const plugin = authKit({
			workos,
			prefix: "/auth",
			clientId: fakeConstants.clientId,
			jwtSecret: "jwt-secret",
			jwtExp: "1d",
			redirectUri: "/callback",
			paths: {
				login: "/login",
				logout: "/logout",
				callback: "/callback",
			},
		});

		it("is configured", () => {
			expect(plugin.config.name).toBe("@gtramontina.com/elysia-authkit");
			expect(plugin.config.prefix).toBe("/auth");
			expect(plugin.config.seed).toStrictEqual({
				prefix: "/auth",
				clientId: fakeConstants.clientId,
				jwtSecret: "jwt-secret",
				jwtExp: "1d",
				redirectUri: "/callback",
				paths: {
					login: "/login",
					logout: "/logout",
					callback: "/callback",
				},
			});
		});
	});

	it("allows for customizing the way user information is serialized to and deserialized from the session", async () => {
		type ApplicationUser = { name: string };

		const app = new Elysia()
			.mount("/", workos.fakeServer())
			.use(
				authKit({
					workos,
					clientId: fakeConstants.clientId,
					jwtSecret: "jwt-secret",
					redirectUri: "/callback",
					serializeUser: (response): Promise<{ applicationId: string }> => {
						return Promise.resolve({ applicationId: "user-application-id" });
					},
					deserializeUser: (user): Promise<ApplicationUser> => {
						expect(user.applicationId).toBe("user-application-id");
						return Promise.resolve({ name: "Marty McFly" });
					},
				}),
			)
			.get("/", ({ user }) => `Welcome, ${user.name}`);

		const response = await handleRedirects(app, req("/login"));
		expect(response.status).toBe(200);
		expect(response.text()).resolves.toBe("Welcome, Marty McFly");
	});
});

// ---

const handleRedirects = async (
	app: { handle: (_: Request) => Promise<Response> },
	request: Request,
): Promise<Response> => {
	const response = await app.handle(request);
	if (response.status === 302) {
		const headers = new Headers();
		headers.set(
			"cookie",
			[response.headers.get("set-cookie"), request.headers.get("cookie")]
				.filter(Boolean)
				.join(", "),
		);
		return handleRedirects(
			app,
			req(response.headers.get("location") ?? "", { headers }),
		);
	}

	return response;
};

const req = (path: string, init: RequestInit = {}) =>
	new Request(new URL(path, "http://localhost").href, init);

const parseCookieJar = (response: Response) =>
	response.headers.getAll("set-cookie").map(parseCookie);

const parseCookie = (cookie: string) =>
	cookie.split(";").reduce(
		(acc, it) => {
			const [key, value] = it.split("=");
			acc[key.trim()] = value ?? true;
			return acc;
		},
		{} as Record<string, string | boolean>,
	);
