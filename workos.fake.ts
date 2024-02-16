import {
	type AuthenticateWithCodeOptions,
	type AuthenticationResponse,
	type AuthorizationURLOptions,
	WorkOS,
} from "@workos-inc/node";
import { UserManagement } from "@workos-inc/node/lib/user-management/user-management";
import { Elysia } from "elysia";

class FakeWorkOSError extends Error {
	readonly status: number;
	constructor(message: string, status = 500) {
		super(`WorkOS - Fake AuthKit: ${message}`);
		this.status = status;
	}
}

export const fakeConstants = {
	authCode: "<FAKE-AUTH-CODE>",
	clientId: "<FAKE-CLIENT-ID>",
	userId: "<FAKE-ID>",
	email: "<FAKE-EMAIL>",
	profilePictureUrl: "<FAKE-PROFILE-PICTURE-URL>",
	firstName: "<FAKE-FIRST-NAME>",
	lastName: "<FAKE-LAST-NAME>",
	createdAt: "<FAKE-CREATED-AT>",
	updatedAt: "<FAKE-UPDATED-AT>",
	organizationId: "<FAKE-ORGANIZATION-ID>",
	apiKey: "<FAKE-API-KEY>",
};

class FakeUserManagement extends UserManagement {
	readonly authorizationUrl = "/__fake_authorization_url";

	getAuthorizationUrl(options: AuthorizationURLOptions): string {
		if (!options.connection && !options.organization && !options.provider) {
			throw new FakeWorkOSError(
				"Incomplete arguments. Need to specify either a 'connectionId', 'organizationId', or 'provider'. (Fake currently only works with provider='authkit')",
			);
		}

		if (options.provider !== "authkit") {
			throw new FakeWorkOSError(`Invalid provider: ${options.provider}`);
		}

		return `${this.authorizationUrl}/?callback=${options.redirectUri}`;
	}

	authenticateWithCode(
		payload: AuthenticateWithCodeOptions,
	): Promise<AuthenticationResponse> {
		if (payload.code !== fakeConstants.authCode) {
			return Promise.reject(
				new FakeWorkOSError(
					`The code '${payload.code}' has expired or is invalid.`,
					400,
				),
			);
		}

		if (payload.clientId !== fakeConstants.clientId) {
			return Promise.reject("WorkOS - Fake AuthKit: Invalid client id");
		}

		return Promise.resolve({
			user: {
				object: "user",
				id: fakeConstants.userId,
				email: fakeConstants.email,
				emailVerified: true,
				profilePictureUrl: fakeConstants.profilePictureUrl,
				firstName: fakeConstants.firstName,
				lastName: fakeConstants.lastName,
				createdAt: fakeConstants.createdAt,
				updatedAt: fakeConstants.updatedAt,
			},
			organizationId: fakeConstants.organizationId,
		});
	}
}

export class FakeWorkOS extends WorkOS {
	readonly userManagement: FakeUserManagement;

	constructor() {
		super(fakeConstants.apiKey);
		this.userManagement = new FakeUserManagement(this);
	}

	fakeServer({ redirectUri = "/callback" } = {}) {
		return new Elysia({ name: "fake-workos-authkit-server" }).get(
			this.userManagement.authorizationUrl,
			({ set, query }) => {
				if (query.callback !== redirectUri) {
					throw new FakeWorkOSError(
						"Make sure that the app uses the correct redirect URI. If you are not sure what this means, please contact your organization admin.",
						400,
					);
				}
				set.redirect = `${redirectUri}/?code=${fakeConstants.authCode}`;
			},
		);
	}
}
