import type { JWTPayloadSpec } from "@elysiajs/jwt";
import type { AuthenticationResponse, WorkOS } from "@workos-inc/node";

type Digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9";
type Interval = "s" | "m" | "h" | "d" | "w" | "y";
type JwtExp = `${"-" | ""}${Digit | ""}${Digit | ""}${Digit}${Interval}`;

export type SerializedUser = Record<string, string | number> & JWTPayloadSpec;

export type AuthenticatedUser = {
	id: string;
	email: string;
	firstName: string;
	lastName: string;
	organizationId?: string;
};

export type Options<User> = {
	prefix?: string;
	workos: WorkOS;
	clientId: string;
	jwtSecret: string;
	jwtExp?: JwtExp;
	redirectUri: string;
	paths?: {
		login?: string;
		logout?: string;
		callback?: string;
	};
	serializeUser?: (response: AuthenticationResponse) => Promise<SerializedUser>;
	deserializeUser?: (user: SerializedUser) => Promise<User>;
};
