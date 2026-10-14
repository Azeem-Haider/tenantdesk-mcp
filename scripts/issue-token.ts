import { ALL_SCOPES, issueToken } from "../src/auth.js";

// Dev tokens only (AUTH_MODE=dev). In production your identity provider issues tokens.
// Demo users: u_ana (Acme admin), u_ben (Acme agent), u_cara (Acme viewer),
//             u_dev (Brightside admin), u_eli (Brightside agent)
//
//   npm run token u_ana                       all scopes
//   npm run token u_ana tenantdesk:read       read-only token for the same admin
const [user = "u_ana", ...scopes] = process.argv.slice(2);
console.log(await issueToken(user, { scopes: scopes.length ? scopes : ALL_SCOPES }));
