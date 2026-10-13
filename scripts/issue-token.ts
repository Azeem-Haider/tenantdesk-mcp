import { issueToken } from "../src/auth.js";

// Demo users: u_ana (Acme admin), u_ben (Acme agent), u_cara (Acme viewer),
//             u_dev (Brightside admin), u_eli (Brightside agent)
const user = process.argv[2] ?? "u_ana";
console.log(await issueToken(user));
