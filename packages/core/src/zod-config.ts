// zod (inside @sd-jwt/*, @owf/*, @openid4vc/* and dcql) compiles a parser per object schema with
// `new Function` and probes for it, unless its documented `jitless` configuration is set before
// the schema is built. Every SDK module that imports one of those libraries imports this module
// FIRST, so the setting is in place before any of their schemas exist: the SDK runs under a CSP
// without 'unsafe-eval' and never constructs code from strings through zod. (zod keeps the
// setting on globalThis, shared by every copy of zod in the process or bundle.)
import { config } from 'zod/v4/core';

config({ jitless: true });
