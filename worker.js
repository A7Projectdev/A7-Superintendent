

const REDIRECT_URI =
  "https://a7-superintendent-api.a7tristian.workers.dev/auth/google/callback";

const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const TOKEN_KEY = "gmail-owner-refresh-token";

function reply(message, status = 200, extraHeaders = {}) {
  return new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      ...extraHeaders,
    },
  });
}

function randomState() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const entry = cookies
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(name + "="));

  return entry ? entry.slice(name.length + 1) : "";
}

const clearStateCookie =
  "a7_oauth_state=; Path=/auth/google; HttpOnly; Secure; SameSite=Lax; Max-Age=0";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        app: "A7 Superintendent",
        api: "online",
        gmailConnected: false,
        note: "Gmail connection status is not exposed publicly.",
      });
    }

    if (url.pathname === "/auth/google/start") {
      if (request.method !== "GET") {
        return reply("Method not allowed.", 405);
      }

      if (
        !env.GOOGLE_CLIENT_ID ||
        !env.GOOGLE_CLIENT_SECRET ||
        !env.ALLOWED_EMAIL ||
        !env.GMAIL_TOKENS
      ) {
        return reply(
          "Google sign-in setup is incomplete. Check the Worker secrets and KV binding.",
          503
        );
      }

      const state = randomState();

      const googleUrl = new URL(
        "https://accounts.google.com/o/oauth2/v2/auth"
      );

      googleUrl.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
      googleUrl.searchParams.set("redirect_uri", REDIRECT_URI);
      googleUrl.searchParams.set("response_type", "code");
      googleUrl.searchParams.set("scope", GMAIL_SCOPE);
      googleUrl.searchParams.set("access_type", "offline");
      googleUrl.searchParams.set("prompt", "consent");
      googleUrl.searchParams.set("state", state);

      return Response.redirect(googleUrl.toString(), 302) instanceof Response
        ? new Response(null, {
            status: 302,
            headers: {
              Location: googleUrl.toString(),
              "Cache-Control": "no-store",
              "Set-Cookie":
                `a7_oauth_state=${state}; Path=/auth/google; ` +
                "HttpOnly; Secure; SameSite=Lax; Max-Age=600",
            },
          })
        : reply("Unable to start Google sign-in.", 500);
    }

    if (url.pathname === "/auth/google/callback") {
      if (request.method !== "GET") {
        return reply("Method not allowed.", 405);
      }

      const headers = { "Set-Cookie": clearStateCookie };

      const expectedState = getCookie(request, "a7_oauth_state");
      const returnedState = url.searchParams.get("state") || "";
      const code = url.searchParams.get("code");

      if (
        !expectedState ||
        !returnedState ||
        expectedState !== returnedState
      ) {
        return reply(
          "Sign-in session expired or did not match. Start again.",
          400,
          headers
        );
      }

      if (url.searchParams.has("error")) {
        return reply("Google sign-in was not completed.", 400, headers);
      }

      if (
        !code ||
        !env.GOOGLE_CLIENT_ID ||
        !env.GOOGLE_CLIENT_SECRET ||
        !env.ALLOWED_EMAIL ||
        !env.GMAIL_TOKENS
      ) {
        return reply("Sign-in setup is incomplete.", 503, headers);
      }

      try {
        const tokenResponse = await fetch(
          "https://oauth2.googleapis.com/token",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              code,
              client_id: env.GOOGLE_CLIENT_ID,
              client_secret: env.GOOGLE_CLIENT_SECRET,
              redirect_uri: REDIRECT_URI,
              grant_type: "authorization_code",
            }),
          }
        );

        if (!tokenResponse.ok) {
          return reply(
            "Google could not complete the token exchange. Check the OAuth settings.",
            502,
            headers
          );
        }

        const tokens = await tokenResponse.json();

        if (
          !tokens.access_token ||
          !String(tokens.scope || "").split(" ").includes(GMAIL_SCOPE)
        ) {
          return reply(
            "The required read-only Gmail permission was not granted.",
            403,
            headers
          );
        }

        const profileResponse = await fetch(
          "https://gmail.googleapis.com/gmail/v1/users/me/profile",
          {
            headers: {
              Authorization: `Bearer ${tokens.access_token}`,
            },
          }
        );

        if (!profileResponse.ok) {
          return reply(
            "Could not verify the Google account.",
            502,
            headers
          );
        }

        const profile = await profileResponse.json();
        const authorizedEmail = String(env.ALLOWED_EMAIL)
          .trim()
          .toLowerCase();

        if (
          String(profile.emailAddress || "").toLowerCase() !==
          authorizedEmail
        ) {
          return reply(
            "This Google account is not authorized for A7 Superintendent.",
            403,
            headers
          );
        }

        const existingRefreshToken = await env.GMAIL_TOKENS.get(TOKEN_KEY);
        const refreshToken =
          tokens.refresh_token || existingRefreshToken;

        if (!refreshToken) {
          return reply(
            "Google did not return an offline token. Please start sign-in again.",
            502,
            headers
          );
        }

        await env.GMAIL_TOKENS.put(TOKEN_KEY, refreshToken);

        return reply(
          "Gmail authorization saved for A7 Superintendent. You can close this page.",
          200,
          headers
        );
      } catch {
        return reply(
          "Google sign-in could not finish. Please try again.",
          500,
          headers
        );
      }
    }

    return reply("A7 Superintendent API is running.");
  },
};
