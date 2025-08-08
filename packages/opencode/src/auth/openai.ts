import { generatePKCE } from "@openauthjs/openauth/pkce"
import open from "open"
import { Auth } from "./index"
import { Server } from "../server/server"

export namespace AuthOpenAI {
  const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
  const ISSUER = "https://auth.openai.com"

  type OAuthTokens = {
    id_token: string
    access_token?: string
    refresh_token?: string
  }

  const pending = new Map<string, { resolve: (code: string) => void; reject: (err: any) => void }>()

  export async function loginViaChatGPT(): Promise<void> {
    // Start a temporary local server on an ephemeral port for handling the callback
    const serverHandle = await startEphemeralCallbackServer()
    const { url, verifier, state } = await authorize(serverHandle.redirect)

    try {
      await open(url)
    } catch {}
    // eslint-disable-next-line no-console
    console.log(url)

    let stopServer: (() => void) | undefined
    if (serverHandle.started && serverHandle.server?.stop) {
      stopServer = () => serverHandle.server!.stop()
    }

    const code = await waitForCallback(state).finally(() => {
      // Stop only if we started a temporary server
      try {
        stopServer?.()
      } catch {}
    })

    const tokens = await exchangeCodeForTokens({ code, verifier, redirectUri: serverHandle.redirect })
    const apiKey = await exchangeIdTokenForApiKey(tokens.id_token)

    await Auth.set("openai", {
      type: "api",
      key: apiKey,
    })
  }

  async function startEphemeralCallbackServer(): Promise<{
    started: boolean
    server?: ReturnType<typeof Server.listen>
    redirect: string
  }> {
    // Use fixed port and localhost to match registered redirect URI
    const server = Server.listen({ hostname: "127.0.0.1", port: 1455 })
    const redirect = `http://localhost:1455/auth/callback`
    return { started: true, server, redirect }
  }

  export async function authorize(redirectUri: string) {
    const pkce = await generatePKCE()
    const state = crypto.getRandomValues(new Uint8Array(16)).reduce((acc, b) => acc + b.toString(16).padStart(2, "0"), "")

    const url = new URL(`${ISSUER}/oauth/authorize`)
    url.searchParams.set("response_type", "code")
    url.searchParams.set("client_id", CLIENT_ID)
    url.searchParams.set("redirect_uri", redirectUri)
    url.searchParams.set("scope", "openid profile email offline_access")
    url.searchParams.set("code_challenge", pkce.challenge)
    url.searchParams.set("code_challenge_method", "S256")
    url.searchParams.set("id_token_add_organizations", "true")
    // Required by OpenAI's CLI-friendly flow
    url.searchParams.set("codex_cli_simplified_flow", "true")
    url.searchParams.set("state", state)

    return {
      url: url.toString(),
      verifier: pkce.verifier,
      state,
    }
  }

  export function receiveCallback(state: string, code: string) {
    const p = pending.get(state)
    if (p) {
      p.resolve(code)
      pending.delete(state)
    }
  }

  export async function waitForCallback(expectedState: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      pending.set(expectedState, { resolve, reject })
      // Safety timeout in case the callback never arrives
      setTimeout(() => {
        if (pending.has(expectedState)) {
          pending.delete(expectedState)
          reject(new Error("OAuth callback timed out"))
        }
      }, 5 * 60 * 1000) // 5 minutes
    })
  }

  export async function exchangeCodeForTokens(args: { code: string; verifier: string; redirectUri: string }): Promise<OAuthTokens> {
    const body = new URLSearchParams()
    body.set("grant_type", "authorization_code")
    body.set("code", args.code)
    body.set("redirect_uri", args.redirectUri)
    body.set("client_id", CLIENT_ID)
    body.set("code_verifier", args.verifier)

    const res = await fetch(`${ISSUER}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    })
    if (!res.ok) throw new TokenExchangeFailed()
    const json = await res.json()
    return {
      id_token: json.id_token as string,
      access_token: json.access_token as string | undefined,
      refresh_token: json.refresh_token as string | undefined,
    }
  }

  export async function exchangeIdTokenForApiKey(idToken: string): Promise<string> {
    const body = new URLSearchParams()
    body.set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
    body.set("client_id", CLIENT_ID)
    body.set("requested_token", "openai-api-key")
    body.set("subject_token", idToken)
    body.set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
    body.set("name", buildKeyName())

    const res = await fetch(`${ISSUER}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    })
    if (!res.ok) throw new ApiKeyExchangeFailed()
    const json = await res.json()
    const apiKey = json.access_token as string
    if (!apiKey) throw new Error("OpenAI API key not returned")
    return apiKey
  }

  function buildKeyName() {
    const today = new Date()
    const iso = today.toISOString().slice(0, 10)
    const rand = Math.random().toString(16).slice(2, 10)
    return `OpenCode CLI [auto-generated] (${iso}) [${rand}]`
  }

  export class TokenExchangeFailed extends Error {
    constructor() {
      super("OpenAI token exchange failed")
    }
  }

  export class ApiKeyExchangeFailed extends Error {
    constructor() {
      super("OpenAI API key exchange failed")
    }
  }
}
