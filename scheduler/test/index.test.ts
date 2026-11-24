import { expect, it } from "vite-plus/test";
import { dispatchRequest, dispatchUpdate, type DispatchConfig } from "../src/index.ts";

const cfg: DispatchConfig = { GITHUB_TOKEN: "test-token", GITHUB_REPO: "owner/repo", WORKFLOW_FILE: "update.yml", GIT_REF: "main" };

it("builds the GitHub workflow_dispatch request", async () => {
	const req = dispatchRequest(cfg);
	expect(req.method).toBe("POST");
	expect(req.url).toBe("https://api.github.com/repos/owner/repo/actions/workflows/update.yml/dispatches");
	expect(req.headers.get("Authorization")).toBe("Bearer test-token");
	expect(req.headers.get("Accept")).toBe("application/vnd.github+json");
	expect(req.headers.get("User-Agent")).toBe("cyberdigest-scheduler");
	expect(await req.json()).toEqual({ ref: "main" });
});

it("treats 204 as success", async () => {
	const seen: Request[] = [];
	await dispatchUpdate(cfg, async (req) => {
		seen.push(req);
		return new Response(null, { status: 204 });
	});
	expect(seen).toHaveLength(1);
});

it("throws with GitHub's error on failure", async () => {
	await expect(dispatchUpdate(cfg, async () => new Response('{"message":"Bad credentials"}', { status: 401 }))).rejects.toThrow(/HTTP 401.*Bad credentials/);
});

it("refuses to run without a token", async () => {
	await expect(dispatchUpdate({ ...cfg, GITHUB_TOKEN: "" }, async () => new Response(null, { status: 204 }))).rejects.toThrow(/GITHUB_TOKEN/);
});
