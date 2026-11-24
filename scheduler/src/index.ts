/**
 * CyberDigest scheduler.
 *
 * GitHub's built-in `schedule` trigger is best-effort (new repositories can wait many hours for the
 * first run, and runs are delayed or dropped under load). This Worker's Cron Trigger fires every
 * 10 minutes and asks GitHub Actions to start the "Update CyberDigest" workflow via the
 * workflow_dispatch API. The workflow's concurrency group queues overlapping runs, so a slow run
 * is never duplicated in parallel.
 *
 * The Worker has no public URL; it only runs on its schedule.
 */

export interface DispatchConfig {
	/** Fine-grained GitHub token: this repository only, "Actions: Read and write". */
	GITHUB_TOKEN: string;
	/** owner/repo */
	GITHUB_REPO: string;
	/** Workflow file name or numeric id. */
	WORKFLOW_FILE: string;
	/** Branch the workflow runs on. */
	GIT_REF: string;
}

export function dispatchRequest(cfg: DispatchConfig): Request {
	return new Request(`https://api.github.com/repos/${cfg.GITHUB_REPO}/actions/workflows/${encodeURIComponent(cfg.WORKFLOW_FILE)}/dispatches`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${cfg.GITHUB_TOKEN}`,
			Accept: "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
			"Content-Type": "application/json",
			"User-Agent": "cyberdigest-scheduler",
		},
		body: JSON.stringify({ ref: cfg.GIT_REF }),
	});
}

/** Start one workflow run. GitHub answers 204 No Content on success. */
export async function dispatchUpdate(cfg: DispatchConfig, fetcher: (req: Request) => Promise<Response> = (req) => fetch(req)): Promise<void> {
	if (!cfg.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN secret is not set");
	const res = await fetcher(dispatchRequest(cfg));
	if (res.status !== 204) {
		const detail = (await res.text()).slice(0, 300);
		throw new Error(`GitHub workflow dispatch failed: HTTP ${res.status} ${detail}`);
	}
}

export default {
	async scheduled(controller, env) {
		await dispatchUpdate(env);
		console.log(`Dispatched ${env.WORKFLOW_FILE} on ${env.GITHUB_REPO}@${env.GIT_REF} (cron "${controller.cron}")`);
	},
} satisfies ExportedHandler<Env>;
