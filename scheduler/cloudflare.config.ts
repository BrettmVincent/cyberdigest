import { bindings, defineConfig, triggers } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

export default defineConfig({
	worker: {
		name: "cyberdigest-scheduler",
		compatibilityDate: "2026-11-19",
		entrypoint,
		// No public URL: this Worker only runs on its Cron Trigger.
		workersDev: false,
		previewUrls: false,
		// Every 10 minutes (UTC).
		triggers: [triggers.scheduled({ schedule: "*/10 * * * *" })],
		env: {
			GITHUB_REPO: bindings.text("BrettmVincent/cyberdigest"),
			WORKFLOW_FILE: bindings.text("update.yml"),
			GIT_REF: bindings.text("main"),
			// Fine-grained GitHub token (this repo only, Actions: Read and write). Set as an encrypted secret.
			GITHUB_TOKEN: bindings.secret(),
		},
	},
});
