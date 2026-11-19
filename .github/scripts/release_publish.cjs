"use strict";

const fs = require("node:fs");

const SCRIPT_NAME = "release_publish.cjs";
const SCRIPT_DESCRIPTION = "Create or update a GitHub Release from the verified release inputs.";
const SCRIPT_SOURCE = ".github/scripts/release_publish.cjs";
const SCRIPT_AUTHOR = "Gill-Bates";
const SCRIPT_HELP = `https://github.com/Gill-Bates/crowdsec-toolbox/blob/main/${SCRIPT_SOURCE}`;

async function publishRelease({ github, context, core, version, releaseNotesFile }) {
  core.info(`Script: ${SCRIPT_NAME}`);
  core.info(`Description: ${SCRIPT_DESCRIPTION}`);
  core.info(`Version: ${context.sha || "unknown"}`);
  core.info(`Source: ${SCRIPT_SOURCE}`);
  core.info(`Author: ${SCRIPT_AUTHOR}`);
  core.info(`Help: ${SCRIPT_HELP}`);

  const body = fs.readFileSync(releaseNotesFile, "utf8");
  if (!body.trim()) throw new Error("combined release notes are empty");

  const tagName = `v${version}`;
  const prerelease = version.includes("-");
  const { owner, repo } = context.repo;
  let existing = null;
  try {
    existing = (await github.rest.repos.getReleaseByTag({ owner, repo, tag: tagName })).data;
  } catch (error) {
    if (error.status !== 404) throw error;
  }

  if (existing) {
    await github.rest.repos.updateRelease({
      owner,
      repo,
      release_id: existing.id,
      name: `CrowdSec Toolbox ${version}`,
      body,
      prerelease,
    });
    core.info(`Updated release ${tagName}`);
  } else {
    await github.rest.repos.createRelease({
      owner,
      repo,
      tag_name: tagName,
      name: `CrowdSec Toolbox ${version}`,
      body,
      prerelease,
      draft: false,
    });
    core.info(`Created release ${tagName}`);
  }
}

module.exports = { publishRelease };
