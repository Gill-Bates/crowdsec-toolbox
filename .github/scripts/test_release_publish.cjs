"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { publishRelease } = require("./release_publish.cjs");

function withNotes(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-publish-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const releaseNotesFile = path.join(directory, "release-notes.md");
  fs.writeFileSync(releaseNotesFile, "Release notes\n", "utf8");
  const calls = { create: [], update: [] };
  const github = {
    rest: {
      repos: {
        getReleaseByTag: async () => {
          const error = new Error("missing");
          error.status = 404;
          throw error;
        },
        createRelease: async (input) => calls.create.push(input),
        updateRelease: async (input) => calls.update.push(input),
      },
    },
  };
  const core = { info() {} };
  const context = { sha: "abc123", repo: { owner: "owner", repo: "repo" } };
  return { releaseNotesFile, calls, github, core, context };
}

test("creates a release when the tag has no existing release", async (t) => {
  const fixture = withNotes(t);
  await publishRelease({ ...fixture, version: "1.2.3" });

  assert.equal(fixture.calls.create.length, 1);
  assert.equal(fixture.calls.create[0].tag_name, "v1.2.3");
  assert.equal(fixture.calls.update.length, 0);
});

test("updates an existing release", async (t) => {
  const fixture = withNotes(t);
  fixture.github.rest.repos.getReleaseByTag = async () => ({ data: { id: 42 } });
  await publishRelease({ ...fixture, version: "1.2.3" });

  assert.equal(fixture.calls.update.length, 1);
  assert.equal(fixture.calls.update[0].release_id, 42);
  assert.equal(fixture.calls.create.length, 0);
});

test("propagates GitHub API errors other than a missing release", async (t) => {
  const fixture = withNotes(t);
  fixture.github.rest.repos.getReleaseByTag = async () => {
    const error = new Error("rate limited");
    error.status = 403;
    throw error;
  };

  await assert.rejects(publishRelease({ ...fixture, version: "1.2.3" }), /rate limited/);
  assert.equal(fixture.calls.create.length, 0);
  assert.equal(fixture.calls.update.length, 0);
});
