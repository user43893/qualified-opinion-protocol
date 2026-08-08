import { chmod, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, run } from "./shared";

type PackageName = "protocol" | "verifier";

const packageBuilds: Record<
  PackageName,
  {
    entrypoints: string[];
    external: string[];
  }
> = {
  protocol: {
    entrypoints: ["src/index.ts", "src/node.ts"],
    external: [],
  },
  verifier: {
    entrypoints: ["src/index.ts", "src/cli.ts"],
    external: ["@qualified-opinion/protocol", "@qualified-opinion/protocol/node"],
  },
};

const requested = Bun.argv.slice(2);
const requestedPackages: PackageName[] =
  requested.length === 0
    ? ["protocol", "verifier"]
    : requested.map((value) => {
        if (value !== "protocol" && value !== "verifier") {
          throw new Error(`Unknown package ${JSON.stringify(value)}`);
        }
        return value;
      });
const selected: PackageName[] = requestedPackages.includes("verifier")
  ? ["protocol", "verifier"]
  : ["protocol"];

for (const packageName of selected) {
  const packageDirectory = join(ROOT, "packages", packageName);
  const outputDirectory = join(packageDirectory, "dist");
  const configuration = packageBuilds[packageName];
  await rm(outputDirectory, { force: true, recursive: true });
  await mkdir(outputDirectory, { recursive: true });

  const result = await Bun.build({
    entrypoints: configuration.entrypoints.map((entrypoint) =>
      join(packageDirectory, entrypoint),
    ),
    external: configuration.external,
    format: "esm",
    minify: false,
    outdir: outputDirectory,
    sourcemap: "external",
    target: "node",
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    throw new Error(`JavaScript build failed for ${packageName}`);
  }

  await run(["bunx", "tsc", "-p", join(packageDirectory, "tsconfig.build.json")]);

  if (packageName === "verifier") {
    await chmod(join(outputDirectory, "cli.js"), 0o755);
  }
  console.log(`Built @qualified-opinion/${packageName}.`);
}
