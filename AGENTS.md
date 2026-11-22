# Pi extension dependencies

When a Pi extension imports `typebox` or a subpath such as `typebox/value`, declare `"typebox": "*"` in the `peerDependencies` section of `package.json`. Pi supplies `typebox` at runtime, so keep it out of `dependencies`. Specify the version needed for type checking or tests in `devDependencies`. Update the lockfile whenever you change a dependency declaration.
