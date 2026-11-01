# Repository Guidance

## Scope and Conventions

- Elune provides a modified Lua interpreter and library. Keep runtime/library changes in `liblua/`, interpreter changes in `lua/`, compiler changes in `luac/`, and tests in `tests/`.
- Follow nearby code and the repository's `.editorconfig` and `.clang-format`. Avoid unrelated formatting changes.
- Preserve existing interpreter behavior and library contracts unless the task explicitly changes them.
- Do not update `README.md` unless the operator explicitly requests it. `CHANGELOG.md` updates are permissible for user-facing changes, including changes affecting interpreter users or library consumers.

## Building and Validation

- Use CMake 3.28 or newer, Ninja, and the platform compiler. The presets use Ninja Multi-Config; build presets select Release.
- Run commands from the repository root. Substitute `macos` or `windows` for `linux` as appropriate; build directories are platform-specific.

  ```sh
  cmake --preset linux
  cmake --build --preset linux
  ```

- Top-level builds enable tests by default through `BUILD_TESTING`. Configuration fetches Acutest from GitHub; report unavailable network access or missing prerequisites rather than treating skipped checks as passing.
- Run the test executable from its output directory, not the repository root: Lua scripts are copied beside it and loaded by relative path. On Windows, use `luatest.exe`.

  ```sh
  cd build/linux/bin/Release
  ./luatest --list
  ./luatest "scripted test cases"
  ./luatest
  ```

- Start with the relevant test names from `--list`, then run the full suite for runtime/library changes. Other script groups are `"coroutine script tests"` and `"profiling script tests"`. Select the containing script group for Lua cases; individual `case(...)` labels are not top-level test selectors.
- Rebuild after changing native tests or Lua scripts so the executable and copied scripts are current. Use `luatest` directly; the current suite is not registered with CTest.
- Installation and packaging are separate checks, not routine validation. When those surfaces change, follow the workflow in `.github/workflows/build.yaml` using the matching build preset and `--target install` or `--target package`. Do not install into system locations without operator approval.
- Documentation-only changes do not require a native build or test run.
- Report the commands run, their results, any skipped checks, and outstanding operator validation. Local tests establish elune behavior, not reference-client compatibility.

## Writing Tests

- Keep each test small and focused on one behavior. Prefer several clearly named cases over a large test exercising unrelated behavior.
- Keep inputs, actions, and assertions visible in the test body. Avoid abstractions that require readers to chase details; small shared setup helpers are acceptable.
- Prefer a brief comment at the start of each test body explaining what it evaluates. Use a block comment for native C tests.
- Native tests need additional commentary where Lua stack operations obscure intent. Explain relevant stack positions, values left or consumed, and important stack/taint transitions. Keep these comments synchronized with the operations.
- Assert observable behavior and meaningful failure cases. For native APIs, also verify relevant stack effects and restore or close the Lua state as appropriate.
- Native tests live in `tests/luatest.c`, use Acutest assertions, and are registered in `TEST_LIST`. Follow the existing setup and cleanup patterns.
- Lua tests use `case("description", function() ... end)` with assertions inside the body. Add cases to the appropriate existing script when possible:
  - `tests/luatest_scriptcases.lua`: reference-client-compatible behavior, including taint.
  - `tests/luatest_coroutine.lua`: coroutine behavior.
  - `tests/luatest_profiling.lua`: profiling behavior.
- Adding a case to an existing script does not need another native registration. Adding a new script requires a native runner and `TEST_LIST` entry in `tests/luatest.c`, plus an `elune_target_copy_file(...)` entry in `tests/CMakeLists.txt`.
- Keep reference-client cases runnable in-game. Do not rely on elune-only APIs or unavailable debug APIs in those cases. `tests/luatest_scriptcases.lua` provides a fallback `case` runner for the client when `_G.case` is absent; preserve that path. Other scripts need an appropriate client-side runner before operator validation.

## Reference-Client API Work

1. Obtain official API documentation or community notes for the specific function first. Record the sources and distinguish documented behavior from assumptions. If documentation is absent or contradictory, identify the gap rather than inventing a contract.
2. Write small script cases for the expected contract and uncertain behavior before implementing the API in elune. Keep the cases compatible with the target WoW client. Use reference source as supporting evidence, not as proof that a case passes in-game.
3. Ask the operator to run the cases in-game. Supply the exact script cases, any runner/setup needed, the target client, and the expected results; request the actual output or failures.
4. Stop before implementation until the operator confirms that all proposed reference cases pass in-game. If cases fail, resolve the discrepancy, revise them as needed, and request another client run.
5. Implement elune behavior against the confirmed cases, then build and run focused tests followed by the full suite. Add native tests for C API or stack behavior that cannot be exercised by client-side Lua.

Agents cannot run or validate against the WoW client. Never claim in-game validation based on local tests, documentation, or source inspection. If implementation exposes a new reference-behavior question, return to operator-run cases before relying on an assumption.
