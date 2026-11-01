# Changelog

## [Unreleased]
### Added
- Added `LUA_DISABLE_LOADLIB` build option to disable the runtime dynamic module loader.
- Added `CreateFromMixins`, `Mixin`, `dumpobject`, `mapvalues`, and `securecallmethod` base library functions.
- Added `GetGlobalEnvironment`, `GetCurrentEnvironment`, `IsInGlobalEnvironment`, and `SwapToGlobalEnvironment` base library functions.
- Added the `issecurevalue(value)` base library function.
- Added speculative support for `securecopy(value[, options])` and the corresponding `luaL_securecopy` C API.
  - Copies table graphs while preserving shared references and cycles, with options for maximum traversal depth, wrapping untrusted functions, and permitting script objects.
- Added `table.freeze` and `table.isfrozen`, and the corresponding `lua_freezetable` and `lua_isfrozen` C APIs.
  - Frozen tables reject direct writes and metatable replacement, but still support assignment through `__newindex`. Insecure code can only freeze tables with matching object taint.
- Added `table.contains`, `table.count`, `table.create`, `table.getcountinfo`, `table.indexof`, `table.isempty`, `table.keys`, `table.removeunordered`, `table.removevalue`, and `table.values`.
- Added `math.clamp`, `math.isfinite`, `math.isinf`, `math.isnan`, `math.lerp`, `math.normalize`, `math.remap`, `math.round`, `math.saturate`, `math.sign`, and `math.wrap`.
- Added `string.contains`, `string.endswith`, `string.ltrim`, `string.rtrim`, and `string.startswith`.
- Added `string.join`, `string.split`, and `string.trim` to the string library without requiring the compatibility library.
- Added elune-specific `debug.setobjectname(userdata, name)` and `debug.getobjectname(userdata)`, with corresponding `luaL_setobjectname` and `luaL_getobjectname` C APIs.
  - Names must be strings; assigning nil clears a name, and querying an unregistered object returns nil.
  - Names live in a private registry table with weak keys. Full userdata remains collectible; clear light userdata names before reusing native pointers.

### Changed
- Required CMake version is now 3.28.
- The `string.lower` and `string.upper` functions now use UTF-8 case conversion by default. Set the new `LUA_USE_UTF8_CASE` build option to OFF to retain byte-wise conversion.
  - UTF-8 conversion discards malformed bytes and stops at the first embedded null character, matching reference behavior.
  - UTF-8 conversion may not support the same codepoint blocks as the reference client, but it should be accurate enough.
- The `luaL_loadbuffer` function now skips a leading UTF-8 byte order mark.
- The `string.join` function now uses Lua concatenation semantics, including `__concat` metamethods and preservation of embedded null characters.
- The `table.wipe` function now removes entries without invoking `__newindex`.
- Fixed a correctness issue where the insertion of new table entries did not remove taint from the assigned key.
- Fixed incorrect handling of original function and hook taint in `hooksecurefunc`.
- Fixed acceptance of NaN table keys and floating point classification under fast math optimizations.
- Fixed incorrect `math.huge` values in MSVC builds with `/fp:fast`.
- Fixed division-by-zero and signed integer overflow in `bit.mod`.
- Fixed missing argument validation in `tostring`.
- Fixed handling of empty format strings in `date` to match reference client errors.
- Fixed trimming of empty strings and embedded null characters in `string.trim`.
- Fixed unterminated option arrays used by the compatibility and taint mode APIs.
- Fixed build portability issues with compiler attributes, user presets, and exported dependency targets.

### Removed
- Removed 32-bit Windows builds from CI and the supplied user presets.
- The `__name` metamethod is no longer consulted for object-name replacement in error handling and `debuglocals`.

## [v3.1]
### Added
- Added the `pcallwithenv(f, env, [args...])` base library function.
- Added compatibility option interface. This allows toggling any potentially incompatible changes made for reference client compatibility.
  - This is exposed via the debug library as `debug.getcompatopt(name)` and `debug.setcompatopt(name, value)`.
  - Supported option names are currently "setfenv", "gctaint", "gcdebug", and "inerrorhandler" which - if set to 1 - will revert the changes documented below.
### Changed
- The `setfenv` function will no longer allow replacing function environments that have a metatable with an `__environment` key to match new reference client behavior.
- `__gc` metamethods are now invoked with a taint barrier to match new reference client behavior.
- The `debugstack`, `debuglocals`, and `getfenv` functions will now return no results if called by `__gc` metamethods.
- The `debuglocals` function can now be called outside of an error handler.
- Fixed linker errors with inlined security functions in unoptimized builds on non-Windows systems.
- Fixed a correctness issue with `secureexecuterange` where errors in the supplied callback were incorrectly forwarded to the global error handler.
- Fixed an issue with `secureexecuterange` where the the C stack would grow each time the callback errored.

## [v3.0]
### Added
- Added a build option (`LUA_USE_FAST_MATH`) to toggle the addition of floating point optimization compiler flags, which have been removed from the presets. This is enabled by default.
- Added a new `n` parameter to `lua_cleartaint` which will clear the taint off the top `n` stack variables.
- Added a backport of `luaL_tolstring` from Lua 5.2.
### Changed
- Fixed a few issues with the `bit.*` library functions.
- Required CMake version is now 3.24.
- CMake will now consult find_package modules to search for dependency libraries before falling back to acquiring them via FetchContent.
### Removed
- Removed `lua_istaintexpected`. This API was effectively non-functional when called by C due to the internals of taint and would always return 1.

## [v2.2]
### Added
- Added `debuglocals([level])` library API.
- Added `debugstack([thread, ][level, ntop, nbase, ...])` library API.
- Added `strsplittable(delim, str[, limit])` library API.
- Added support for object name replacements in handled errors.
### Changed
- Fixed an issue where `secureexecuterange()` would not pass through additional arguments to the supplied function.
- Fixed an issue where `strsplit()` would ignore the value supplied to the `limit` parameter.
- Fixed various correctness issues with `strsplit()` and processing of parameters with embedded null characters.

## [v2.1]
### Changed
- The `lua_Clock` typedef is now an `int64_t` to work around issues on 32-bit platforms.
- Fixed a bug with `table.concat` and `unpack` using an incorrect default value for the optional `j` parameter.

## [v2.0]
### Added
- Reimplemented taint propagation from the ground-up, fixing a large amount of bugs and unimplemented aspects particularly around coroutines.
- Added C and Lua APIs for creating and testing C closures.
- Added C and Lua APIs for profiling and memory measurement.
- Added C and Lua APIs for high-precision timers.
- Added C and Lua APIs for querying and manipulating taint.
- Added C and Lua APIs for secure random number generation.
- Added support for the `__environment` metatable key to `getfenv`.
- Added a `-p` flag to the interpreter to enable performance accounting.
- Added a `-t` flag to the interpreter to run inline scripts (`-e`) or load files insecurely.
  - When this flag is specified, any modules loaded via `-l` will still be loaded securely.

### Changed
- Build process now requires CMake 3.22 and makes use of CMake presets for common build targets. See README for more information.

### Removed
- Removed the taint field on the `lua_Debug` to fix potential binary incompatibilities.
- Removed the `"s"` field from `debug.getinfo`. Use `debug.getstacktaint()` instead.
- Removed `debug.forcesecure()`. Use `debug.setstacktaint(nil)` instead.

## [v1]
### Added
- Added basic taint propagation system.
- Added the following security extensions to the base library:
  - `forceinsecure()`
  - `geterrorhandler()`
  - `hooksecurefunc([table,] "name", func)`
  - `issecure()`
  - `issecurevariable([table,] "variable")`
  - `scrub(...)`
  - `seterrorhandler(errfunc)`
- Added the following security extensions to the debug library:
  - `debug.forcesecure()`
- Added a new hook mask (`"s"`) which is invoked whenever the VM transitions between security states. This occurs after processing of the current instruction.
- Added a debug trap system that allows configuring errors under certain runtime conditions.
  - This can be controlled through the `debug.settrapmask("mask")` and `debug.gettrapmask()` functions.
  - The `"s"` mask enables integer overflow errors in `string.format` falls for signed format specifiers.
  - The `"u"` mask enables integer overflow errors in `string.format` calls for unsigned format specifiers.
  - The `"z"` mask enables divide-by-zero errors for division and modulo operations.
  - The default trap mask matches that of a live retail client environment and is set to `"s"`.
- Added all string library extensions present in the in-game environment as well as their global aliases.
- Added all table library extensions present in the in-game environment as well as their global aliases.
- Added all math library extensions present in the in-game environment as well as their global aliases.
- Added all global aliases to the OS libary functions as present in the in-game environment.

[Unreleased]: https://github.com/Meorawr/elune/compare/v3.1...HEAD
[v3.1]: https://github.com/Meorawr/elune/compare/v3.0...v3.1
[v3.0]: https://github.com/Meorawr/elune/compare/v2.2...v3.0
[v2.2]: https://github.com/Meorawr/elune/compare/v2.1...v2.2
[v2.1]: https://github.com/Meorawr/elune/compare/v2.0...v2.0
[v2.0]: https://github.com/Meorawr/elune/compare/v1...v2.0
[v1]: https://github.com/Meorawr/elune/releases/tag/v1
