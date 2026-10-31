--
-- This script contains a large amount of conformance tests for verifying
-- implementation details of taint against the reference environment.
--
-- If you were to execute this script securely in the reference client, all
-- the below test cases would pass. As a result - don't add anything here
-- that wouldn't actually work in the reference client, like relying on
-- debug APIs that don't exist.
--

-- luacheck: globals forceinsecure hooksecurefunc issecure issecurevariable
-- luacheck: globals loadstring_untainted securecall securecallfunction
-- luacheck: globals geterrorhandler seterrorhandler
-- luacheck: globals strsplit strsplittable secureexecuterange
-- luacheck: globals bit.mod
-- luacheck: globals date
-- luacheck: globals dumpobject mapvalues Mixin CreateFromMixins securecallmethod
-- luacheck: globals table.freeze table.isfrozen table.count table.wipe

local case = _G.case
    or function(name, func)
        local olderrhandler = geterrorhandler()
        local errors = {}

        seterrorhandler(function(err)
            table.insert(errors, err)
        end)
        securecall(func)
        seterrorhandler(olderrhandler)

        print(
            string.format("Test %s: [ %s ]", name, (#errors > 0 and "\124cffff0000FAIL\124r" or "\124cff00ff00OK\124r"))
        )

        for _, err in ipairs(errors) do
            olderrhandler(err)
        end
    end

-- This test verifies that the MOVE operation correctly results in a tainted
-- assignment if the context is insecure.
case("OP_MOVE: Copy secure value from tainted context", function()
    local _ENV = {}

    securecall(function()
        local source = "test" -- LOADK
        _ENV.source = source -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local target = source -- MOVE
        _ENV.target = target -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "source"), "expected '_ENV.source' to be secure")
    assert(not issecurevariable(_ENV, "target"), "expected '_ENV.target' to be tainted")
end)

-- This test verifies that the LOADK operation correctly results in a tainted
-- assignment if the context is insecure.
case("OP_LOADK: Load constant into tainted context", function()
    local _ENV = {}

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local value = 123 -- LOADK
        _ENV.value = value -- GETUPVAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be tainted")
end)

-- This test verifies that the LOADBOOL operation correctly results in a tainted
-- assignment if the context is insecure.
case("OP_LOADBOOL: Load boolean value into tainted context", function()
    local _ENV = {}

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local value = true -- LOADBOOL
        _ENV.value = value -- GETUPVAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be tainted")
end)

-- This test verifies that the LOADNIL operation correctly results in a tainted
-- assignment if the context is insecure.
case("OP_LOADNIL: Load nil value into tainted context", function()
    local _ENV = {}
    collectgarbage("stop") -- GC table traversal can nuke tainted nil values.

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local value = nil -- LOADNIL
        _ENV.value = value -- GETUPVAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be tainted")
end)

-- This test verifies that the GETGLOBAL operation does not taint the stack
-- if reading a secure value.
case("OP_GETGLOBAL: Read secure value", function()
    local _ENV = {}

    securecall(function()
        variable = "test" -- LOADK, SETGLOBAL
        _ENV.value = variable -- GETGLOBAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "value"), "expected '_ENV.value' to be secure")
end)

-- This test verifies that the GETGLOBAL operation taints the stack if reading
-- an insecure global variable.
case("OP_GETGLOBAL: Read tainted value", function()
    local _ENV = {}

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        variable = "test" -- LOADK, SETGLOBAL
    end)

    securecall(function()
        _ENV.value = variable -- GETGLOBAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be tainted")
end)

-- This test verifies that the GETGLOBAL operation taints the read value if
-- a secure value is read from a tainted context.
case("OP_GETGLOBAL: Read secure value from tainted context", function()
    local _ENV = {}

    securecall(function()
        variable = "test" -- LOADK, SETGLOBAL
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local value = variable -- GETGLOBAL
        _ENV.value = value -- GETUPVAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be tainted")
end)

-- This test verifies that the GETGLOBAL operation does not trigger taint
-- if reading values from an insecurely-assigned function environment.
case("OP_GETGLOBAL: Read from insecure function environment", function()
    local assert = assert
    local getfenv = getfenv
    local issecure = issecure

    local insecureclosure = function()
        forceinsecure()
        setfenv(3, {})
    end

    local secureclosure = function()
        securecall(insecureclosure)
        assert(issecure(), "expected context to be secure after applying tainted function environment")
        local _ = getfenv(1)
        assert(not issecure(), "expected context to be insecure after retrieving tainted function environment")
    end

    secureclosure()
end)

-- This test verifies that the GETTABLE operation does not taint the stack
-- if reading a secure field.
case("OP_GETTABLE: Read secure field", function()
    local _ENV = {}

    securecall(function()
        local value = "test" -- LOADK
        _ENV.source = value -- SETTABLE
    end)

    securecall(function()
        _ENV.target = _ENV.source -- GETTABLE, SETTABLE
    end)

    assert(issecurevariable(_ENV, "target"), "expected '_ENV.target' to be secure")
end)

-- This test verifies that the GETTABLE operation taints the stack if reading
-- an insecure field.
case("OP_GETTABLE: Read tainted field", function()
    local _ENV = {}

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local value = "test" -- LOADK
        _ENV.source = value -- SETTABLE
    end)

    securecall(function()
        _ENV.target = _ENV.source -- GETTABLE, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "target"), "expected '_ENV.target' to be tainted")
end)

-- This test verifies that the GETTABLE operation applies taint to secure
-- values read from tables while the context is tainted.
case("OP_GETTABLE: Read secure field from tainted context", function()
    local _ENV = {}

    securecall(function()
        local value = "test" -- LOADK
        _ENV.source = value -- SETTABLE
    end)

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        _ENV.target = _ENV.source -- GETTABLE, SETTABLE
    end)

    assert(issecurevariable(_ENV, "source"), "expected '_ENV.source' to be secure")
    assert(not issecurevariable(_ENV, "target"), "expected '_ENV.target' to be tainted")
end)

-- This test verifies that the GETUPVAL operation does not taint the stack
-- if reading a secure upvalue.
case("OP_GETUPVAL: Read secure upvalue", function()
    local _ENV = {}
    local upval

    securecall(function()
        upval = "test" -- LOADK, SETUPVAL
    end)

    securecall(function()
        _ENV.value = upval -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "value"), "expected '_ENV.value' to be secure")
end)

-- This test verifies that the GETUPVAL operation taints the stack if reading
-- a tainted upvalue.
case("OP_GETUPVAL: Read tainted upvalue", function()
    local _ENV = {}
    local upval

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        upval = "test" -- LOADK, SETUPVAL
    end)

    securecall(function()
        _ENV.value = upval -- GETUPVAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be insecure")
end)

-- This test verifies that the GETUPVAL operation taints read upvalues if
-- they are secure while the context is currently insecure.
case("OP_GETUPVAL: Read secure upvalue from tainted context", function()
    local _ENV = {}
    local upval

    securecall(function()
        upval = "test" -- LOADK, SETUPVAL
    end)

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        _ENV.value = upval -- GETUPVAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be insecure")
end)

-- This test verifies that SETGLOBAL does not unexpectedly taint values when
-- writing secure values from a secure context.
case("OP_SETGLOBAL: Write secure value", function()
    securecall(function()
        local value = "test" -- LOADK
        variable = value -- SETGLOBAL
    end)

    assert(issecurevariable("variable"), "expected 'variable' to be secure")
end)

-- This test verifies that SETGLOBAL correctly transfers taint to the written
-- field when writing a tainted value.
case("OP_SETGLOBAL: Write tainted value", function()
    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        variable = "test" -- LOADK, SETGLOBAL
    end)

    assert(not issecurevariable("variable"), "expected 'variable' to be tainted")
end)

-- This test verifies that SETGLOBAL does **not** taint secure values when
-- written from an insecure context.
case("OP_SETGLOBAL: Write secure value from tainted context", function()
    securecall(function()
        local value = "test" -- LOADK
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        variable = value -- SETGLOBAL
    end)

    assert(issecurevariable("variable"), "expected 'variable' to be secure")
end)

-- This test verifies that SETTABLE does not unexpectedly taint values when
-- writing secure values from a secure context.
case("OP_SETTABLE: Write secure value", function()
    local _ENV = {}

    securecall(function()
        local value = "test" -- LOADK
        _ENV.key = value -- SETTABLE
    end)

    assert(issecurevariable(_ENV, "key"), "expected '_ENV.key' to be secure")
end)

-- This test verifies that SETTABLE correctly stores any taint associated with
-- a value when writing to the table.
case("OP_SETTABLE: Write tainted value", function()
    local _ENV = {}

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local value = "test" -- LOADK
        _ENV.key = value -- SETTABLE
    end)

    assert(not issecurevariable(_ENV, "key"), "expected '_ENV.key' to be tainted")
end)

-- This test verifies that SETTABLE does **not** taint secure values written
-- to tables from insecure contexts.
--
-- This is a critical test; if this fails other tests will also fail as we
-- rely on this to observe the effects of taint.
case("OP_SETTABLE: Write secure value from tainted context", function()
    local _ENV = {}

    securecall(function()
        local value = "test" -- LOADK
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        _ENV.key = value -- SETTABLE
    end)

    assert(issecurevariable(_ENV, "key"), "expected '_ENV.key' to be secure")
end)

-- This test verifies that SETTABLE does **not** taint constants when written
-- directly to tables.
--
-- This is a critical test; if this fails it's likely that other tests will be
-- broken by this implicitly.
case("OP_SETTABLE: Write secure constant from tainted context", function()
    local _ENV = {}

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        _ENV.key = 123 -- SETTABLE
    end)

    assert(issecurevariable(_ENV, "key"), "expected '_ENV.key' to be secure")
end)

-- This test verifies that the SETUPVAL operation does not unexpectedly taint
-- written values while secure.
case("OP_SETUPVAL: Write secure value", function()
    local _ENV = {}
    local upval

    securecall(function()
        upval = "test" -- LOADK, SETUPVAL
    end)

    securecall(function()
        _ENV.value = upval -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "value"), "expected '_ENV.value' to be secure")
end)

-- This test verifies that the SETUPVAL operation writes tainted values when
-- the execution stack is insecure.
case("OP_SETUPVAL: Write tainted value", function()
    local _ENV = {}
    local upval

    securecall(function()
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        upval = "test" -- LOADK, SETUPVAL
    end)

    securecall(function()
        _ENV.value = upval -- GETUPVAL, SETTABLE
    end)

    assert(not issecurevariable(_ENV, "value"), "expected '_ENV.value' to be insecure")
end)

-- This test verifies that the SETUPVAL operation does **not** taint secure
-- values stored in upvalues if written from an insecure context.
case("OP_SETUPVAL: Write secure value from tainted context", function()
    local _ENV = {}
    local upval

    securecall(function()
        local value = "test" -- LOADK
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        upval = value -- SETUPVAL
    end)

    securecall(function()
        _ENV.value = upval -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "value"), "expected '_ENV.value' to be secure")
end)

-- This test verifies that the ADD operation correctly taints its result if
-- executed on secure values in an insecure context.
case("OP_ADD: Evaluate in tainted context", function()
    local _ENV = {}

    securecall(function()
        local a = 1 -- LOADK
        _ENV.a = a -- GETUPVAL, SETTABLE
        local b = 2 -- LOADK
        _ENV.b = b -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local c = a + b -- ADD
        _ENV.c = c -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "a"), "expected '_ENV.a' to be secure")
    assert(issecurevariable(_ENV, "b"), "expected '_ENV.b' to be secure")
    assert(not issecurevariable(_ENV, "c"), "expected '_ENV.c' to be tainted")
end)

-- This test verifies that the SUB operation correctly taints its result if
-- executed on secure values in an insecure context.
case("OP_SUB: Evaluate in tainted context", function()
    local _ENV = {}

    securecall(function()
        local a = 1 -- LOADK
        _ENV.a = a -- GETUPVAL, SETTABLE
        local b = 2 -- LOADK
        _ENV.b = b -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local c = a - b -- SUB
        _ENV.c = c -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "a"), "expected '_ENV.a' to be secure")
    assert(issecurevariable(_ENV, "b"), "expected '_ENV.b' to be secure")
    assert(not issecurevariable(_ENV, "c"), "expected '_ENV.c' to be tainted")
end)

-- This test verifies that the MUL operation correctly taints its result if
-- executed on secure values in an insecure context.
case("OP_MUL: Evaluate in tainted context", function()
    local _ENV = {}

    securecall(function()
        local a = 1 -- LOADK
        _ENV.a = a -- GETUPVAL, SETTABLE
        local b = 2 -- LOADK
        _ENV.b = b -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local c = a * b -- MUL
        _ENV.c = c -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "a"), "expected '_ENV.a' to be secure")
    assert(issecurevariable(_ENV, "b"), "expected '_ENV.b' to be secure")
    assert(not issecurevariable(_ENV, "c"), "expected '_ENV.c' to be tainted")
end)

-- This test verifies that the DIV operation correctly taints its result if
-- executed on secure values in an insecure context.
case("OP_DIV: Evaluate in tainted context", function()
    local _ENV = {}

    securecall(function()
        local a = 1 -- LOADK
        _ENV.a = a -- GETUPVAL, SETTABLE
        local b = 2 -- LOADK
        _ENV.b = b -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local c = a / b -- DIV
        _ENV.c = c -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "a"), "expected '_ENV.a' to be secure")
    assert(issecurevariable(_ENV, "b"), "expected '_ENV.b' to be secure")
    assert(not issecurevariable(_ENV, "c"), "expected '_ENV.c' to be tainted")
end)

-- This test verifies that the MOD operation correctly taints its result if
-- executed on secure values in an insecure context.
case("OP_MOD: Evaluate in tainted context", function()
    local _ENV = {}

    securecall(function()
        local a = 1 -- LOADK
        _ENV.a = a -- GETUPVAL, SETTABLE
        local b = 2 -- LOADK
        _ENV.b = b -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local c = a % b -- MOD
        _ENV.c = c -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "a"), "expected '_ENV.a' to be secure")
    assert(issecurevariable(_ENV, "b"), "expected '_ENV.b' to be secure")
    assert(not issecurevariable(_ENV, "c"), "expected '_ENV.c' to be tainted")
end)

-- This test verifies that the POW operation correctly taints its result if
-- executed on secure values in an insecure context.
case("OP_POW: Evaluate in tainted context", function()
    local _ENV = {}

    securecall(function()
        local a = 1 -- LOADK
        _ENV.a = a -- GETUPVAL, SETTABLE
        local b = 2 -- LOADK
        _ENV.b = b -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local c = a ^ b -- POW
        _ENV.c = c -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "a"), "expected '_ENV.a' to be secure")
    assert(issecurevariable(_ENV, "b"), "expected '_ENV.b' to be secure")
    assert(not issecurevariable(_ENV, "c"), "expected '_ENV.c' to be tainted")
end)

-- This test verifies that the UNM operation correctly taints its result if
-- executed on secure values in an insecure context.
case("OP_UNM: Evaluate in tainted context", function()
    local _ENV = {}

    securecall(function()
        local a = 1 -- LOADK
        _ENV.a = a -- GETUPVAL, SETTABLE
        forceinsecure() -- GETGLOBAL, CALL
        -- Stack tainted! --
        local b = -a -- UNM
        _ENV.b = b -- GETUPVAL, SETTABLE
    end)

    assert(issecurevariable(_ENV, "a"), "expected '_ENV.a' to be secure")
    assert(not issecurevariable(_ENV, "b"), "expected '_ENV.b' to be tainted")
end)

-- This test verifies that taint present at the time of creation of a coroutine
-- has no effect when starting or resuming the thread at a later time if the
-- main closure of the coroutine itself is a secure closure.
case("Coroutines: Create tainted coroutine with secure closure", function()
    local comain = function()
        assert(issecure(), "expected coroutine thread to start securely")
        coroutine.yield()
        assert(issecure(), "expected coroutine thread to resume securely")
    end

    local thread = securecall(function()
        forceinsecure()
        return coroutine.create(comain)
    end)
    assert(issecure(), "expected main thread to be initially secure")
    assert(coroutine.resume(thread))
    assert(issecure(), "expected main thread to remain secure after first yield")
    assert(coroutine.resume(thread))
    assert(issecure(), "expected main thread to remain secure after coroutine finish")
    assert(coroutine.status(thread) == "dead", "expected coroutine thread to be dead")
end)

-- This test verifies that starting a coroutine from a tainted context will
-- propagate to the child thread. Additionally, this verifies that later
-- resuming the thread securely does _not_ taint further execution in the thread.
case("Coroutines: Start coroutine from tainted thread", function()
    local comain = function()
        assert(not issecure(), "expected coroutine thread to start insecurely")
        coroutine.yield()
        assert(issecure(), "expected coroutine thread to resume securely")
    end

    local thread = coroutine.create(comain)
    assert(issecure(), "expected main thread to be initially secure")
    securecall(function()
        forceinsecure()
        coroutine.resume(thread)
    end)
    assert(issecure(), "expected main thread to remain secure after first yield")
    assert(coroutine.resume(thread))
    assert(issecure(), "expected main thread to remain secure after coroutine finish")
    assert(coroutine.status(thread) == "dead", "expected coroutine thread to be dead")
end)

-- This test verifies that resuming a coroutine from an insecure parent thread
-- propagates taint to the resumed thread.
case("Coroutines: Resume coroutine from tainted thread", function()
    local comain = function()
        assert(issecure(), "expected coroutine thread to start securely")
        coroutine.yield()
        assert(not issecure(), "expected coroutine thread to resume insecurely")
    end

    local thread = coroutine.create(comain)
    assert(issecure(), "expected main thread to be initially secure")
    assert(coroutine.resume(thread))
    assert(issecure(), "expected main thread to remain secure after first yield")
    securecall(function()
        forceinsecure()
        coroutine.resume(thread)
    end)
    assert(issecure(), "expected main thread to remain secure after coroutine finish")
    assert(coroutine.status(thread) == "dead", "expected coroutine thread to be dead")
end)

-- This test verifies that taint propagates from an insecure child thread back
-- to its secure parent when yielding.
case("Coroutines: Yield coroutine while tainted", function()
    local comain = function()
        assert(issecure(), "expected coroutine thread to start securely")
        forceinsecure()
        coroutine.yield()
    end

    local thread = coroutine.create(comain)
    assert(issecure(), "expected main thread to be initially secure")
    assert(coroutine.resume(thread))
    assert(not issecure(), "expected main thread to be tainted after first yield")
    assert(coroutine.status(thread) == "suspended", "expected coroutine thread to be suspended")
end)

-- This test verifies that taint propagates from an insecure child thread back
-- to its secure parent when returning.
case("Coroutines: Return from coroutine while tainted", function()
    local comain = function()
        assert(issecure(), "expected coroutine thread to start securely")
        forceinsecure()
    end

    local thread = coroutine.create(comain)
    assert(issecure(), "expected main thread to be initially secure")
    assert(coroutine.resume(thread))
    assert(not issecure(), "expected main thread to be tainted after finishing")
    assert(coroutine.status(thread) == "dead", "expected coroutine thread to be dead")
end)

-- This test verifies that resuming a coroutine that previously yielded
-- insecurely will - if resumed from a secure context - then execute securely.
case("Coroutines: Resume tainted coroutine from secure thread", function()
    local comain = function()
        forceinsecure()
        assert(not issecure(), "expected coroutine thread to be tainted before yield")
        coroutine.yield()
        assert(issecure(), "expected coroutine thread to resume securely")
    end

    local thread = coroutine.create(comain)
    assert(issecure(), "expected main thread to be initially secure")
    securecall(coroutine.resume, thread)
    assert(issecure(), "expected main thread to remain secure after first yield")
    assert(coroutine.resume(thread))
    assert(issecure(), "expected main thread to remain secure after coroutine finish")
    assert(coroutine.status(thread) == "dead", "expected coroutine thread to be dead")
end)

-- This test verifies that starting and resuming a closure that has an insecure
-- closure as its main function will taint execution.
case("Coroutines: Create secure coroutine with tainted closure", function()
    local comain = securecall(function()
        forceinsecure()

        return function()
            assert(not issecure(), "expected coroutine thread to start insecurely")
            coroutine.yield()
            assert(not issecure(), "expected coroutine thread to resume insecurely")
        end
    end)

    local thread = coroutine.create(comain)
    assert(issecure(), "expected main thread to be initially secure")
    assert(coroutine.resume(thread))
    assert(not issecure(), "expected main thread to be tainted after first yield")
    assert(coroutine.resume(thread))
    assert(not issecure(), "expected main thread to be tainted after coroutine finish")
    assert(coroutine.status(thread) == "dead", "expected coroutine thread to be dead")
end)

-- This test verifies that starting and resuming a coroutine whose main function
-- is an insecure closure will always taint, even if the parent thread is fully
-- secure.
case("Coroutines: Resume secure coroutine with tainted closure", function()
    local comain = securecall(function()
        forceinsecure()

        return function()
            assert(not issecure(), "expected coroutine thread to start insecurely")
            coroutine.yield()
            assert(not issecure(), "expected coroutine thread to resume insecurely")
        end
    end)

    local thread = coroutine.create(comain)
    assert(issecure(), "expected main thread to be initially secure")
    securecall(coroutine.resume, thread)
    assert(issecure(), "expected main thread to remain secure after first yield")
    securecall(coroutine.resume, thread)
    assert(issecure(), "expected main thread to remain secure after coroutine finish")
    assert(coroutine.status(thread) == "dead", "expected coroutine thread to be dead")
end)

-- This test verifies that the insecure insertion of a new entry into the
-- table results in the assigned key being cleansed of taint, and thus secure.
case("Tables: Keys are always secure", function()
    local t = {}
    local k = "foo"

    local function setinsecure()
        forceinsecure()
        t[k] = true
    end

    securecall(setinsecure)

    assert(issecure())
    assert(issecurevariable(t, k))
    assert(t[k] ~= nil)
    assert(next(t) ~= nil)
    assert(issecure())
end)

-- This test verifies that table accesses which go through a tainted '__index'
-- metatable field don't taint the caller.
case("Metatables: Read secure value through tainted '__index'", function()
    local proxy = {}
    local store = { foo = 1 }

    securecall(function()
        forceinsecure()
        setmetatable(proxy, { __index = store })
    end)

    assert(issecure(), "expected execution to start securely")
    globalfoo = proxy.foo
    assert(issecure(), "expected execution to remain secure after reading 'proxy.foo'")
    assert(issecurevariable("globalfoo"), "expected 'globalfoo' to be secure")
    assert(globalfoo == 1, "expected 'globalfoo' to be '1'")
end)

-- This test verifies that reads which go through metatables and access tainted
-- values will propagate taint back to the caller.
case("Metatables: Read tainted value from '__index'", function()
    local proxy = {}
    local store = {}

    securecall(function()
        forceinsecure()
        rawset(store, "foo", 1)
        setmetatable(proxy, { __index = store })
    end)

    assert(issecure(), "expected execution to start securely")
    assert(not issecurevariable(proxy, "foo"), "expected 'proxy.foo' to be tainted")
    globalfoo = proxy.foo
    assert(not issecure(), "expected execution to taint after reading 'proxy.foo'")
    assert(not issecurevariable("globalfoo"), "expected 'globalfoo' to be tainted")
    assert(globalfoo == 1, "expected 'globalfoo' to be '1'")
end)

-- This test verifies that writes through a tainted '__newindex' metatable field
-- will taint the calling context. This differs from '__index' behavior which
-- does not taint the caller.
--
-- One additional thing to note is that while execution will taint, the value
-- written to the backing 'store' table will _not_ be tainted.
case("Metatables: Write secure value through tainted '__newindex'", function()
    local proxy = {}
    local store = {}

    securecall(function()
        forceinsecure()
        setmetatable(proxy, { __newindex = store })
    end)

    assert(issecure(), "expected execution to start securely")
    proxy.foo = 1
    assert(not issecure(), "expected execution to taint after writing 'proxy.foo'")
    assert(issecurevariable(store, "foo"), "expected 'proxy.foo' to be secure")
    assert(store.foo == 1, "expected 'store.foo' to be '1'")
end)

-- This test verifies compatibility with changes in patch 10.1 whereby taint
-- can no longer propagate outside of the execution of a '__gc' metamethod.
case("Metatables: Taint during '__gc' metamethod", function()
    local object = newproxy(true)
    local collected = false
    getmetatable(object).__gc = function()
        collected = true
        forceinsecure()
    end

    assert(issecure(), "expected execution to start securely")
    object = nil
    collectgarbage("collect")
    assert(collected, "expected userdata to be garbage collected")
    assert(issecure(), "expected execution to not taint after garbage collection")
end)

-- This test verifies compatibility with changes in patch 10.1 whereby '__gc'
-- metamethods can no longer call debuglocals/debugstack.
case("Metatables: Debug collection during '__gc' metamethod", function()
    local object = newproxy(true)
    local collected = false
    local stack
    local locals

    getmetatable(object).__gc = function()
        collected = true
        stack = debugstack()
        locals = debuglocals()
    end

    object = nil
    collectgarbage("collect")
    assert(collected, "expected userdata to be garbage collected")
    assert(stack == nil, "expected stack trace to be nil")
    assert(locals == nil, "expected locals dump to be nil")
end)

-- This test verifies that replacing the environment of a secure function
-- from a tainted context will taint the function, causing future queries
-- for the function environment to then taint their accessors.
case("getfenv: Read tainted environment", function()
    local function setenv(func)
        local env = {}
        forceinsecure()
        setfenv(func, env)
    end

    local func = function() end

    securecall(setenv, func)
    securecall(function()
        local _ = getfenv(func)
        assert(not issecure(), "expected context to be tainted")
    end)
end)

-- This test verifies that execution remains secure when querying a function
-- environment even if the metatable applied to its table is an insecure
-- table.
case("getfenv: Read secure environment with tainted metatable", function()
    local function setenv(func)
        local env = {}
        setfenv(func, env)
        forceinsecure()
        local meta = {}
        setmetatable(env, meta)
    end

    local func = function() end

    securecall(setenv, func)
    securecall(function()
        local _ = getfenv(func)
        assert(issecure(), "expected context to be secure")
    end)
end)

-- This test verifies that 'getfenv' honors the custom '__environment' field
-- present on function environment metatables and that 'setfenv' cannnot
-- later replace the environment on the function.
case("getfenv: Read function environment with '__environment' metatable key", function()
    local func = function() end
    setfenv(func, setmetatable({}, { __environment = false }))
    assert(getfenv(func) == false, "expected getfenv on 'func' to return 'false'")
    assert(not pcall(setfenv, func, _G), "expected setfenv on 'func' to fail")
end)

-- This test verifies that when a function has a custom environment with a
-- secure '__environment' key that accessing the environment will not taint
-- execution even if the environment was applied to the function from an
-- insecure context.
case("getfenv: Read tainted environment with secure '__environment' key", function()
    local function setenv(func)
        local env = {}
        local meta = {}
        forceinsecure()
        setfenv(func, setmetatable(env, meta))
        meta.__environment = false -- This is secure; see 'op_settable_constant_tainted_context'.
    end

    local func = function() end

    securecall(setenv, func)
    securecall(function()
        local _ = getfenv(func)
        assert(issecure(), "expected context to be secure")
    end)
end)

-- This test verifies that querying overridden function environments with
-- tainted '__environment' metatable keys will taint execution.
case("getfenv: Read secure environment with tainted '__environment' key", function()
    local function setenv(func)
        local env = {}
        local meta = {}
        setfenv(func, setmetatable(env, meta))
        forceinsecure()
        meta.__environment = {}
    end

    local func = function() end

    securecall(setenv, func)
    securecall(function()
        local _ = getfenv(func)
        assert(not issecure(), "expected context to be tainted")
    end)
end)

-- This test verifies compatibility with changes in patch 10.1 whereby '__gc'
-- metamethods can no longer call debuglocals/debugstack.
case("getfenv: Returns nil inside '__gc' metamethods", function()
    local object = newproxy(true)
    local collected = false
    local env

    getmetatable(object).__gc = function()
        collected = true
        env = getfenv(1)
    end

    object = nil
    collectgarbage("collect")
    assert(collected, "expected userdata to be garbage collected")
    assert(env == nil, "expected queried environment to be nil")
end)

-- This test verifies that changing the environment of a secure caller from
-- a tainted context doesn't propagate taint back to any callers.
case("setfenv: Taint caller environment", function()
    local function inner()
        forceinsecure()
        setfenv(3, _G)
    end

    local function main()
        securecall(inner)
        assert(issecure(), "expected to return from 'inner' securely")
    end

    assert(issecure(), "expected to start initially secure")
    main()
    assert(issecure(), "expected to return from 'main' securely")
end)

-- This test verifies that changing the environment of a secure caller from
-- a tainted context propagates back to the caller if they later call any
-- secure Lua function.
--
-- This differs from behavior when C calls are involved; see the 'ccall'
-- variant of this test.
case("setfenv: Taint caller environment with Lua call", function()
    local function inner()
        forceinsecure()
        setfenv(3, _G)
    end

    local function lfunc() end

    local function main()
        securecall(inner)
        assert(issecure(), "expected to return from 'inner' securely")
        lfunc()
        assert(not issecure(), "expected to return from 'lfunc' insecurely")
    end

    assert(issecure(), "expected to start initially secure")
    main()
    assert(not issecure(), "expected to return from 'main' insecurely")
end)

-- This test verifies that changing the environment of a secure caller from
-- a tainted context doesn't propagate taint back to the caller if they later
-- call other (secure) C functions.
--
-- This differs from behavior when Lua calls are involved; see the 'lcall'
-- variant of this test.
case("setfenv: Taint caller environment with C call", function()
    local function inner()
        forceinsecure()
        setfenv(3, _G)
    end

    local function main()
        securecall(inner)
        assert(issecure(), "expected to return from 'inner' securely")
        tostring("")
        assert(issecure(), "expected to return from 'tostring' securely")
    end

    assert(issecure(), "expected to start initially secure")
    main()
    assert(issecure(), "expected to return from 'main' securely")
end)

case("table.contains: searches all table values", function()
    assert(table.contains({ first = "alpha", [4] = "beta" }, "beta"))
    assert(not table.contains({ first = "alpha", [4] = "beta" }, "missing"))
end)

case("table.count: counts array and non-array entries", function()
    assert(table.count({ "alpha", "beta", named = "gamma" }) == 3)
    assert(table.count({}) == 0)
end)

case("table.create: returns an empty table", function()
    local created = table.create(3, 2)
    assert(type(created) == "table")
    assert(next(created) == nil)
end)

case("table.freeze: returns the supplied table and preserves reads", function()
    local values = { "alpha", named = "beta" }
    assert(table.isfrozen(values) == false)
    assert(table.freeze(values) == values)
    assert(table.isfrozen(values) == true)
    assert(table.freeze(values) == values)
    assert(table.isfrozen(values) == true)
    assert(values[1] == "alpha" and values.named == "beta")
    assert(rawget(values, "named") == "beta")
    assert(#values == 1)
    assert(table.count(values) == 2)
end)

case("table.freeze: rejects ordinary writes without changing contents", function()
    local values = table.freeze({ "alpha", named = "beta" })
    local writes = {
        function() values[1] = "changed" end,
        function() values.named = "changed" end,
        function() values[2] = "new" end,
        function() values.missing = "new" end,
        function() values.named = nil end,
        function() values.named = "beta" end,
        function() values.missing = nil end,
    }

    for index, write in ipairs(writes) do
        assert(not pcall(write), "expected frozen write " .. index .. " to fail")
        assert(values[1] == "alpha" and values.named == "beta")
        assert(values[2] == nil and values.missing == nil)
        assert(table.count(values) == 2)
    end
end)

case("table.freeze: rejects raw writes even with __newindex", function()
    local calls = 0
    local values = setmetatable({ "alpha", named = "beta" }, {
        __newindex = function() calls = calls + 1 end,
    })
    table.freeze(values)

    for _, key in ipairs({ 1, 2, "named", "missing" }) do
        assert(not pcall(rawset, values, key, "changed"))
        assert(not pcall(rawset, values, key, nil))
    end

    assert(calls == 0)
    assert(values[1] == "alpha" and values.named == "beta")
    assert(values[2] == nil and values.missing == nil)
    assert(table.count(values) == 2)
end)

case("table.freeze: forwards existing and missing keys to __newindex function", function()
    local calls = {}
    local values = setmetatable({ "alpha", named = "beta" }, {
        __newindex = function(object, key, value)
            calls[#calls + 1] = { object = object, key = key, value = value }
        end,
    })
    table.freeze(values)
    values[1] = "changed"
    values.named = "changed"
    values.missing = "new"
    values.named = nil

    assert(#calls == 4)
    assert(calls[1].object == values and calls[1].key == 1 and calls[1].value == "changed")
    assert(calls[2].object == values and calls[2].key == "named" and calls[2].value == "changed")
    assert(calls[3].object == values and calls[3].key == "missing" and calls[3].value == "new")
    assert(calls[4].object == values and calls[4].key == "named" and calls[4].value == nil)
    assert(values[1] == "alpha" and values.named == "beta")
    assert(rawget(values, "missing") == nil)
end)

case("table.freeze: forwards existing and missing keys to __newindex table", function()
    local store = { named = "old" }
    local values = setmetatable({ "alpha", named = "beta" }, { __newindex = store })
    table.freeze(values)
    values[1] = "changed"
    values.named = "changed"
    values.missing = "new"

    assert(store[1] == "changed" and store.named == "changed" and store.missing == "new")
    values.named = nil
    assert(store.named == nil)
    assert(values[1] == "alpha" and values.named == "beta")
    assert(rawget(values, "missing") == nil)
end)

case("table.freeze: prevents metatable replacement and removal", function()
    local metatable = {}
    local values = table.freeze(setmetatable({}, metatable))
    assert(getmetatable(values) == metatable)
    assert(not pcall(setmetatable, values, {}))
    assert(not pcall(setmetatable, values, nil))
    local ok, result = pcall(setmetatable, values, metatable)
    assert(not ok)
    assert(string.find(result, "attempted to replace metatable of a frozen table", 1, true))
    assert(getmetatable(values) == metatable)

    local plain = table.freeze({})
    assert(not pcall(setmetatable, plain, {}))
    assert(getmetatable(plain) == nil)
end)

case("table.freeze: weak values can still be collected", function()
    local values = setmetatable({}, { __mode = "v" })
    do
        local arrayValue, namedValue = {}, {}
        values[1], values.named = arrayValue, namedValue
        table.freeze(values)
        assert(values[1] == arrayValue and values.named == namedValue)
    end

    collectgarbage("collect")
    collectgarbage("collect")
    assert(table.isfrozen(values) == true)
    assert(values[1] == nil and values.named == nil)
end)

case("table.freeze: forwards writes through __newindex added after freezing", function()
    local store = {}
    local metatable = {}
    local values = table.freeze(setmetatable({ named = "original" }, metatable))
    metatable.__newindex = store
    values.named = "changed"
    assert(store.named == "changed")
    assert(values.named == "original")
end)

case("table.freeze: wipe permits empty tables and rejects populated tables without forwarding", function()
    for _, populated in ipairs({ false, true }) do
        for _, forwarding in ipairs({ false, true }) do
            local calls = 0
            local values = populated and { "alpha", named = "beta" } or {}
            if forwarding then
                setmetatable(values, {
                    __newindex = function() calls = calls + 1 end,
                })
            end
            table.freeze(values)
            local ok, result = pcall(table.wipe, values)
            assert(ok == not populated)
            if populated then
                assert(string.find(result, "attempted to perform indexed assignment on a frozen table", 1, true))
                assert(values[1] == "alpha" and values.named == "beta")
                assert(table.count(values) == 2)
            else
                assert(result == values)
                assert(next(values) == nil)
            end
            assert(calls == 0)
            assert(table.isfrozen(values) == true)
        end
    end
end)

case("table.freeze: insert rejects empty and populated frozen tables", function()
    for _, populated in ipairs({ false, true }) do
        local values = table.freeze(populated and { "beta", "alpha" } or {})
        local ok, result = pcall(table.insert, values, "new")
        assert(not ok)
        assert(string.find(result, "attempted to perform indexed assignment on a frozen table", 1, true))
        if populated then
            assert(values[1] == "beta" and values[2] == "alpha" and #values == 2)
        else
            assert(next(values) == nil)
        end
        assert(table.isfrozen(values) == true)
    end
end)

case("table.indexof: returns the first matching array index", function()
    assert(table.indexof({ "alpha", "beta", "alpha" }, "alpha") == 1)
    assert(table.indexof({ "alpha", "beta", "gamma" }, "missing") == nil)
end)

case("table.keys: returns all keys", function()
    local keys = table.keys({ alpha = 1, [4] = 2 })
    local foundAlpha, foundFour
    for _, key in ipairs(keys) do
        foundAlpha = foundAlpha or key == "alpha"
        foundFour = foundFour or key == 4
    end
    assert(#keys == 2)
    assert(foundAlpha and foundFour)
end)

case("table.getcountinfo: reports entry and positive integer key counts", function()
    local entries, positiveIntegerKeys, maxPositiveIntegerKey = table.getcountinfo({ [1] = "one", [3] = "three", [2.5] = "fraction", named = "value" })
    assert(entries == 4)
    assert(positiveIntegerKeys == 2)
    assert(maxPositiveIntegerKey == 3)

    entries, positiveIntegerKeys, maxPositiveIntegerKey = table.getcountinfo({})
    assert(entries == 0 and positiveIntegerKeys == 0 and maxPositiveIntegerKey == 0)
end)

case("table.values: returns all values", function()
    local values = table.values({ alpha = "one", [4] = "four" })
    local foundOne, foundFour
    for _, value in ipairs(values) do
        foundOne = foundOne or value == "one"
        foundFour = foundFour or value == "four"
    end
    assert(#values == 2)
    assert(foundOne and foundFour)
end)

case("table.isempty: reports whether a table has entries", function()
    assert(table.isempty({}))
    assert(not table.isempty({ value = false }))
end)

case("table.removeunordered: removes an indexed value", function()
    local values = { "alpha", "beta", "gamma" }
    assert(table.removeunordered(values, 2) == "beta")
    assert(#values == 2)
    assert(values[1] == "alpha" and values[2] == "gamma")
end)

case("table.removevalue: removes all matching array values", function()
    local values = { "remove", "keep", "remove", "remove", "last" }
    assert(table.removevalue(values, "remove") == 3)
    assert(#values == 2)
    assert(values[1] == "keep" and values[2] == "last")
end)

case("dumpobject: invokes the __dump metamethod", function()
    local object = setmetatable({}, {
        __dump = function(value)
            assert(type(value) == "table")
            return "dumped"
        end,
    })

    assert(dumpobject(object) == "dumped")
end)

case("mapvalues: maps each supplied value", function()
    local first, second = mapvalues(function(value) return value * 2 end, 3, 5)
    assert(first == 6 and second == 10)
end)

case("Mixin: copies mixin fields onto and returns the object", function()
    local object = { original = true }
    local result = Mixin(object, { first = "one" }, { second = "two" })

    assert(result == object)
    assert(result.original and result.first == "one" and result.second == "two")
end)

case("CreateFromMixins: creates an object from mixins", function()
    local object = CreateFromMixins({ first = "one" }, { second = "two" })

    assert(type(object) == "table")
    assert(object.first == "one" and object.second == "two")
end)

case("securecallmethod: invokes a raw method and returns its results", function()
    local object = {
        value = 5,
        add = function(self, amount)
            return self.value + amount, "done"
        end,
    }

    local value, status = securecallmethod(object, "add", 3)
    assert(value == 8 and status == "done")
end)

case("securecallmethod: callee does not taint caller", function()
    local object = {
        run = function()
            forceinsecure()
            assert(not issecure())
        end,
    }

    securecallmethod(object, "run")
    assert(issecure())
end)

case("securecallmethod: method lookup does not taint caller", function()
    local object = {}
    local function run()
        assert(not issecure())
    end

    securecall(function()
        forceinsecure()
        local method = run
        object.run = method
    end)

    assert(not issecurevariable(object, "run"))
    assert(issecure())
    securecallmethod(object, "run")
    assert(issecure())
end)

case("securecallmethod: ignores methods inherited through __index", function()
    local object = setmetatable({}, {
        __index = {
            run = function()
                return true
            end,
        },
    })

    local origerrorhandler = geterrorhandler()
    local lasterror

    seterrorhandler(function(err) lasterror = err end)
    local resultCount = select("#", securecallmethod(object, "run"))
    seterrorhandler(origerrorhandler)

    assert(resultCount == 0)
    assert(type(lasterror) == "string", "expected an error reported through the global error handler")
    assert(string.find(lasterror, "attempt to call a nil value", 1, true), lasterror)
end)

case("math.clamp: clamps to an inclusive range", function()
    assert(math.clamp(5, 0, 10) == 5)
    assert(math.clamp(-5, 0, 10) == 0)
    assert(math.clamp(15, 0, 10) == 10)
end)

case("math.clamp: returns maximum when minimum exceeds it", function()
    assert(math.clamp(0, 100, 50) == 50)
end)

case("math.huge: equals positive infinity from division by zero", function()
    assert(math.huge == 1 / 0, "expected 'math.huge' to be positive infinity")
end)

case("math.isfinite: rejects infinity and NaN", function()
    local nan = -math.sin(math.huge)
    assert(math.isfinite(1))
    assert(not math.isfinite(math.huge))
    assert(not math.isfinite(nan))
end)

case("math.isinf: recognizes positive and negative infinity", function()
    assert(math.isinf(math.huge))
    assert(math.isinf(-math.huge))
    assert(not math.isinf(1))
end)

case("math.isnan: recognizes NaN", function()
    assert(math.isnan(-math.sin(math.huge)))
    assert(not math.isnan(1))
end)

case("math.lerp: interpolates and extrapolates", function()
    assert(math.lerp(10, 20, 0.25) == 12.5)
    assert(math.lerp(10, 20, 2) == 30)
end)

case("math.normalize: maps a range to relative positions", function()
    assert(math.normalize(15, 10, 20) == 0.5)
    assert(math.normalize(5, 10, 20) == -0.5)
end)

case("math.remap: maps between ranges and extrapolates", function()
    assert(math.remap(5, 0, 10, 20, 40) == 30)
    assert(math.remap(15, 0, 10, 20, 40) == 50)
end)

case("math.round: rounds halfway values away from zero", function()
    assert(math.round(1.5) == 2)
    assert(math.round(-1.5) == -2)
    assert(math.round(125, -1) == 130)
end)

case("math.saturate: clamps to the unit range", function()
    assert(math.saturate(-1) == 0)
    assert(math.saturate(0.5) == 0.5)
    assert(math.saturate(2) == 1)
end)

case("math.sign: returns the sign of a value", function()
    assert(math.sign(-5) == -1)
    assert(math.sign(0) == 0)
    assert(math.sign(5) == 1)
end)

case("math.wrap: wraps into a half-open range", function()
    assert(math.wrap(370, 0, 360) == 10)
    assert(math.wrap(-10, 0, 360) == 350)
    assert(math.wrap(360, 0, 360) == 0)
    assert(math.wrap(7, 7, 7) == 7)
end)

case("string.ltrim: removes specified characters from the start", function()
    assert(string.ltrim(" \t--value-- ", " \t-") == "value-- ")
    assert(string.ltrim("value", "x") == "value")
end)

case("string.rtrim: removes specified characters from the end", function()
    assert(string.rtrim(" --value-- \t", " \t-") == " --value")
    assert(string.rtrim("value", "x") == "value")
end)

case("string.trim: removes specified characters from both ends", function()
    assert(string.trim(" \t--value-- \t", " \t-") == "value")
    assert(string.trim("value", "x") == "value")
end)

case("string.contains: searches for a literal substring", function()
    assert(string.contains("a.b.c", "."))
    assert(not string.contains("a.b.c", "%"))
end)

case("string.endswith: checks the suffix", function()
    assert(string.endswith("hello/world", "world"))
    assert(not string.endswith("hello/world", "World"))
end)

case("string.startswith: checks the prefix", function()
    assert(string.startswith("hello/world", "hello"))
    assert(not string.startswith("hello/world", "Hello"))
end)

case("string.trim: handles null bytes", function()
    assert(string.trim("\000 alpha \000", "\000 ") == "alpha")
    assert(string.ltrim("\000 alpha \000", "\000 ") == "alpha \000")
    assert(string.rtrim("\000 alpha \000", "\000 ") == "\000 alpha")
    assert(string.trim(" \000alpha\000 ", " ") == "\000alpha\000")
end)

case("string.join: validates the separator", function()
    local ok, err = pcall(string.join)
    assert(not ok)
    assert(err == "bad argument #1 to '?' (string expected, got no value)", err)

    ok, err = pcall(string.join, nil, "alpha", "beta")
    assert(not ok)
    assert(err == "bad argument #1 to '?' (string expected, got nil)", err)

    assert(string.join(42, "alpha", "beta", "gamma") == "alpha42beta42gamma")
end)

case("string.join: separator only returns an empty string", function()
    assert(string.join(",") == "")
    assert(select("#", string.join(",")) == 1)
end)

case("string.join: returns one value unchanged", function()
    assert(string.join(",", 42) == 42)
    assert(select("#", string.join(",", 42)) == 1)
    assert(string.join(",", nil) == nil)
    assert(select("#", string.join(",", nil)) == 1)
end)

case("string.join: joins strings and numbers", function()
    assert(string.join(",", "alpha", 42, -7, 1.5, "beta") == "alpha,42,-7,1.5,beta")
    assert(select("#", string.join(",", "alpha", 42, -7, 1.5, "beta")) == 1)
    assert(string.join("", 42, -7, 1.5) == "42-71.5")
end)

case("string.join: stack overflow depends on the separator", function()
    local pieces = {}
    for i = 1, 7997 do
        pieces[i] = ""
    end
    assert(string.join("", "", "", "", "", "", "", "", "", "", unpack(pieces)) == "")
    local ok, err = pcall(function()
        return string.join(",", "", "", "", "", "", "", "", "", "", unpack(pieces))
    end)
    assert(not ok)
    -- Exact error message differs in-game. Not aiming for 100% compat here.
    assert(string.find(err, "[Ss]tack overflow"), err)
end)

case("string.join: trailing nil raises a concatenation error", function()
    local ok, err = pcall(string.join, ",", "a", nil)
    assert(not ok)
    assert(err == "attempt to concatenate a nil value", err)
end)

case("string.join: preserves null bytes in separators and pieces", function()
    assert(string.join(",\000/", "alpha", "beta", "gamma") == "alpha,\000/beta,\000/gamma")
    assert(string.join(",", "alpha\000beta", "gamma\000delta") == "alpha\000beta,gamma\000delta")
end)

case("string.join: invokes __concat for first and interior pieces", function()
    local value = setmetatable({}, {
        __concat = function(left, right)
            assert(type(left) == "table" and type(right) == "string")
            return "concatenated"
        end,
    })
    assert(string.join(",", value, "alpha") == "concatenated")
    assert(string.join(",", "alpha", value, "beta") == "alpha,concatenated")
end)

case("string.join: invokes __concat for the last piece", function()
    local value = setmetatable({}, {
        __concat = function(left, right)
            assert(type(left) == "string" and type(right) == "table")
            return "concatenated"
        end,
    })

    assert(string.join(",", "alpha", value) == "alphaconcatenated")
end)

-- This test verifies that the "%d" and "%i" format specifier matches reference
-- behavior where not supplying a value to be formatted doesn't trigger errors.
case("string.format: Missing parameters", function()
    assert(not pcall(string.format, "%c"))
    assert(not pcall(string.format, "%e"))
    assert(string.format("%d") == "0")
    assert(not pcall(string.format, "%f"))
    assert(not pcall(string.format, "%E"))
    assert(not pcall(string.format, "%G"))
    assert(not pcall(string.format, "%g"))
    assert(not pcall(string.format, "%o"))
    assert(string.format("%i") == "0")
    assert(not pcall(string.format, "%s"))
    assert(not pcall(string.format, "%q"))
    assert(not pcall(string.format, "%x"))
    assert(not pcall(string.format, "%u"))
end)

-- This test verifies the added support for Lua 4.x style positional format
-- specifiers of the form "%n$s" which are present in the reference environment.
case("string.format: Positional specifiers", function()
    assert(string.format("%0$d", 1, 2, 3) == "0")
    assert(string.format("%d", 1, 2, 3) == "1")
    assert(string.format("%2$d", 1, 2, 3) == "2")
    assert(string.format("%1$d", 1, 2, 3) == "1")
    assert(string.format("%4$d", 1, 2, 3) == "0")
    assert(string.format("%3$d", 1, 2, 3) == "3")
    assert(string.format("%10$d", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11) == "10")
    assert(string.format("%09$d", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11) == "9")
    assert(string.format("%12$d", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11) == "0")
    assert(string.format("%11$d", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11) == "11")
    assert(string.format("%d %0$d %d", 1, 2, 3) == "1 0 1")
    assert(string.format("%d %d %d", 1, 2, 3) == "1 2 3")
    assert(string.format("%d %2$d %d", 1, 2, 3) == "1 2 3")
    assert(string.format("%d %1$d %d", 1, 2, 3) == "1 1 2")
    assert(not pcall(string.format, "%100$d", 1, 2, 3))
    assert(string.format("%d %3$d %d", 1, 2, 3) == "1 3 0")
    assert(string.format("%11$+22.13f", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -11) == "     -11.0000000000000")
end)

-- This test verifies various quirks with the format implementation in the
-- reference client where repeated use of flags will not result in errors,
-- as well verifying the maximum permissible length of individual format
-- specifiers.
case("string.format: Repeated flags", function()
    assert(string.format("%--++  00##d", 1) == "+1")
    assert(string.format("%--------------11d", 1) == "1          ")
    assert(string.format("%----------------d", 1) == "1")
    assert(not pcall(string.format, "%-----------------d", 1))
    assert(string.format("%-----------11.11d", 1) == "00000000001")
    assert(not pcall(string.format, "%------------11.11d", 1))
    assert(not pcall(string.format, "%---------------11d", 1))
end)

-- Verifies that return values are passed through to the caller properly.
case("securecallfunction: returns values to caller", function()
    local a, b, c = securecallfunction(function()
        return 1, 2, 3
    end)
    assert(a == 1 and b == 2 and c == 3)
    assert(select(
        "#",
        securecallfunction(function()
            return 1, 2, 3
        end)
    ) == 3)
end)

-- Verifies that arguments are passed through to the callee properly.
case("securecallfunction: arguments passed to callee", function()
    assert(securecallfunction(function(...)
        return select("#", ...)
    end, "a", "b", "c") == 3)
end)

-- Verifies that errors do not bubble back through the securecall boundary and
-- are instead routed to the global error handler.
case("securecallfunction: errors forwarded to error handler", function()
    local oldhandler = geterrorhandler()
    local numerrors = 0
    local lasterror = nil
    seterrorhandler(function(...)
        numerrors = numerrors + 1
        lasterror = ...
    end)

    local numreturns = select("#", securecallfunction(error, "error message"))
    seterrorhandler(oldhandler)

    assert(lasterror == "error message")
    assert(numerrors == 1)
    assert(numreturns == 0)
end)

-- Verifies that taint does not propagate back to the caller.
case("securecallfunction: does not taint caller", function()
    securecallfunction(function()
        forceinsecure()
        assert(not issecure())
    end)
    assert(issecure())
end)

-- Verifies that taint does not propagate back to the caller through its returns.
case("securecallfunction: return values do not taint caller", function()
    local a, b, c = securecallfunction(function()
        forceinsecure()
        return 1, 2, 3
    end)
    local _, _, _ = a, b, c
    assert(issecure())
end)

-- Verifies that no global lookups are performed if the given func is a string.
case("securecallfunction: does not perform global lookup", function()
    local errors = 0
    seterrorhandler(function()
        errors = errors + 1
    end)
    securecall("goodfunction")
    assert(errors == 1)
end)

-- Verifies that taint is retained by the callee.
case("securecallfunction: caller taint propagates to callee", function()
    forceinsecure()
    securecallfunction(function()
        assert(not issecure())
    end)
end)

-- Verifies that return values are passed through to the caller properly.
case("securecall: returns values to caller", function()
    local a, b, c = securecall(function()
        return 1, 2, 3
    end)
    assert(a == 1 and b == 2 and c == 3)
    assert(select(
        "#",
        securecall(function()
            return 1, 2, 3
        end)
    ) == 3)
end)

-- Verifies that arguments are passed through to the callee properly.
case("securecall: arguments passed to callee", function()
    assert(securecall(function(...)
        return select("#", ...)
    end, "a", "b", "c") == 3)
end)

-- Verifies that errors do not bubble back through the securecall boundary and
-- are instead routed to the global error handler.
case("securecall: errors forwarded to error handler", function()
    local oldhandler = geterrorhandler()
    local numerrors = 0
    local lasterror = nil
    seterrorhandler(function(...)
        numerrors = numerrors + 1
        lasterror = ...
    end)

    local numreturns = select("#", securecallfunction(error, "error message"))
    seterrorhandler(oldhandler)

    assert(lasterror == "error message")
    assert(numerrors == 1)
    assert(numreturns == 0)
end)

-- Verifies that taint does not propagate back to the caller.
case("securecall: does not taint caller", function()
    securecall(function()
        forceinsecure()
        assert(not issecure())
    end)
    assert(issecure())
end)

-- Verifies that taint does not propagate back to the caller through its returns.
case("securecall: return values do not taint caller", function()
    local a, b, c = securecall(function()
        forceinsecure()
        return 1, 2, 3
    end)
    local _, _, _ = a, b, c
    assert(issecure())
end)

-- Verifies that when supplied with a string value it'll do a lookup in _G and
-- call that function instead.
case("securecall: perform global lookup", function()
    local testcalls = 0
    _G.goodfunction = function()
        testcalls = testcalls + 1
    end

    securecall("goodfunction")
    assert(testcalls == 1)
end)

-- Verifies that taint on a global lookup doesn't propagate back to the caller.
case("securecall: global lookups do not taint caller", function()
    securecall(function()
        forceinsecure()
        _G.evilfunction = function() end
    end)
    securecall("evilfunction")

    assert(not issecurevariable("evilfunction"))
    assert(issecure())
end)

-- Verifies that taint applied from the global lookup correctly taints execution
-- of the function to-be-invoked.
case("securecall: tainted global propagates to calleee", function()
    local _ENV = {}

    securecall(function()
        forceinsecure()
        _G.evilfunction = function(a)
            _ENV.a = a
        end
    end)
    securecall("evilfunction")
    assert(not issecurevariable(_ENV, "a"))
end)

-- Verifies that taint is retained by the callee.
case("securecall: caller taint propagates to callee", function()
    forceinsecure()
    securecall(function()
        assert(not issecure())
    end)
end)

case("secureexecuterange: calls function for each entry in table", function()
    local ncalls = 0

    local function exec(k, v)
        ncalls = ncalls + 1
        assert(k == ncalls)
        assert(v == tostring(ncalls))
    end

    secureexecuterange({ "1", "2", "3", "4", "5" }, exec)
    assert(ncalls == 5)
end)

case("secureexecuterange: continues if function errors", function()
    local ncalls = 0
    local nerrs = 0

    local oldhandler = geterrorhandler()
    seterrorhandler(function()
        nerrs = nerrs + 1
    end)
    secureexecuterange({ 1, 2, 3, 4, 5 }, function()
        ncalls = ncalls + 1
        error("foo")
    end)
    seterrorhandler(oldhandler)
    assert(ncalls == 5)
    assert(nerrs == 0)
end)

case("secureexecuterange: does not propagate taint from calls", function()
    local function exec()
        assert(issecure())
        forceinsecure()
        assert(not issecure())
    end

    assert(issecure())
    secureexecuterange({ 1, 2, 3, 4, 5 }, exec)
    assert(issecure())
end)

case("secureexecuterange: does not clear taint if called insecurely", function()
    local function exec()
        assert(not issecure())
    end

    forceinsecure()
    assert(not issecure())
    secureexecuterange({ 1, 2, 3, 4, 5 }, exec)
    assert(not issecure())
end)

case("secureexecuterange: passes through additional arguments", function()
    local function exec(k, v, ...)
        assert(type(k) == "number")
        assert(type(v) == "string")
        assert(select("#", ...) == 3)
        assert(select(1, ...) == true)
        assert(select(2, ...) == false)
        assert(type(select(3, ...)) == "userdata")
    end

    secureexecuterange({ "foo", "bar" }, exec, true, false, newproxy(false))
end)

case("secureexecuterange: cannot return values", function()
    local function exec()
        return 1, 2, 3
    end

    assert(select("#", secureexecuterange({ 1, 2, 3 }, exec) == 0))
end)

-- This test verifies that hooksecurefunc calls both functions in the expected
-- order; original first, then posthook.
case("hooksecurefunc: calls both functions in-order", function()
    local ncalls = 0
    _G.hookfunc = function()
        assert(ncalls == 0)
        ncalls = ncalls + 1
    end
    hooksecurefunc("hookfunc", function()
        assert(ncalls == 1)
        ncalls = ncalls + 1
    end)

    _G.hookfunc()
    assert(ncalls == 2)
end)

-- This test verifies that both the original function and the posthook both
-- receive the same arguments.
case("hooksecurefunc: arguments supplied to both prefunc and posthook", function()
    local preargs
    local posargs

    _G.hookfunc = function(...)
        preargs = { n = select("#", ...), ... }
    end
    hooksecurefunc("hookfunc", function(...)
        posargs = { n = select("#", ...), ... }
    end)

    _G.hookfunc("a", "b", "c")

    assert(preargs.n == 3)
    assert(preargs[1] == "a")
    assert(preargs[2] == "b")
    assert(preargs[3] == "c")

    assert(posargs.n == 3)
    assert(posargs[1] == "a")
    assert(posargs[2] == "b")
    assert(posargs[3] == "c")
end)

-- This test verifies that values returned from the posthook never get passed
-- back to the caller.
case("hooksecurefunc: return values come from prefunc", function()
    _G.hookfunc = function()
        return "a", "b", "c"
    end
    hooksecurefunc("hookfunc", function()
        return 1, 2, 3
    end)

    local results = { _G.hookfunc() }
    assert(#results == 3)
    assert(results[1] == "a")
    assert(results[2] == "b")
    assert(results[3] == "c")
end)

-- This test verifies that taint encountered during execution of the posthook
-- does not propagate to the caller.
case("hooksecurefunc: posthook taint does not taint caller", function()
    _G.hookfunc = function() end
    hooksecurefunc("hookfunc", function()
        forceinsecure()
    end)
    _G.hookfunc()

    assert(issecure())
end)

-- This test verifies that if the posthook supplied to hooksecurefunc is
-- a tainted closure, executing it does not spread that taint to the caller.
case("hooksecurefunc: tainted posthook does not taint caller", function()
    _G.hookfunc = function() end
    securecall(function()
        forceinsecure()
        hooksecurefunc("hookfunc", function()
            forceinsecure()
        end)
    end)
    _G.hookfunc()

    assert(issecure())
end)

-- This test verifies that errors in the posthook function are routed to the
-- global error handler and do not interrupt execution of the caller.
case("hooksecurefunc: posthook errors do not propagate", function()
    local prehookcalled = false
    local poshookcalled = false
    local errhandlercalled = false
    local origerrorhandler = geterrorhandler()

    _G.hookfunc = function()
        prehookcalled = true
    end
    hooksecurefunc("hookfunc", function()
        poshookcalled = true
        error("test error")
    end)

    seterrorhandler(function()
        errhandlercalled = true
    end)
    pcall(_G.hookfunc)
    seterrorhandler(origerrorhandler)

    assert(prehookcalled)
    assert(errhandlercalled)
    assert(poshookcalled)
    assert(errhandlercalled)
end)

-- This test verifies that if the original function encounters taint during
-- execution then it will propagate that taint to both the posthook and the
-- caller.
case("hooksecurefunc: prefunc taint propagates to posthook and caller", function()
    _G.hookfunc = function()
        forceinsecure()
    end
    hooksecurefunc("hookfunc", function()
        assert(not issecure())
    end)
    _G.hookfunc()
    assert(not issecure())
end)

-- This test verifies that if the original function is a tainted global closure
-- then calling it will taint execution of both the posthook and the caller.
case("hooksecurefunc: tainted prefunc propagates to posthook and caller", function()
    securecall(function()
        forceinsecure()
        _G.hookfunc = function() end
    end)
    assert(issecure())
    hooksecurefunc("hookfunc", function()
        assert(not issecure())
    end)
    assert(issecure())
    _G.hookfunc()
    assert(not issecure())
end)

-- This test verifies that errors in the original function are fatal to the
-- caller and do not allow the posthook to execute.
case("hooksecurefunc: prefunc errors propagate", function()
    local prehookcalled = false
    local poshookcalled = false

    _G.hookfunc = function()
        prehookcalled = true
        error("test error")
    end
    hooksecurefunc("hookfunc", function()
        poshookcalled = true
    end)

    assert(not pcall(_G.hookfunc))
    assert(prehookcalled)
    assert(not poshookcalled)
end)

-- This test verifies that loadstring taints the caller.
case("loadstring: taints caller", function()
    assert(issecure())
    loadstring("")
    assert(not issecure())
end)

case("loadstring: skips leading UTF-8 BOM", function()
    local func, err = loadstring("\239\187\191return 1")
    assert(func, err)
    assert(func() == 1)
end)

-- This test verifies that loadstring_untainted does not taint the caller.
case("loadstring_untainted: does not taint caller", function()
    assert(issecure())
    loadstring_untainted("")
    assert(issecure())
end)

-- This test verifies that the error handler installed via seterrorhandler can
-- be retrieved correctly.
case("geterrorhandler: returns user-installed error handler", function()
    local origerrorhandler = geterrorhandler()
    local customhandler = function() end
    local retrievedhandler

    seterrorhandler(customhandler)
    retrievedhandler = geterrorhandler()
    seterrorhandler(origerrorhandler)

    assert(retrievedhandler == customhandler)
end)

-- This test verifies that error handlers installed from Lua scripts cannot
-- be invoked with non-string error values.
case("seterrorhandler: converts non-string errors", function()
    local origerrorhandler = geterrorhandler()
    local lasterror

    seterrorhandler(function(err)
        lasterror = err
    end)
    error({})
    seterrorhandler(origerrorhandler)

    assert(lasterror == "UNKNOWN ERROR")
end)

case("seterrorhandler: replaces '*' source with object names", function()
    local origerrorhandler = geterrorhandler()
    local lasterror
    local frame

    if CreateFrame then
        frame = CreateFrame("Frame", "TestFrame")
    else
        frame = { [0] = newproxy(true) }
        getmetatable(frame[0]).__name = function()
            return "TestFrame"
        end
    end

    seterrorhandler(function(err)
        lasterror = err
    end)
    securecall(loadstring("local _ = ...; ImmediateError = ImmediateError + 1", "*:OnBanana"), frame)
    seterrorhandler(origerrorhandler)

    assert(
        lasterror
            == [=[[string "TestFrame:OnBanana"]:1: attempt to perform arithmetic on global 'ImmediateError' (a nil value)]=]
    )
end)

case("seterrorhandler: ignores '*' source if first local is not a named object", function()
    local origerrorhandler = geterrorhandler()
    local lasterror

    local fakeframe = { [0] = newproxy(true) }
    getmetatable(fakeframe[0]).__name = nil

    seterrorhandler(function(err)
        lasterror = err
    end)
    securecall(loadstring("local _ = ...; ImmediateError = ImmediateError + 1", "*:OnBanana"), fakeframe)
    seterrorhandler(origerrorhandler)

    assert(
        lasterror
            == [=[[string "*:OnBanana"]:1: attempt to perform arithmetic on global 'ImmediateError' (a nil value)]=]
    )
end)

case("strsplit: splits strings", function()
    local a, b, c, d, e, f = strsplit(" ", "a b c d e")
    assert(a == "a")
    assert(b == "b")
    assert(c == "c")
    assert(d == "d")
    assert(e == "e")
    assert(f == nil)
end)

case("strsplittable: splits strings", function()
    local tbl = strsplittable(" ", "a b c d e")
    assert(tbl[1] == "a")
    assert(tbl[2] == "b")
    assert(tbl[3] == "c")
    assert(tbl[4] == "d")
    assert(tbl[5] == "e")
    assert(tbl[6] == nil)
end)

case("strsplit: splits strings with multiple delimiters", function()
    assert(select("#", strsplit("- ", "a-b c-d-e", 0)) == 5)
end)

case("strsplit: splits strings with limit", function()
    assert(select("#", strsplit(" ", "a b c d e", 0)) == 5)
    assert(select("#", strsplit(" ", "a b c d e", 1)) == 1)
    assert(select("#", strsplit(" ", "a b c d e", 2)) == 2)
    assert(select("#", strsplit(" ", "a b c d e", 3)) == 3)
    assert(select("#", strsplit(" ", "a b c d e", 4)) == 4)
    assert(select("#", strsplit(" ", "a b c d e", 5)) == 5)
    assert(select("#", strsplit(" ", "a b c d e", 6)) == 5)
end)

case("strsplit: ignores delimiters after null byte", function()
    assert(select("#", strsplit("\000 ", "a b c d e")) == 1)
end)

case("strsplit: ignores string after null byte", function()
    assert(select("#", strsplit(" ", "a \000b c d e")) == 2)
    assert(select("#", strsplit(" ", "a \000b c d e", 3)) == 2)
    assert(select("#", strsplit(" ", "a b\000 c d e", 3)) == 2)
    assert(select("#", strsplit(" ", "a b \000c d e", 3)) == 3)
end)

case("strsplit: ignores empty delimiter string", function()
    assert(select("#", strsplit("", "a b c d e") == 1))
    assert(select("#", strsplit("", "a b c d e", -1) == 1))
    assert(select("#", strsplit("", "a b c d e", 0) == 1))
    assert(select("#", strsplit("", "a b c d e", 1) == 1))
    assert(select("#", strsplit("", "a b c d e", 2) == 1))
end)

case("pcallwithenv: calls function with custom environment", function()
    local wantedenv = { getfenv = getfenv }
    local actualenv

    local function foo(v)
        actualenv = getfenv(1)
    end

    assert(getfenv(foo) == _G, "expected 'foo' to have '_G' as its environment pre-call")

    local ok = pcallwithenv(foo, wantedenv, 100)

    assert(ok, "expected 'pcallwithenv' to execute successfully")
    assert(wantedenv == actualenv, "expected 'foo' to be called with custom environment")
    assert(getfenv(foo) == _G, "expected 'foo' to have '_G' as its environment post-call")
end)

case("pcallwithenv: calls erroring function with custom environment", function()
    local wantedenv = { getfenv = getfenv }
    local actualenv

    local function foo(v)
        actualenv = getfenv(1)
        error("!")
    end

    assert(getfenv(foo) == _G, "expected 'foo' to have '_G' as its environment pre-call")

    local ok = pcallwithenv(foo, wantedenv, 100)

    assert(not ok, "expected 'pcallwithenv' to execute unsuccessfully")
    assert(wantedenv == actualenv, "expected 'foo' to be called with custom environment")
    assert(getfenv(foo) == _G, "expected 'foo' to have '_G' as its environment post-call")
end)

case("pcallwithenv: disallows calls to functions with protected environments", function()
    local foo = setfenv(function() end, setmetatable({}, { __environment = false }))

    local ok, err = pcall(pcallwithenv, foo, {})

    assert(not ok, "expected 'pcallwithenv' to immediately error")
    assert(string.find(err, "protected environment"), "expected 'pcallwithenv' to complain about environments")
end)

case("pcallwithenv: taints secure closures if called insecurely", function()
    local foo = function() end

    securecall(function()
        forceinsecure()
        pcallwithenv(foo, {})
    end)

    assert(issecure(), "expected execution to be initially secure")
    foo()
    assert(not issecure(), "expected execution to taint after executing tainted closure")
end)

case("pcallwithenv: calls function with single parameter and return", function()
    local function f(v)
        return v * 2
    end

    local function foo(v)
        return bar(v)
    end

    local function pack(...)
        return { n = select("#", ...), ... }
    end

    local res = pack(pcallwithenv(foo, { bar = f }, 100))

    assert(res.n == 2, "expected 'pcallwithenv' to return two values")
    assert(res[1], "expected 'pcallwithenv' to execute successfully")
    assert(res[2] == 200, "expected 'pcallwithenv' to return doubled value")
end)

case("pcallwithenv: calls function with multiple parameters and returns", function()
    local function f(a, b, c)
        return c, b, a
    end

    local function foo(a, b, c)
        return bar(a, b, c)
    end

    local function pack(...)
        return { n = select("#", ...), ... }
    end

    local a, b, c = 100, 200, 300
    local res = pack(pcallwithenv(foo, { bar = f }, 100, 200, 300))

    assert(res.n == 4, "expected 'pcallwithenv' to return four values")
    assert(res[1], "expected 'pcallwithenv' to execute successfully")
    assert(res[2] == c, res[3] == b, res[4] == a, "expected 'pcallwithenv' to return reversed values")
end)

case("pcallwithenv: calls erroring function and returns error", function()
    local function foo()
        return error("test error")
    end

    local function pack(...)
        return { n = select("#", ...), ... }
    end

    local res = pack(pcallwithenv(foo, { error = error }))

    assert(res.n == 2, "expected 'pcallwithenv' to return two values")
    assert(not res[1], "expected 'pcallwithenv' to execute unsuccessfully")
    assert(string.find(res[2], "test error"), "expected 'pcallwithenv' to return an error string")
end)

case("date: empty format raises a format-length error", function()
    local ok, err = pcall(date, "")
    assert(not ok, "expected 'date(\"\")' to raise an error")
    assert(string.find(err, "'date' format too long", 1, true), tostring(err))
end)

case("date: UTC prefix alone raises a format-length error", function()
    local ok, err = pcall(date, "!")
    assert(not ok, "expected 'date(\"!\")' to raise an error")
    assert(string.find(err, "'date' format too long", 1, true), tostring(err))
end)

case("date: literal text and escaped percent do not depend on the clock", function()
    local result = date("literal %% text")
    assert(result == "literal % text", "unexpected literal-format result: " .. tostring(result))
end)

case("date: formats an explicit UTC timestamp on leap day", function()
    local result = date("!%Y-%m-%d %H:%M:%S", 951827696)
    assert(result == "2000-02-29 12:34:56", "unexpected UTC-format result: " .. tostring(result))
end)

case("date: returns calendar fields for an explicit UTC timestamp", function()
    local result = date("!*t", 951827696)
    assert(type(result) == "table", "expected 'date(\"!*t\", ...)' to return a table")
    assert(result.year == 2000, "unexpected year: " .. tostring(result.year))
    assert(result.month == 2, "unexpected month: " .. tostring(result.month))
    assert(result.day == 29, "unexpected day: " .. tostring(result.day))
    assert(result.hour == 12, "unexpected hour: " .. tostring(result.hour))
    assert(result.min == 34, "unexpected minute: " .. tostring(result.min))
    assert(result.sec == 56, "unexpected second: " .. tostring(result.sec))
    assert(result.wday == 3, "expected Tuesday to have weekday index 3: " .. tostring(result.wday))
    assert(result.yday == 60, "expected leap day to have year-day index 60: " .. tostring(result.yday))
    assert(result.isdst == false, "expected UTC to have no daylight saving: " .. tostring(result.isdst))
end)

case("string.lower: converts ASCII letters to lowercase", function()
    assert(string.lower("AbC") == "abc", "expected lowercase ASCII letters")
end)

case("string.lower: discards malformed UTF-8 bytes", function()
    assert(string.lower("A\255B") == "ab", "expected malformed byte to be discarded")
end)

case("string.lower: discards truncated UTF-8 sequences", function()
    assert(string.lower("A\195") == "a", "expected truncated sequence to be discarded")
end)

case("string.lower: stops at an embedded NUL", function()
    assert(string.lower("A\0B") == "a", "expected conversion to stop at the first NUL")
end)

case("string.upper: converts ASCII letters to uppercase", function()
    assert(string.upper("AbC") == "ABC", "expected uppercase ASCII letters")
end)

case("string.upper: discards malformed UTF-8 bytes", function()
    assert(string.upper("a\255b") == "AB", "expected malformed byte to be discarded")
end)

case("string.upper: discards truncated UTF-8 sequences", function()
    assert(string.upper("a\195") == "A", "expected truncated sequence to be discarded")
end)

case("string.upper: stops at an embedded NUL", function()
    assert(string.upper("a\0b") == "A", "expected conversion to stop at the first NUL")
end)

case("string.upper: leaves dotless i unchanged", function()
    assert(string.upper("\196\177") == "\196\177", "expected dotless i to remain unchanged")
end)

case("bit.mod: zero divisor returns infinity", function()
    assert(bit.mod(5, 0) == math.huge, "expected 'bit.mod(5, 0)' to return infinity")
end)

case("bit.mod: fractional divisors that truncate to zero return their reciprocal", function()
    assert(bit.mod(5, 0.5) == 2, "expected 'bit.mod(5, 0.5)' to return 2")
    assert(bit.mod(5, -0.5) == -2, "expected 'bit.mod(5, -0.5)' to return -2")
    assert(bit.mod(5, 0.9) == 1 / 0.9, "expected 'bit.mod(5, 0.9)' to return its divisor's reciprocal")
end)

case("bit.mod: nonzero integer divisor returns remainder", function()
    assert(bit.mod(17, 5) == 2, "expected 'bit.mod(17, 5)' to return 2")
end)

-- Elune-only: this can crash in-game with a divide-by-zero exception.
if _G.case then
    case("bit.mod: signed division overflow safely returns zero", function()
        assert(bit.mod(-2147483648, -1) == 0, "expected 'bit.mod(-2147483648, -1)' to return 0")
    end)
end

-- This test verifies recent changes made in 10.1 that allow 'debuglocals'
-- to be called anywhere outside of a global error handler (yay!).
case("debuglocals: can be called anywhere", function()
    assert(select("#", debuglocals()) > 0)
end)

-- This test verifies that changes made in patch 10.2.0 now prevent the use of
-- NaN values as table keys, as is consistent with a stock build of Lua where
-- math optimizations are disabled.
case("tables: nan cannot be used as a table key", function()
    local function nantest()
        local tbl = {}
        tbl[-math.sin(math.huge)] = true
    end

    local ok, err = pcall(nantest)
    assert(not ok, "expected 'nantest' call to fail")
    assert(string.find(err, "table index is NaN"), "expected 'nantest' call to fail because table index is a NaN")
end)
