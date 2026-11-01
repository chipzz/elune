--
-- Elune-specific object naming tests; these APIs are not available in-game.
--

case("object names: registration, replacement and clearing", function()
    -- Each userdata has an independent name, even with a shared metatable.
    local first = newproxy(true)
    local second = newproxy(first)
    assert(debug.getobjectname(first) == nil)
    assert(select("#", debug.setobjectname(first, "First")) == 0)
    debug.setobjectname(second, "Second")
    assert(debug.getobjectname(first) == "First")
    assert(debug.getobjectname(second) == "Second")
    debug.setobjectname(first, "Renamed")
    assert(debug.getobjectname(first) == "Renamed")
    debug.setobjectname(first, "")
    assert(debug.getobjectname(first) == "")
    debug.setobjectname(first, "a\0b")
    assert(debug.getobjectname(first) == "a\0b")
    debug.setobjectname(first, nil)
    assert(select("#", debug.getobjectname(first)) == 1)
    assert(debug.getobjectname(first) == nil)
    assert(debug.getobjectname(second) == "Second")
end)

case("object names: invalid arguments raise errors", function()
    -- Reject non-userdata keys and non-string names without coercion.
    local object = newproxy(false)
    assert(not pcall(debug.getobjectname))
    assert(not pcall(debug.setobjectname, object))
    for _, value in ipairs({ false, 1, "text", {}, function() end }) do
        assert(not pcall(debug.getobjectname, value))
        assert(not pcall(debug.setobjectname, value, "Name"))
    end
    for _, value in ipairs({ false, 1, {}, function() end }) do
        assert(not pcall(debug.setobjectname, object, value))
    end
    assert(debug.getobjectname(object) == nil)
end)

case("object names: full userdata remains collectible", function()
    -- Registered names must not extend the lifetime of their userdata keys.
    local observed = setmetatable({}, { __mode = "v" })
    do
        local object = newproxy(false)
        observed[1] = object
        debug.setobjectname(object, "Collectible")
    end
    collectgarbage("collect")
    collectgarbage("collect")
    assert(observed[1] == nil)
end)

case("object names: light userdata names require explicit clearing", function()
    -- Native pointers are not collected and remain named until cleared.
    debug.setobjectname(testlightuserdata, "NativeFrame")
    collectgarbage("collect")
    assert(debug.getobjectname(testlightuserdata) == "NativeFrame")
    debug.setobjectname(testlightuserdata, nil)
    assert(debug.getobjectname(testlightuserdata) == nil)
end)

case("debuglocals: registered full userdata names and clearing", function()
    -- Naming changes only table headers, including nested table headers.
    local object = newproxy(false)
    local frame = { [0] = object }
    local nested = { child = frame }
    debug.setobjectname(object, "TestFrame")
    local dump = debuglocals()
    assert(dump:find("frame = TestFrame {\n", 1, true))
    assert(dump:find(" child = TestFrame {\n", 1, true))
    assert(dump:find("object = <userdata>\n", 1, true))
    debug.setobjectname(object, nil)
    dump = debuglocals()
    assert(dump:find("frame = <table> {\n", 1, true))
end)

case("debuglocals: registered light userdata names", function()
    -- Light userdata at raw table key 0 uses the same naming path.
    local frame = { [0] = testlightuserdata }
    debug.setobjectname(testlightuserdata, "NativeFrame")
    assert(debuglocals():find("frame = NativeFrame {\n", 1, true))
    debug.setobjectname(testlightuserdata, nil)
    assert(debuglocals():find("frame = <table> {\n", 1, true))
end)

case("seterrorhandler: registered light userdata names and clearing", function()
    -- Replace only the script-source asterisk, and stop replacing after clear.
    local oldhandler = geterrorhandler()
    local errors = {}
    local frame = { [0] = testlightuserdata }
    local handler = assert(loadstring("local self = ...; return self.missing + 1", "*:OnTest"))
    debug.setobjectname(testlightuserdata, "NativeFrame")
    seterrorhandler(function(err) errors[#errors + 1] = err end)
    securecall(handler, frame)
    debug.setobjectname(testlightuserdata, nil)
    securecall(handler, frame)
    seterrorhandler(oldhandler)
    assert(#errors == 2)
    assert(errors[1] == '[string "NativeFrame:OnTest"]:1: attempt to perform arithmetic on field \'missing\' (a nil value)')
    assert(errors[2] == '[string "*:OnTest"]:1: attempt to perform arithmetic on field \'missing\' (a nil value)')
end)
