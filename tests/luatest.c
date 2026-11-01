/*
** elune tests
**
** Licensed under the terms of the MIT License; see full copyright information
** in the "LICENSE" file or at <http://www.lua.org/license.html>
*/

#include "lua.h"

#include "lauxlib.h"
#include "lualib.h"

#include <acutest.h>
#include <string.h>

static int luatest_panichandler (lua_State *L) {
    acutest_check_(0, __FILE__, __LINE__, "lua panic");
    acutest_message_("%s", luaL_optstring(L, -1, "<unknown error>"));
    lua_close(L);
    acutest_abort_();
    return 0; /* unreachable */
}

static lua_State *luatest_newstate (void) {
    lua_State *L = luaL_newstate();
    lua_setprofilingenabled(L, 1);
    lua_settaintmode(L, LUA_TAINTRDRW);
    lua_atpanic(L, luatest_panichandler);
    return L;
}

/*
** C API Test Cases
*/

static void f_protecttaint_normal (lua_State *L, void *ud) {
    lua_setstacktaint(L, (const char *) ud);
    lua_pushliteral(L, "test");
}

static void test_protecttaint_secure_normal (void) {
    lua_State *L = luatest_newstate();
    lua_protecttaint(L, &f_protecttaint_normal, NULL);
    TEST_CHECK((luaL_issecure(L)));
    TEST_CHECK((luaL_issecurevalue(L, -1)));
    lua_close(L);
}

static void test_protecttaint_tainted_normal (void) {
    lua_State *L = luatest_newstate();
    lua_protecttaint(L, &f_protecttaint_normal, LUA_FORCEINSECURE_TAINT);
    TEST_CHECK((!luaL_issecure(L)));
    TEST_CHECK((!luaL_issecurevalue(L, -1)));
    lua_close(L);
}

static void f_protecttaint_error (lua_State *L, void *ud) {
    lua_setstacktaint(L, (const char *) ud);
    lua_pushliteral(L, "error");
    lua_error(L);
}

static int f_protecttaint_inner (lua_State *L) {
    lua_protecttaint(L, &f_protecttaint_error, lua_touserdata(L, 1));
    return 0;
}

static void test_protecttaint_secure_error (void) {
    int status;

    lua_State *L = luatest_newstate(); /* start secure */
    status = lua_cpcall(L, &f_protecttaint_inner, LUA_FORCEINSECURE_TAINT);
    TEST_CHECK((status != 0));
    TEST_CHECK((luaL_issecure(L)));
    lua_close(L);
}

static void test_protecttaint_tainted_error (void) {
    int status;

    lua_State *L = luatest_newstate();
    lua_setstacktaint(L, LUA_FORCEINSECURE_TAINT); /* start tainted */
    status = lua_cpcall(L, &f_protecttaint_inner, NULL);
    TEST_CHECK((status != 0));
    TEST_CHECK((!luaL_issecure(L)));
    lua_close(L);
}

static int f_freezetable (lua_State *L) {
    lua_freezetable(L, 1);
    return 0;
}

static void test_freezetable_secure_table (void) {
    lua_State *L = luatest_newstate();
    lua_newtable(L);
    TEST_CHECK((!lua_isfrozen(L, 1)));
    lua_freezetable(L, 1);
    TEST_CHECK((lua_isfrozen(L, 1)));
    lua_close(L);
}

static void test_freezetable_secure_caller (void) {
    lua_State *L = luatest_newstate();
    lua_setnewobjecttaint(L, "AddonA");
    lua_newtable(L);
    lua_setnewobjecttaint(L, NULL);
    lua_freezetable(L, 1);
    TEST_CHECK((lua_isfrozen(L, 1)));
    lua_close(L);
}

static void test_freezetable_same_owner (void) {
    lua_State *L = luatest_newstate();
    lua_setnewobjecttaint(L, "AddonA");
    lua_newtable(L);
    lua_setnewobjecttaint(L, NULL);
    lua_setstacktaint(L, "AddonA");
    lua_freezetable(L, 1);
    TEST_CHECK((lua_isfrozen(L, 1)));
    lua_close(L);
}

static void test_freezetable_tainted_caller_secure_table (void) {
    lua_State *L = luatest_newstate();
    lua_newtable(L);
    lua_pushcfunction(L, &f_freezetable);
    lua_pushvalue(L, 1);
    lua_setstacktaint(L, "AddonA");
    const int status = lua_pcall(L, 1, 0, 0);
    TEST_CHECK((status != 0));
    TEST_CHECK((!lua_isfrozen(L, 1)));
    lua_close(L);
}

static void test_freezetable_different_owner (void) {
    lua_State *L = luatest_newstate();
    lua_setnewobjecttaint(L, "AddonA");
    lua_newtable(L);
    lua_setnewobjecttaint(L, NULL);
    lua_pushcfunction(L, &f_freezetable);
    lua_pushvalue(L, 1);
    lua_setstacktaint(L, "AddonB");
    const int status = lua_pcall(L, 1, 0, 0);
    TEST_CHECK((status != 0));
    TEST_CHECK((!lua_isfrozen(L, 1)));
    lua_close(L);
}

static void test_securecopy_taint_isolation (void) {
    for (int insecure = 0; insecure <= 1; ++insecure) {
        lua_State *L = luatest_newstate();

        /* Mix secure entries, different addon taints, a nested table and a
         * tainted hash key so traversal cannot rely on one uniform owner. */
        lua_newtable(L);
        lua_pushliteral(L, "secure");
        lua_rawseti(L, 1, 1);
        lua_setstacktaint(L, "AddonA");
        lua_pushliteral(L, "first");
        lua_rawseti(L, 1, 2);
        lua_setstacktaint(L, "AddonB");
        lua_newtable(L);
        lua_pushliteral(L, "nested");
        lua_rawseti(L, 2, 1);
        lua_rawseti(L, 1, 3);
        lua_pushliteral(L, "key");
        lua_pushboolean(L, 1);
        lua_rawset(L, 1);
        lua_setstacktaint(L, insecure ? "Caller" : NULL);

        /* Copying preserves the entry context and pushes one new table. */
        luaL_securecopy(L, 1, NULL);
        TEST_CHECK((lua_gettop(L) == 2));
        TEST_CHECK((luaL_issecure(L) == !insecure));
        TEST_CHECK((luaL_issecureobject(L, 2) == !insecure));

        /* Every copied value and nested allocation receives caller taint,
         * regardless of taint encountered while reading another entry. */
        for (int index = 1; index <= 3; ++index) {
            lua_rawgeti(L, 2, index);
            const char *taint = lua_getvaluetaint(L, -1);
            TEST_CHECK((insecure ? taint && strcmp(taint, "Caller") == 0 : taint == NULL));
            if (index == 3) {
                TEST_CHECK((luaL_issecureobject(L, -1) == !insecure));
                lua_rawgeti(L, -1, 1);
                taint = lua_getvaluetaint(L, -1);
                TEST_CHECK((insecure ? taint && strcmp(taint, "Caller") == 0 : taint == NULL));
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }

        /* Keys follow the same rule, and reading the completed copy must
         * not expose any of the original addon taints. */
        lua_pushnil(L);
        while (lua_next(L, 2)) {
            const char *taint = lua_getvaluetaint(L, -2);
            TEST_CHECK((insecure ? taint && strcmp(taint, "Caller") == 0 : taint == NULL));
            lua_pop(L, 1);
        }
        TEST_CHECK((luaL_issecure(L) == !insecure));
        lua_close(L);
    }
}

static int f_securecopy_callback (lua_State *L) {
    /* The captured value taint, not function ownership, controls entry.
     * A different taint acquired during execution must propagate out. */
    const char *taint = lua_getstacktaint(L);
    TEST_CHECK((taint && strcmp(taint, "AddonA") == 0));
    lua_setstacktaint(L, "AddonB");
    if (lua_toboolean(L, 1)) {
        lua_pushliteral(L, "callback error");
        return lua_error(L);
    }
    lua_pushboolean(L, 1);
    return 1;
}

static void test_securecopy_function_taint (void) {
    lua_State *L = luatest_newstate();

    /* Deliberately separate value taint from function ownership. */
    lua_setstacktaint(L, "AddonA");
    lua_pushcfunction(L, f_securecopy_callback);
    lua_setobjecttaint(L, 1, "DifferentOwner");
    lua_setstacktaint(L, NULL);

    /* Copying creates an unowned wrapper with a secure result value. */
    luaL_securecopy(L, 1, NULL);
    TEST_CHECK((luaL_issecureobject(L, 2)));
    TEST_CHECK((luaL_issecurevalue(L, 2)));
    TEST_CHECK((!lua_rawequal(L, 1, 2)));

    /* A normal return retains the callee's taint on both execution and
     * the returned value; the wrapper is not a secure call barrier. */
    const int status = lua_pcall(L, 0, 1, 0);
    TEST_CHECK((status == LUA_OK));
    TEST_CHECK((!luaL_issecure(L)));
    TEST_CHECK((lua_toboolean(L, -1)));
    const char *taint = lua_getvaluetaint(L, -1);
    TEST_CHECK((taint && strcmp(taint, "AddonB") == 0));
    lua_pop(L, 1);

    /* Errors also retain callee taint rather than being retagged by the
     * wrapper. Reset the caller before creating a fresh wrapper. */
    lua_setstacktaint(L, NULL);
    luaL_securecopy(L, 1, NULL);
    lua_pushboolean(L, 1);
    TEST_CHECK((lua_pcall(L, 1, 1, 0) == LUA_ERRRUN));
    TEST_CHECK((!luaL_issecure(L)));
    taint = lua_getvaluetaint(L, -1);
    TEST_CHECK((taint && strcmp(taint, "AddonB") == 0));
    lua_close(L);
}

static void test_securecopy_trusted_function (void) {
    lua_State *L = luatest_newstate();

    /* An untainted function value stays identical even for an insecure
     * caller; only the copied value receives caller taint. */
    lua_pushcfunction(L, f_securecopy_callback);
    lua_setstacktaint(L, "Caller");
    luaL_securecopy(L, 1, NULL);
    TEST_CHECK((lua_rawequal(L, 1, 2)));
    TEST_CHECK((luaL_issecureobject(L, 2)));
    const char *taint = lua_getvaluetaint(L, 2);
    TEST_CHECK((taint && strcmp(taint, "Caller") == 0));
    lua_pop(L, 1);

    /* Object ownership alone must not cause an untainted value to wrap. */
    lua_setobjecttaint(L, 1, "OwnedFunction");
    luaL_securecopy(L, 1, NULL);
    TEST_CHECK((lua_rawequal(L, 1, 2)));
    TEST_CHECK((strcmp(lua_getobjecttaint(L, 2), "OwnedFunction") == 0));
    lua_close(L);
}

static int f_securecopy_default (lua_State *L) {
    luaL_securecopy(L, 1, NULL);
    return 1;
}

static void test_securecopy_script_objects (void) {
    lua_State *L = luatest_newstate();

    /* A raw light userdata at key 0 marks an opaque script object.
     * Default copying rejects it; permission preserves its identity. */
    lua_newtable(L);
    lua_pushlightuserdata(L, L);
    lua_rawseti(L, 1, 0);
    lua_pushcfunction(L, f_securecopy_default);
    lua_pushvalue(L, 1);
    TEST_CHECK((lua_pcall(L, 1, 1, 0) == LUA_ERRRUN));
    lua_pop(L, 1);
    const luaL_SecureCopyOptions options = { 100, 1, 1 };
    luaL_securecopy(L, 1, &options);
    TEST_CHECK((lua_rawequal(L, 1, 2)));
    lua_pop(L, 1);

    /* The same permission applies when the object occurs as both a key
     * and a value inside an otherwise ordinary copied table. */
    lua_newtable(L);
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 1);
    lua_rawset(L, 2);
    luaL_securecopy(L, 2, &options);
    lua_pushvalue(L, 1);
    lua_rawget(L, 3);
    TEST_CHECK((lua_rawequal(L, 1, -1)));
    lua_pop(L, 1);
    lua_pushcfunction(L, f_securecopy_default);
    lua_pushvalue(L, 2);
    TEST_CHECK((lua_pcall(L, 1, 1, 0) == LUA_ERRRUN));
    lua_pop(L, 1);

    /* Full userdata at key 0 is not a script-object marker. The enclosing
     * table is copied normally while the userdata retains identity. */
    lua_newtable(L);
    lua_newuserdata(L, 1);
    lua_rawseti(L, -2, 0);
    const int source = lua_gettop(L);
    luaL_securecopy(L, source, NULL);
    TEST_CHECK((!lua_rawequal(L, source, -1)));
    lua_rawgeti(L, source, 0);
    lua_rawgeti(L, source + 1, 0);
    TEST_CHECK((lua_rawequal(L, -1, -2)));
    lua_close(L);
}

static void test_securecopy_error_taint (void) {
    lua_State *L = luatest_newstate();

    /* Traversal reads a tainted entry before rejecting its script object. */
    lua_setstacktaint(L, "AddonA");
    lua_newtable(L);
    lua_newtable(L);
    lua_pushlightuserdata(L, L);
    lua_rawseti(L, 2, 0);
    lua_rawseti(L, 1, 1);
    lua_setstacktaint(L, NULL);
    lua_pushcfunction(L, f_securecopy_default);
    lua_pushvalue(L, 1);

    /* Pushing the tainted source already taints setup. Clear that taint
     * immediately before calling to isolate the traversal error path. */
    lua_setstacktaint(L, NULL);
    TEST_CHECK((lua_pcall(L, 1, 1, 0) == LUA_ERRRUN));
    TEST_CHECK((luaL_issecure(L)));
    lua_close(L);
}

static void test_securecopy_deep_graph (void) {
    lua_State *L = luatest_newstate();

    /* Build the documented 100-table boundary without recursive setup.
     * These deep-copy probes are native-only: they crashed the client. */
    lua_newtable(L);
    lua_pushvalue(L, 1);
    for (int depth = 1; depth < 100; ++depth) {
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_rawseti(L, -3, 1);
        lua_remove(L, -2);
    }
    lua_pop(L, 1);

    /* The boundary copy succeeds and contains every nested table. */
    luaL_securecopy(L, 1, NULL);
    TEST_CHECK((lua_gettop(L) == 2));
    TEST_CHECK((!lua_rawequal(L, 1, 2)));
    lua_pushvalue(L, 2);
    for (int depth = 1; depth < 100; ++depth) {
        lua_rawgeti(L, -1, 1);
        lua_remove(L, -2);
        TEST_CHECK((lua_istable(L, -1)));
    }
    lua_pop(L, 2);

    /* Adding one enclosing table exceeds the default limit and must
     * produce a Lua error rather than a native stack assertion. */
    lua_newtable(L);
    lua_pushvalue(L, 1);
    lua_rawseti(L, 2, 1);
    lua_pushcfunction(L, f_securecopy_default);
    lua_pushvalue(L, 2);
    TEST_CHECK((lua_pcall(L, 1, 1, 0) == LUA_ERRRUN));
    lua_close(L);
}

/*
** Scripted Test Cases
*/

static int luatest_errorhandler (lua_State *L) {
    acutest_check_(0, __FILE__, __LINE__, "error handler");
    luaL_traceback(L, L, lua_tostring(L, 1), 2);
    acutest_message_("%s", lua_tostring(L, -1));
    return 0;
}

static int luatest_case (lua_State *L) {
    acutest_case_("%s", luaL_checkstring(L, 1));
    lua_pushcclosure(L, &luatest_errorhandler, 0);
    lua_replace(L, LUA_ERRORHANDLERINDEX);
    luaL_securecall(L, 0, 0, LUA_ERRORHANDLERINDEX);
    return 0;
}

static void test_scriptcases (void) {
    lua_State *L = luatest_newstate();
    luaL_openlibsx(L, LUALIB_ELUNE);

    /* Add custom test case registration function to environment. */
    lua_pushcclosure(L, &luatest_case, 0);
    lua_setfield(L, LUA_GLOBALSINDEX, "case");

    if (!TEST_CHECK((luaL_dofile(L, "luatest_scriptcases.lua") == 0))) {
        TEST_MSG("%s", (luaL_optstring(L, -1, "<unknown script error>")));
    }

    lua_close(L);
}

static void test_coroutinescriptcases (void) {
    lua_State *L = luatest_newstate();
    luaL_openlibs(L);

    /* Add custom test case registration function to environment. */
    lua_pushcclosure(L, &luatest_case, 0);
    lua_setfield(L, LUA_GLOBALSINDEX, "case");

    if (!TEST_CHECK((luaL_dofile(L, "luatest_coroutine.lua") == 0))) {
        TEST_MSG("%s", (luaL_optstring(L, -1, "<unknown script error>")));
    }

    lua_close(L);
}

static void test_profilingscriptcases (void) {
    lua_State *L = luatest_newstate();
    luaL_openlibs(L);

    /* Add custom test case registration function to environment. */
    lua_pushcclosure(L, &luatest_case, 0);
    lua_setfield(L, LUA_GLOBALSINDEX, "case");

    if (!TEST_CHECK((luaL_dofile(L, "luatest_profiling.lua") == 0))) {
        TEST_MSG("%s", (luaL_optstring(L, -1, "<unknown script error>")));
    }

    lua_close(L);
}

/*
** Test Case Registration
*/

TEST_LIST = {
    { "luaL_securecopy: table visits preserve caller taint independently", test_securecopy_taint_isolation },
    { "luaL_securecopy: wrappers propagate original value and call taint", test_securecopy_function_taint },
    { "luaL_securecopy: trusted functions retain identity", test_securecopy_trusted_function },
    { "luaL_securecopy: synthetic script objects require permission", test_securecopy_script_objects },
    { "luaL_securecopy: traversal errors restore caller taint", test_securecopy_error_taint },
    { "luaL_securecopy: deep graphs respect the default depth limit safely", test_securecopy_deep_graph },
    { "lua_freezetable: secure table can be frozen", test_freezetable_secure_table },
    { "lua_freezetable: secure caller can freeze addon table", test_freezetable_secure_caller },
    { "lua_freezetable: addon can freeze its own table", test_freezetable_same_owner },
    { "lua_freezetable: tainted caller cannot freeze secure table", test_freezetable_tainted_caller_secure_table },
    { "lua_freezetable: addon cannot freeze another addon's table", test_freezetable_different_owner },
    { "lua_protecttaint: stack remains secure after call", test_protecttaint_secure_normal },
    { "lua_protecttaint: stack remains tainted after call", test_protecttaint_tainted_normal },
    { "lua_protecttaint: stack restored to secure on error", test_protecttaint_secure_error },
    { "lua_protecttaint: stack restored to tainted on error", test_protecttaint_tainted_error },
    { "scripted test cases", test_scriptcases },
    { "coroutine script tests", test_coroutinescriptcases },
    { "profiling script tests", test_profilingscriptcases },
    /* clang-format off */
    { NULL, NULL },
    /* clang-format on */
};
