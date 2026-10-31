/* Licensed under the terms of the MIT License; see full copyright information
 * in the "LICENSE" file or at <http://www.lua.org/license.html> */

#define llimits_c
#define LUA_CORE

#include "llimits.h"

#if FLT_RADIX != 2 || DBL_MANT_DIG != 53 || DBL_MAX_EXP != 1024
#error "numeric classification requires IEEE-754 binary64 numbers"
#endif

static uint64_t luai_num2bits (lua_Number value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

int luai_numisfinite (lua_Number value) {
    return (luai_num2bits(value) & UINT64_C(0x7ff0000000000000)) != UINT64_C(0x7ff0000000000000);
}

int luai_numisinf (lua_Number value) {
    const uint64_t bits = luai_num2bits(value);
    return (bits & UINT64_C(0x7fffffffffffffff)) == UINT64_C(0x7ff0000000000000);
}

int luai_numisnan (lua_Number value) {
    const uint64_t bits = luai_num2bits(value);
    return (bits & UINT64_C(0x7ff0000000000000)) == UINT64_C(0x7ff0000000000000) &&
           (bits & UINT64_C(0x000fffffffffffff)) != 0;
}

int luai_numiszero (lua_Number value) {
    return (luai_num2bits(value) & UINT64_C(0x7fffffffffffffff)) == 0;
}

lua_Number luai_numinfinity (void) {
    const uint64_t bits = UINT64_C(0x7ff0000000000000);
    lua_Number value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}
