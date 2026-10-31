include(FetchContent)

FetchContent_Declare(
  acutest
  GIT_REPOSITORY "https://github.com/mity/acutest.git"
  GIT_TAG "31751b4089c93b46a9fd8a8183a695f772de66de"
  SOURCE_SUBDIR "None"
  FIND_PACKAGE_ARGS
)

FetchContent_MakeAvailable(acutest)

if(acutest_SOURCE_DIR AND NOT TARGET mity::acutest)
  add_library(acutest INTERFACE IMPORTED GLOBAL)
  add_library(mity::acutest ALIAS acutest)
  target_include_directories(acutest INTERFACE "${acutest_SOURCE_DIR}/include")
endif()
