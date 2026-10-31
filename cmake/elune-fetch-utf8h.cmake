include(FetchContent)

FetchContent_Declare(
  utf8h
  GIT_REPOSITORY "https://github.com/sheredom/utf8.h.git"
  GIT_TAG "8a37b279054b0f573e461a1c478db27cb42265cb"
  FIND_PACKAGE_ARGS
)

FetchContent_MakeAvailable(utf8h)

if(utf8h_SOURCE_DIR AND NOT TARGET sheredom::utf8h)
  add_library(utf8h INTERFACE IMPORTED GLOBAL)
  add_library(sheredom::utf8h ALIAS utf8h)
  target_include_directories(utf8h INTERFACE ${utf8h_SOURCE_DIR})
endif()
