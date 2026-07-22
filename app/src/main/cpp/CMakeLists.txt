cmake_minimum_required(VERSION 3.22.1)
project("iconify-native" C)

add_library(
    iconify-native
    SHARED
    iconify_jni.c
    sha256.c
    sha512.c
)

target_compile_options(iconify-native PRIVATE -O3 -fvisibility=hidden)

find_library(log-lib      log)
find_library(android-lib  android)
find_library(jnigraphics  jnigraphics)

target_link_libraries(iconify-native
    ${log-lib}
    ${android-lib}
    ${jnigraphics}
)
