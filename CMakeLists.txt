project (nice)

cmake_minimum_required (VERSION 2.8)


set(LibNice_SOURCES
    agent/address.h
    agent/address.c
    agent/agent.h
    agent/agent-priv.h
    agent/agent.c
    agent/component.h
    agent/component.c
    agent/debug.h
    agent/debug.c
    agent/inputstream.h
    agent/inputstream.c
    agent/iostream.h
    agent/iostream.c
    agent/pseudotcp.h
    agent/pseudotcp.c
    agent/candidate.h
    agent/candidate.c
    agent/conncheck.h
    agent/conncheck.c
    agent/discovery.h
    agent/discovery.c
    agent/interfaces.h
    agent/interfaces.c
    agent/outputstream.h
    agent/outputstream.c
    agent/stream.h
    agent/stream.c
    stun/constants.h
    stun/debug.h
    stun/debug.c
    stun/md5.h
    stun/md5.c
    stun/rand.h
    stun/rand.c
    stun/sha1.h
    stun/sha1.c
    stun/stun5389.h
    stun/stun5389.c
    stun/stunagent.h
    stun/stunagent.c
    stun/stuncrc32.h
    stun/stuncrc32.c
    stun/stunhmac.h
    stun/stunhmac.c
    stun/stunmessage.h
    stun/stunmessage.c
    stun/utils.h
    stun/utils.c
    stun/win32_common.h
    socket/udp-turn-over-tcp.h
    socket/udp-turn-over-tcp.c
    socket/udp-turn.h
    socket/udp-turn.c
    socket/udp-bsd.h
    socket/udp-bsd.c
    socket/tcp-passive.h
    socket/tcp-passive.c
    socket/tcp-bsd.h
    socket/tcp-bsd.c
    socket/tcp-active.h
    socket/tcp-active.c
    socket/socks5.h
    socket/socks5.c
    socket/socket-priv.h
    socket/socket.h
    socket/socket.c
    socket/pseudossl.h
    socket/pseudossl.c
    socket/http.h
    socket/http.c
    random/random.h
    random/random.c
    random/random-glib.h
    random/random-glib.c
)

INCLUDE (CheckIncludeFiles)
CHECK_INCLUDE_FILES (arpa/inet.h HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES (dlfcn.h HAVE_DLFCN_H)
CHECK_INCLUDE_FILES (ifaddrs.h HAVE_IFADDRS_H)
CHECK_INCLUDE_FILES (inttypes.h HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES (memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILES (net/in.h HAVE_NET_IN_H)
CHECK_INCLUDE_FILES (stdint.h HAVE_STDINT_H)
CHECK_INCLUDE_FILES (stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILES (strings.h HAVE_STRINGS_H)
CHECK_INCLUDE_FILES (string.h HAVE_STRING_H)
CHECK_INCLUDE_FILES (sys/stat.h HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES (sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES (unistd.h HAVE_UNISTD_H)

INCLUDE (CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("void test(int len) { int vla[len]; }; int main(int argc, char** argv) { return 0; }" HAVE_C_VARARRAYS)
CHECK_C_SOURCE_COMPILES("#include <unistd.h>
    #if !defined (_POSIX_VERSION) || _POSIX_VERSION < 200112L
    #error \"no posix\"
    #endif
    int main(int argc, char** argv) { return 0; }" _POSIX_1_SOURCE)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories("${CMAKE_CURRENT_BINARY_DIR}") #this adds config.h to the include path

add_library(nice STATIC ${LibNice_SOURCES})
add_definitions(-DHAVE_CONFIG_H)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/socket")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/agent")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/random")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/stun")

#find_package(GLib)
#target_link_libraries(LibNice glib-2.0)

find_package (PkgConfig REQUIRED)
pkg_check_modules (GLIB2 REQUIRED glib-2.0)

include_directories (${GLIB2_INCLUDE_DIRS})
link_directories (${GLIB2_LIBRARY_DIRS})
add_definitions (${GLIB2_CFLAGS_OTHER})
target_link_libraries (nice ${GLIB2_LIBRARIES})
