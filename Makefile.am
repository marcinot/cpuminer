
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  sha2.c scrypt.c \
		  algo/x11.c \
		  aes.h \
		  aes.c \
		  kjv.h \
		  kjv.c \
		  crypto/oaes_lib.c \
		  crypto/c_keccak.c \
		  crypto/c_groestl.c \
		  crypto/c_blake256.c \
		  crypto/c_jh.c \
		  crypto/c_skein.c \
		  crypto/hash.c \
		  crypto/aesb.c \
		  sha3/sph_keccak.c \
		  sha3/sph_groestl.c \
		  sha3/sph_skein.c \
		  sha3/sph_bmw.c \
		  sha3/sph_jh.c \
		  sha3/sph_shavite.c \
		  sha3/sph_blake.c \
		  sha3/sph_blake.h \
		  sha3/sph_luffa.c \
		  sha3/sph_cubehash.c \
		  sha3/sph_simd.c \
		  sha3/sph_echo.c \
		  sha3/sph_hamsi.c \
		  sha3/sph_haval.c \
		  sha3/sph_fugue.c \
		  sha3/sph_ripemd.c \
		  sha3/sph_sha2.c \
		  sha3/sph_sha2big.c \
		  sha3/sph_shabal.c \
		  sha3/sph_whirlpool.c 	   

if USE_ASM
if ARCH_x86
minerd_SOURCES += sha2-x86.S scrypt-x86.S
endif
if ARCH_x86_64
minerd_SOURCES += sha2-x64.S scrypt-x64.S
endif
if ARCH_ARM
minerd_SOURCES += sha2-arm.S scrypt-arm.S
endif
if ARCH_PPC
minerd_SOURCES += sha2-ppc.S scrypt-ppc.S
endif
endif
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CFLAGS	= -fno-strict-aliasing
minerd_CPPFLAGS	= @LIBCURL_CPPFLAGS@ $(JANSSON_INCLUDES) $(PTHREAD_FLAGS)
CFLAGS += -DAEX256=1

