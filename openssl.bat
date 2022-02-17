call vcvars32

del /f makefile

perl Configure VC-WIN32 zlib no-deprecated no-capieng no-sm3 no-sm4 no-seed no-idea no-camellia no-aria no-cast no-pic no-shared enable-async enable-rc5 enable-rfc3779 enable-chacha enable-poly1305 enable-ec enable-quic enable-winstore enable-threads -DWINVER=0x0500 -D_WIN32_WINNT=0x0400 -DWIN32_IE=0x0400 -DOPENSSL_NO_LOCALE -D__STRICT_ANSI__ -D__FUNCTION__=\\\"\\\" -Zi --with-zlib-include=../ssp_src_set/J-Gx/extlib/zlib/ --with-zlib-lib=../ssp_src_set/J-Gx/extlib/zlib/zlib.lib

del /f makefile.orig
ren makefile makefile.orig

sed -e "s/-D\"UNICODE\" -D\"_UNICODE\"/-DNDEBUG -DSTRICT -D_MBCS -MT/" -e "s/\/WX//" -e "s/\/showIncludes//g" -e "s/\/wd4090//g" -e "s/-Zi/\/Zi \/Oy-/g" -e "s/\/MD/\/MT/g" -e "s/\-static//g" makefile.orig > makefile

nmake /f makefile | tee build.log

