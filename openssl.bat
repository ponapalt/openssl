call vcvars32

del /f makefile

perl Configure VC-WIN32 zlib no-dynamic-engine no-dso no-hw no-deprecated no-async no-ssl3 no-weak-ssl-ciphers no-sm3 no-sm4 no-seed no-idea no-camellia no-aria no-cast no-asm enable-rc5 enable-rfc3779 enable-capieng enable-chacha enable-poly1305 enable-ec -static -DWINVER=0x0500 -DWIN32_IE=0x0400 -D__FUNCTION__=\\\"\\\" -Zi --with-zlib-lib="../ssp_src_set/zlib-new/zlib.lib" --with-zlib-include="../ssp_src_set/zlib-new/"

del /f makefile.orig
ren makefile makefile.orig

sed -e "s/-D\"UNICODE\" -D\"_UNICODE\"/-DNDEBUG -DSTRICT -D_MBCS -MT/" -e "s/\/WX//" -e "s/\/showIncludes//g" -e "s/\/wd4090//g" -e "s/\/MD/\/MT/g" -e "s/\-static//g" makefile.orig > makefile

nmake /f makefile
