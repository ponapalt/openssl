call vcvars32

del /f makefile

perl Configure VC-WIN32 no-dynamic-engine no-hw no-deprecated no-async no-ssl3 no-comp no-weak-ssl-ciphers enable-rc5 enable-rfc3779 enable-capieng enable-chacha enable-poly1305 -static -DWINVER=0x0410 -D_WIN32_WINDOWS=0x0410 -DWIN32_IE=0x0300 -D__FUNCTION__=\\\"\\\" -Zi

del /f makefile.orig
ren makefile makefile.orig

sed -e "s/-D\"UNICODE\" -D\"_UNICODE\"/-DNDEBUG -DSTRICT -D_MBCS -MT/" -e "s/\/WX//" -e "s/\/showIncludes//g" -e "s/\/wd4090//g" -e "s/\/MD/\/MT/" makefile.orig > makefile

nmake /f makefile
