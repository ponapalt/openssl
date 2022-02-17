call vcvars32

del /f makefile

perl Configure VC-WIN32 -w zlib no-pinshared no-deprecated no-sm3 no-sm4 no-seed no-idea no-camellia no-aria no-cast no-pic no-shared enable-async enable-rc5 enable-rfc3779 enable-chacha enable-poly1305 enable-ec enable-quic enable-winstore threads enable-thread-pool enable-default-thread-pool -DWINVER=0x0500 -D_WIN32_WINNT=0x0400 -DWIN32_IE=0x0500 -DOPENSSL_NO_LOCALE -DOPENSSL_USE_IPV6=1 -DOPENSSL_NO_UNIX_SOCK -D__STRICT_ANSI__ -D__FUNCTION__=\\\"\\\" -Zi --with-zlib-include=../ssp_src_set/J-Gx/extlib/zlib/ --with-zlib-lib=../ssp_src_set/J-Gx/extlib/zlib/zlib.lib --api=3.0.0

del /f makefile.orig
ren makefile makefile.orig

if "%1"=="-d" (
sed -e "s/-D\"UNICODE\" -D\"_UNICODE\"/-D_DEBUG -DSTRICT -D_UNICODE -DUNICODE -MT/" -e "s/\/WX//" -e "s/\/showIncludes//g" -e "s/\/wd4090//g" -e "s/\/O2//g" -e "s/-Zi/\/Zi \/Od \/Oi \/GZ/g" -e "s/\/MD/\/MTd/g" -e "s/\-static//g" makefile.orig > makefile
) else if "%1"=="-m" (
sed -e "s/-D\"UNICODE\" -D\"_UNICODE\"/-DNDEBUG -DSTRICT -D_MBCS -MT/" -e "s/\/WX//" -e "s/\/showIncludes//g" -e "s/\/wd4090//g" -e "s/\/O2//g" -e "s/-Zi/\/Zi \/O2 \/Oy-/g" -e "s/\/MD/\/MT/g" -e "s/\-static//g" makefile.orig > makefile
) else (
sed -e "s/-D\"UNICODE\" -D\"_UNICODE\"/-DNDEBUG -DSTRICT -D_UNICODE -DUNICODE -MT/" -e "s/\/WX//" -e "s/\/showIncludes//g" -e "s/\/wd4090//g" -e "s/\/O2//g" -e "s/-Zi/\/Zi \/O2 \/Oy-/g" -e "s/\/MD/\/MT/g" -e "s/\-static//g" makefile.orig > makefile
)

nmake /f makefile | tee build.log

