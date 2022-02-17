use strict;
my $mode = shift // '';
my ($defs, $opt, $rt);
if ($mode eq '-d') {
    $defs = '-D_DEBUG -DSTRICT -D_UNICODE -DUNICODE -MT';
    $opt  = '/Zi /Od /Oi /GZ';
    $rt   = '/MTd';
} elsif ($mode eq '-m') {
    $defs = '-DNDEBUG -DSTRICT -D_MBCS -MT';
    $opt  = '/Zi /O2 /Oy-';
    $rt   = '/MT';
} else {
    $defs = '-DNDEBUG -DSTRICT -D_UNICODE -DUNICODE -MT';
    $opt  = '/Zi /O2 /Oy-';
    $rt   = '/MT';
}
while (<STDIN>) {
    s/-D"UNICODE" -D"_UNICODE"/$defs/;
    s|/WX||;
    s|/showIncludes||g;
    s|/wd4090||g;
    s|/O2||g;
    s|-Zi|$opt|g;
    s|/MD|$rt|g;
    s|-static||g;
    print;
}
