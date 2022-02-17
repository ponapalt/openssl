use strict;
use Win32;
my $file = shift // 'tee.out';
my $cp = 'cp' . Win32::GetConsoleOutputCP();
binmode(STDIN,  ":encoding($cp)");
binmode(STDOUT, ":encoding($cp)");
open(my $log, '>', $file) or die "Cannot open $file: $!";
binmode($log, ":encoding($cp)");
$| = 1;
while (<STDIN>) {
    print $_;
    print $log $_;
}
