use IO::File;
use File::Find;

chdir '..';
find(\&tovc6, '.');

sub tovc6 { 

    if (m|.dsp$|) {
	$tname = '.#' . $_;
	print "Convert project " . $_ . " to VC6 in " . $File::Find::dir . "\n"; 
	$srcfl = new IO::File $_, "r" || die;
	$dstfl = new IO::File $tname, "w" || die;
	while ($src = <$srcfl>) {
	    $src =~ s|Format Version 5\.00|Format Version 6\.00|;
	    $src =~ s|^(# ADD CPP .*)/Zi (.*)|$1/ZI $2|;
	    $src =~ s|^(# ADD BASE CPP .*)/Zi (.*)|$1/ZI $2|;
	    if ($src =~ s|^(!MESSAGE .*)\\\n|$1|) {
                $cont = <$srcfl>;
		chomp $src;
		$src = chomp($src) . $cont;
            }
            print $dstfl $src; 
	    if ($src =~ m|^# Begin Project|) {
		print $dstfl "# PROP AllowPerConfigDependencies 0\n"; }
	}
	undef $srcfl;
	undef $dstfl;
	unlink $_;
	rename $tname, $_;
    }
}
