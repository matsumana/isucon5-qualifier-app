use FindBin;
use lib "$FindBin::Bin/local/lib/perl5";
use lib "$FindBin::Bin/lib";
use File::Basename;
use Plack::Builder;
use Isucon5::Web;
use Cache::Memcached::Fast::Safe;

my $root_dir = File::Basename::dirname(__FILE__);

my $app = Isucon5::Web->psgi($root_dir);
builder {
    enable 'ReverseProxy';
    enable 'Static',
        path => qr!^/(?:(?:css|fonts|js)/|favicon\.ico$)!,
        root => File::Basename::dirname($root_dir) . '/static';
    enable 'Session::Simple',
        store => Cache::Memcached::Fast::Safe->new({
            servers => [ "localhost:11211" ],
        }),
        httponly => 1,
        cookie_name => "isuxi_session",
        keep_empty => 0,
    ;
    $app;
};
