# Usage: ~/.local/perl/bin/perl -Ilib -Ilocal/lib/perl5 bin/add_title_in_entries.pl
use strict;
use warnings;
use utf8;
use DBIx::Sunny;

my $db = do {
    my %db = (
        host => $ENV{ISUCON5_DB_HOST} || 'localhost',
        port => $ENV{ISUCON5_DB_PORT} || 3306,
        username => $ENV{ISUCON5_DB_USER} || 'root',
        password => $ENV{ISUCON5_DB_PASSWORD},
        database => $ENV{ISUCON5_DB_NAME} || 'isucon5q',
    );
    DBIx::Sunny->connect(
        "dbi:mysql:database=$db{database};host=$db{host};port=$db{port}", $db{username}, $db{password}, {
            RaiseError => 1,
            PrintError => 0,
            AutoInactiveDestroy => 1,
            mysql_enable_utf8   => 1,
            mysql_auto_reconnect => 1,
        },
    );
};


my $query = q{update entries set title = ?, body = ? where id = ?};
for my $entry (@{$db->select_all('SELECT id, body FROM entries')}) {
    my ($title, $body) = split(/\n/, $entry->{body}, 2);
    $db->query($query, $title, $body, $entry->{id});
}
