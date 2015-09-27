package Isucon5::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Encode;
use Digest::SHA;

my $db;
sub db {
    $db ||= do {
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
}

my ($SELF, $C);

my $users = {};

sub session {
    $C->stash->{session};
}

sub stash {
    $C->stash;
}

sub redirect {
    $C->redirect(@_);
}

sub abort_authentication_error {
    session()->{user_id} = undef;
    $C->halt(401, encode_utf8($C->tx->render('login.tx', { message => 'ログインに失敗しました' })));
}

sub abort_permission_denied {
    $C->halt(403, encode_utf8($C->tx->render('error.tx', { message => '友人のみしかアクセスできません' })));
}

sub abort_content_not_found {
    $C->halt(404, encode_utf8($C->tx->render('error.tx', { message => '要求されたコンテンツは存在しません' })));
}

sub authenticate {
    my ($email, $password) = @_;
    my $query = <<SQL;
SELECT id, account_name, nick_name, email, salt, passhash
FROM users
WHERE email = ?
SQL
    my $result = db->select_row($query, $email);
    if ($result) {
        my $sha = Digest::SHA->new(512);
        my $p = $sha->add($password . $result->{salt})->hexdigest;
        if ($result->{passhash} ne $p) {
            abort_authentication_error();
        }
    } else {
        abort_authentication_error();
    }
    session()->{user_id} = $result->{id};
    return $result;
}

sub current_user {
    my ($self, $c) = @_;

    return undef if (!session()->{user_id});

    my $user = db->select_row('SELECT id, account_name, nick_name, email FROM users WHERE id=?', session()->{user_id});
    if (!$user) {
        session()->{user_id} = undef;
        abort_authentication_error();
    }
    return $user;
}

sub get_user {
    my ($user_id) = @_;
    my $user = $users->{$user_id};
    if (!$user) {
        $user = db->select_row('SELECT * FROM users WHERE id = ?', $user_id);
        if ($user) {
            $users->{$user_id} = $user;
        }
    }
    abort_content_not_found() if (!$user);
    return $user;
}

sub user_from_account {
    my ($account_name) = @_;
    my $user = db->select_row('SELECT * FROM users WHERE account_name = ?', $account_name);
    abort_content_not_found() if (!$user);
    return $user;
}

sub is_friend {
    my ($another_id) = @_;
    my $user_id = session()->{user_id};
    my $query = 'SELECT COUNT(1) AS cnt FROM relations WHERE (one = ? AND another = ?) OR (one = ? AND another = ?)';
    my $cnt = db->select_one($query, $user_id, $another_id, $another_id, $user_id);
    return $cnt > 0 ? 1 : 0;
}

sub is_friend_account {
    my ($account_name) = @_;
    is_friend(user_from_account($account_name)->{id});
}

sub mark_footprint {
    my ($user_id) = @_;
    if ($user_id != session()->{user_id}) {
        my $query = 'INSERT INTO footprints (user_id,owner_id) VALUES (?,?)';
        db->query($query, $user_id, session()->{user_id});
    }
}

sub permitted {
    my ($another_id) = @_;
    $another_id == session()->{user_id} || is_friend($another_id);
}

my $PREFS;
sub prefectures {
    $PREFS ||= do {
        [
        '未入力',
        '北海道', '青森県', '岩手県', '宮城県', '秋田県', '山形県', '福島県', '茨城県', '栃木県', '群馬県', '埼玉県', '千葉県', '東京都', '神奈川県', '新潟県', '富山県',
        '石川県', '福井県', '山梨県', '長野県', '岐阜県', '静岡県', '愛知県', '三重県', '滋賀県', '京都府', '大阪府', '兵庫県', '奈良県', '和歌山県', '鳥取県', '島根県',
        '岡山県', '広島県', '山口県', '徳島県', '香川県', '愛媛県', '高知県', '福岡県', '佐賀県', '長崎県', '熊本県', '大分県', '宮崎県', '鹿児島県', '沖縄県'
        ]
    };
}

filter 'authenticated' => sub {
    my ($app) = @_;
    sub {
        my ($self, $c) = @_;
        if (!current_user()) {
            return redirect('/login');
        }
        $app->($self, $c);
    }
};

filter 'set_global' => sub {
    my ($app) = @_;
    sub {
        my ($self, $c) = @_;
        $SELF = $self;
        $C = $c;
        $C->stash->{session} = $c->req->env->{"psgix.session"};
        $app->($self, $c);
    }
};

get '/login' => sub {
    my ($self, $c) = @_;
    $c->render('login.tx', { message => '高負荷に耐えられるSNSコミュニティサイトへようこそ!' });
};

post '/login' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $email = $c->req->param("email");
    my $password = $c->req->param("password");
    authenticate($email, $password);
    redirect('/');
};

get '/logout' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session()->{user_id} = undef;
    redirect('/login');
};

get '/' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;

    my $profile = db->select_row('SELECT * FROM profiles WHERE user_id = ?', session()->{user_id});

    my $entries_query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5';
    my $entries = [];
    for my $entry (@{db->select_all($entries_query, session()->{user_id})}) {
        $entry->{is_private} = ($entry->{private} == 1);
        $entry->{content} = $entry->{body};
        push @$entries, $entry;
    }

    my $comments_for_me_query = <<SQL;
SELECT c.id AS id, c.entry_id AS entry_id, c.user_id AS user_id, c.comment AS comment, c.created_at AS created_at, u.account_name AS account_name, u.nick_name AS nick_name
FROM comments c
JOIN entries e ON c.entry_id = e.id
INNER JOIN users u ON u.id = c.user_id
WHERE e.user_id = ?
ORDER BY c.created_at DESC
LIMIT 10
SQL
    my $comments_for_me = [];
    $comments_for_me = \@{db->select_all($comments_for_me_query, session()->{user_id})};

    my $friends_query = 'SELECT u.id, u.account_name, u.nick_name FROM users u INNER JOIN (SELECT one, another, created_at FROM relations WHERE one = ? OR another = ?) r ON u.id = r.another OR u.id = r.one ORDER BY r.created_at DESC';
    my %friends = ();
    my $friends = [];
    for my $rel (@{db->select_all($friends_query, session()->{user_id}, session()->{user_id})}) {
        next if exists $friends{$rel->{id}};
        next if $rel->{id} eq session()->{user_id};
        $friends{delete $rel->{id}} = $rel;
        push @$friends, $rel;
    }

    my $entries_of_friends = [];
    for my $entry (@{db->select_all('SELECT u.id as user_id, e.id, e.title, u.account_name, u.nick_name, e.created_at FROM users u join (SELECT id, user_id, title, created_at FROM entries ORDER BY created_at DESC LIMIT 1000) e ON u.id = e.user_id ORDER BY e.created_at DESC')}) {
        next unless $friends{$entry->{user_id}};
        push @$entries_of_friends, $entry;
        last if @$entries_of_friends+0 >= 10;
    }

    my $comments_of_friends = [];
    for my $comment (@{db->select_all('SELECT * FROM comments ORDER BY created_at DESC LIMIT 1000')}) {
        next unless $friends{$comment->{user_id}};
        my $entry = db->select_row('SELECT * FROM entries WHERE id = ?', $comment->{entry_id});
        $entry->{is_private} = ($entry->{private} == 1);
        next if ($entry->{is_private} && !permitted($entry->{user_id}));
        my $entry_owner = get_user($entry->{user_id});
        $entry->{account_name} = $entry_owner->{account_name};
        $entry->{nick_name} = $entry_owner->{nick_name};
        $comment->{entry} = $entry;
        my $comment_owner = get_user($comment->{user_id});
        $comment->{account_name} = $comment_owner->{account_name};
        $comment->{nick_name} = $comment_owner->{nick_name};
        push @$comments_of_friends, $comment;
        last if @$comments_of_friends+0 >= 10;
    }


    my $query = <<SQL;
SELECT f.user_id AS user_id, f.owner_id AS owner_id, DATE(f.created_at) AS date, MAX(f.created_at) as updated, u.account_name AS account_name, u.nick_name AS nick_name
FROM footprints f
INNER JOIN users u ON f.owner_id = u.id
WHERE f.user_id = ?
GROUP BY f.user_id, f.owner_id, DATE(f.created_at)
ORDER BY updated DESC
LIMIT 10
SQL
    my $footprints = [];
    $footprints = \@{db->select_all($query, session()->{user_id})};

    my $locals = {
        'user' => current_user(),
        'profile' => $profile,
        'entries' => $entries,
        'comments_for_me' => $comments_for_me,
        'entries_of_friends' => $entries_of_friends,
        'comments_of_friends' => $comments_of_friends,
        'friends' => $friends,
        'footprints' => $footprints
    };
    $c->render('index.tx', $locals);
};

get '/profile/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    my $owner = user_from_account($account_name);
    my $prof = db->select_row('SELECT * FROM profiles WHERE user_id = ?', $owner->{id});
    $prof = {} if (!$prof);
    my $query;
    if (permitted($owner->{id})) {
        $query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5';
    } else {
        $query = 'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5';
    }
    my $entries = [];
    for my $entry (@{db->select_all($query, $owner->{id})}) {
        $entry->{is_private} = ($entry->{private} == 1);
        $entry->{content} = $entry->{body};
        push @$entries, $entry;
    }
    mark_footprint($owner->{id});
    my $locals = {
        owner => $owner,
        profile => $prof,
        entries => $entries,
        private => permitted($owner->{id}),
        is_friend => is_friend($owner->{id}),
        current_user => current_user(),
        prefectures => prefectures(),
    };
    $c->render('profile.tx', $locals);
};

post '/profile/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    if ($account_name != current_user()->{account_name}) {
        abort_permission_denied();
    }
    my $first_name =  $c->req->param('first_name');
    my $last_name = $c->req->param('last_name');
    my $sex = $c->req->param('sex');
    my $birthday = $c->req->param('birthday');
    my $pref = $c->req->param('pref');

    my $prof = db->select_row('SELECT * FROM profiles WHERE user_id = ?', session()->{user_id});
    if ($prof) {
      my $query = <<SQL;
UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?
SQL
        db->query($query, $first_name, $last_name, $sex, $birthday, $pref, session()->{user_id});
    } else {
        my $query = <<SQL;
INSERT INTO profiles (user_id,first_name,last_name,sex,birthday,pref) VALUES (?,?,?,?,?,?)
SQL
        db->query($query, session()->{user_id}, $first_name, $last_name, $sex, $birthday, $pref);
    }
    redirect('/profile/'.$account_name);
};

get '/diary/entries/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    my $owner = user_from_account($account_name);
    my $query;
    if (permitted($owner->{id})) {
        $query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20';
    } else {
        $query = 'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20';
    }
    my $entries = [];
    for my $entry (@{db->select_all($query, $owner->{id})}) {
        $entry->{is_private} = ($entry->{private} == 1);
        $entry->{content} = $entry->{body};
        $entry->{comment_count} = db->select_one('SELECT COUNT(*) AS c FROM comments WHERE entry_id = ?', $entry->{id});
        push @$entries, $entry;
    }
    mark_footprint($owner->{id});
    my $locals = {
        owner => $owner,
        entries => $entries,
        myself => (session()->{user_id} == $owner->{id}),
    };
    $c->render('entries.tx', $locals);
};

get '/diary/entry/:entry_id' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $entry_id = $c->args->{entry_id};
    my $entry = db->select_row('SELECT * FROM entries WHERE id = ?', $entry_id);
    abort_content_not_found() if (!$entry);
    $entry->{content} = $entry->{body};
    $entry->{is_private} = ($entry->{private} == 1);
    my $owner = get_user($entry->{user_id});
    if ($entry->{is_private} && !permitted($owner->{id})) {
        abort_permission_denied();
    }
    my $comments = [];
    for my $comment (@{db->select_all('SELECT * FROM comments WHERE entry_id = ?', $entry->{id})}) {
        my $comment_user = get_user($comment->{user_id});
        $comment->{account_name} = $comment_user->{account_name};
        $comment->{nick_name} = $comment_user->{nick_name};
        push @$comments, $comment;
    }
    mark_footprint($owner->{id});
    my $locals = {
        'owner' => $owner,
        'entry' => $entry,
        'comments' => $comments,
    };
    $c->render('entry.tx', $locals);
};

post '/diary/entry' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $query = 'INSERT INTO entries (user_id, private, title, body) VALUES (?,?,?,?)';
    my $title = $c->req->param('title') || "タイトルなし";
    my $content = $c->req->param('content');
    my $private = $c->req->param('private');
    db->query($query, session()->{user_id}, ($private ? '1' : '0'), $title, $content);
    redirect('/diary/entries/'.current_user()->{account_name});
};

post '/diary/comment/:entry_id' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $entry_id = $c->args->{entry_id};
    my $entry = db->select_row('SELECT * FROM entries WHERE id = ?', $entry_id);
    abort_content_not_found() if (!$entry);
    $entry->{is_private} = ($entry->{private} == 1);
    if ($entry->{is_private} && !permitted($entry->{user_id})) {
        abort_permission_denied();
    }
    my $query = 'INSERT INTO comments (entry_id, user_id, comment) VALUES (?,?,?)';
    my $comment = $c->req->param('comment');
    db->query($query, $entry->{id}, session()->{user_id}, $comment);
    redirect('/diary/entry/'.$entry->{id});
};

get '/footprints' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $query = <<SQL;
SELECT f.user_id, f.owner_id, DATE(f.created_at) AS date, MAX(f.created_at) as updated, u.account_name AS account_name, u.nick_name AS nick_name
FROM footprints f
INNER JOIN users u ON f.owner_id = u.id
WHERE f.user_id = ?
GROUP BY f.user_id, f.owner_id, DATE(f.created_at)
ORDER BY updated DESC
LIMIT 50
SQL
    my $footprints = [];
    $footprints = \@{db->select_all($query, session()->{user_id})};

    $c->render('footprints.tx', { footprints => $footprints });
};

get '/friends' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;

    my $query = 'SELECT u.id, u.account_name, u.nick_name, r.created_at FROM users u INNER JOIN (SELECT one, another, created_at FROM relations WHERE one = ? OR another = ?) r ON u.id = r.another OR u.id = r.one ORDER BY r.created_at DESC';
    my %friends = ();
    my $friends = [];
    for my $rel (@{db->select_all($query, session()->{user_id}, session()->{user_id})}) {
        next if exists $friends{$rel->{id}};
        next if $rel->{id} eq session()->{user_id};
        $friends{delete $rel->{id}} = $rel;
        push @$friends, $rel;
    }
    #my $friends = [ sort { $a->{created_at} lt $b->{created_at} } values(%friends) ];
    $c->render('friends.tx', { friends => $friends });
};

post '/friends/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    if (!is_friend_account($account_name)) {
        my $user = user_from_account($account_name);
        abort_content_not_found() if (!$user);
        db->query('INSERT INTO relations (one, another) VALUES (?,?)', session()->{user_id}, $user->{id});
        redirect('/friends');
    }
};

get '/initialize' => sub {
    my ($self, $c) = @_;
    db->query("DELETE FROM relations WHERE id > 500000");
    db->query("DELETE FROM footprints WHERE id > 500000");
    db->query("DELETE FROM entries WHERE id > 500000");
    db->query("DELETE FROM comments WHERE id > 1500000");
};

1;
