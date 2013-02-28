#!/usr/bin/perl
use strict;
use Data::Dumper;
use HTML::Parser;
use LWP::UserAgent;
use HTTP::Cookies;
use HTTP::Request::Common;


delete($ENV{HTTP_PROXY});
delete($ENV{HTTPS_PROXY});
delete($ENV{http_proxy});
delete($ENV{https_proxy});

my $ua=new LWP::UserAgent();

my $ciamurl=$ARGV[0];
my $username=$ARGV[1];
my $password=<STDIN>;
$password=~s/\s$//;
#printf STDERR ("using CIAM URL='%s'\nusername='%s'\n",$ciamurl,$username);

my $response=$ua->request(GET($ciamurl));
if ($response->code ne "200"){
   print STDERR ($response->content());
   printf STDERR ("ERROR: fail to get loginurl $ciamurl\n");
   exit(1);
}

my $parser=new HTML::Parser();

my %form=();

$parser->handler(start=>sub {
   my ($pself,$tag,$attr)=@_;
   if (lc($tag) eq "input"){
      if (exists($form{"$attr->{name}"}) &&
          !ref($form{"$attr->{name}"})){
         $form{"$attr->{name}"}=[$form{"$attr->{name}"}];
      }
      if (ref($form{"$attr->{name}"})){
         push(@{$form{"$attr->{name}"}},"$attr->{value}");
      }
      else{
         $form{"$attr->{name}"}="$attr->{value}";
      }
   }
},'self, tagname, attr');

$parser->parse($response->content());
if (!exists($form{email}) || !exists($form{password})){
   printf STDERR ("ERROR: can not found email or password field in form\n");
   exit(1);
}

$form{email}=$username;
$form{password}=$password;

my $request=POST($ciamurl,Content_Type=>'application/x-www-form-urlencoded',
                          Content=>[%form]);
my $response=$ua->request($request);
if ($response->code ne "200"){
   print STDERR ($response->content());
   printf STDERR ("ERROR: invalid response after login\n");
   exit(1);
}
if (grep(/Your e-mail address or password is incorrect/,$response->content())||
    grep(/class="error"/,$response->content())){
   printf STDERR ("Your e-mail address or password is incorrect\n");
   exit(1);
}
if (!grep(/var\s+redir\s+=\s+base/,$response->content())){
   printf STDERR ("unexpected OK response page\n");
   exit(1);
}
printf STDERR ("OK\n");
exit(0);

