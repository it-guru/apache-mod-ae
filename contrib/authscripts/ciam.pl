#!/usr/bin/perl
use Net::LDAP;
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

if (!($username=~m/^.+\@.+$/)){
   printf STDERR ("INFO: Remapping needed\n");
   my $LDAPSERVER=$ARGV[2];
   my $LDAPSEARCHUSER=$ARGV[3];
   my $LDAPSEARCHPASS=$ARGV[4];
   my $LDAPBASE="ou=Person,o=DTAG";
   my $ldaph;
   my $msg;
   
   #
   # uid DN suchen
   #
   $ldaph=new Net::LDAP($LDAPSERVER);
   if (!defined($ldaph) || ($ldaph) == -1){
      printf STDERR ("ERROR: Connection to %s Failed!\n",$LDAPSERVER);
      exit(1);
   }
   #
   # anonym anmelden
   #
   #printf STDERR ("LDAPSEARCHUSER='$LDAPSEARCHUSER' ".
   #               "LDAPSEARCHPASS='$LDAPSEARCHUSER'\n");
   if ($LDAPSEARCHUSER){
      $msg=$ldaph->bind($LDAPSEARCHUSER,password=>$LDAPSEARCHPASS);
   }
   else{
      $msg=$ldaph->bind();
   }

   if ($msg->code){
       printf STDERR ("ERROR: ldaph->bind code=%d msg=%s\n",
                      $msg->code,$msg->error);
       exit(1);
   }
   my @attrs=("mail");
   my %flt=(
      base=>$LDAPBASE,
      scope=>"sub",
      attrs=>\@attrs
   );
   if ($username=~m/^a\d{3,10}$/i){
      # Username is a tCID and needs to be translated
      $username=~s/^a//;
      $flt{filter}="(tcid=$username)";
   }
   elsif ($username=~m/^\d{3,10}$/){
      # Username is a tCID and needs to be translated
      $flt{filter}="(tcid=$username)";
   }
   elsif ($username=~m/^[a-z0-9]{4,8}$/){
      # Username is eine WIWID
      $flt{filter}="(twiw-uid=$username)";
   }
   else{
      exit(1);
   }
   $flt{filter}="(&(tisActive=true)(tisPrimary=true)$flt{filter})";

   printf STDERR ("INFO: remap filter=%s\n",$flt{filter});
   my $msg=$ldaph->search(%flt);
   if ($msg->code){
       printf STDERR ("ERROR: ldaph->bind code=%d msg=%s\n",
                      $msg->code,$msg->error);
       exit(1);
   }
   my $remapped=0;
   LDAPFILTER: foreach my $entry ($msg->entries()){
      foreach my $attr ($entry->attributes) {
         if ($attr eq "mail"){
            my @val=$entry->get_value($attr);
            @val=grep(!/^\s*$/,@val);
            if ($val[0] ne ""){
               $username=$val[0];
               $remapped++;
               last LDAPFILTER;
            }
         }
      }
   }
   $msg=$ldaph->unbind();
   if (!$remapped){
      printf STDERR ("ERROR: user remap failed\n");
      exit(1);
   }
   printf STDERR ("INFO: User remaped to $username\n");
}





my $password=<STDIN>;
$password=~s/\s$//;
#printf STDERR ("using CIAM URL='%s'\nusername='%s'\n",$ciamurl,$username);
my $uaCookies=HTTP::Cookies->new();
$ua->cookie_jar($uaCookies);
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
   if (lc($tag) eq "input" || lc($tag) eq "scale-text-field"){
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
if (!exists($form{userId}) || !exists($form{password})){
   printf STDERR ("ERROR: can not found userId or password field in form\n");
   exit(1);
}

$form{userId}=$username;
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

$uaCookies->extract_cookies($response);

my $loginOK=0;
$uaCookies->scan(sub{
   my $version=shift;
   my $key=shift;
   my $val=shift;

   $loginOK++ if ($key eq "PD-S-SESSION-ID" && $val ne "");
   $loginOK++ if ($key eq "PD-ID" && $val ne "");
});

if ($loginOK!=2){
   printf STDERR ("unexpected OK response page\n");
   exit(1);
}
printf STDERR ("OK\n");
exit(0);

