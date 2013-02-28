#!/usr/bin/perl
use Net::LDAP qw(:all);

my $LDAPSERVER="ldap.t-systems.com";
my $LDAPBASE="o=debis Systemhaus";
my $LDAPSEARCHUSER=undef;
my $LDAPSEARCHPASS=undef;

if ($#ARGV==2){
   $LDAPSEARCHUSER=shift(@ARGV);
   $LDAPSEARCHPASS=shift(@ARGV);
}
printf("fifi0\n");

my $PASS=<STDIN>;
my $USER=$ARGV[0];
my $LDAPUSER="";

my $ldaph;

$PASS=~s/\s*//g;
$USER=~s/[^a-z0-9_-]//gi;   # security filter 


#
# uid DN suchen
#
if (($ldaph=new Net::LDAP($LDAPSERVER)) == -1){
   printf STDERR ("ERROR: Connection to %s Failed!",$host);
   exit(1);
}
#printf("fifi1\n");
#
# anonym anmelden
#
printf STDERR ("LDAPSEARCHUSER='$LDAPSEARCHUSER' ".
               "LDAPSEARCHPASS='$LDAPSEARCHUSER'\n");
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
my $filter="uid=$USER";
#printf ("filter=$filter\n");
my @attrs=("mail");
my $msg=$ldaph->search(base=>$LDAPBASE,
                       scope=>"sub",
                       filter=>$filter,
                       attrs=>\@attrs);
if ($msg->code){
    printf STDERR ("ERROR: ldaph->bind code=%d msg=%s\n",
                   $msg->code,$msg->error);
    exit(1);
}
foreach my $ent ($msg->entries()){
   $LDAPUSER=$ent->dn();
}
if ($LDAPUSER eq ""){
   printf STDERR ("ERROR: Can't Find User\n");
   exit(1);
}
$msg=$ldaph->unbind();
if (($ldaph=new Net::LDAP($LDAPSERVER)) == -1){
   printf STDERR ("ERROR: Connection to %s Failed!",$host);
   exit(1);
}
$msg=$ldaph->bind($LDAPUSER,password=>$PASS);
if ($msg->code){
    printf STDERR ("ERROR: ldaph->bind code=%d msg=%s\n",
                   $msg->code,$msg->error);
    exit(1);
}
printf STDERR ("LDAPUSER=$LDAPUSER\n");
exit(0);







