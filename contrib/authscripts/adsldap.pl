#!/usr/bin/perl
################################################################################
# Andreas Wieschollek <andreas.wieschollek@telekom.de>
# 2019-10-18
# vim: ai et sts=3 sw=3 ft=perl :
################################################################################
use strict;
use warnings;
use Net::LDAP;
use Data::Dumper;

# 
# supports logon by f.e. emea1/a123456 or emea1/hans.meier@t-systems.com 
# (which means sAMAccountName or userPrincipalName field in ADS-LDAP)
# 

my $rc = 1;
my $mesg;
my $domain = $ARGV[1];    # Domain name f.e. emea1
my $host   = $ARGV[2];    # Domain Entry of AD f.e. emea1.cds.t-internal.com
my $user   = $ARGV[0];    # Username from aetools.conf = %U


$user=lc($user);
$user=~s/[^a-z0-9\@_.-]/x/gi;

printf STDERR ("using: $user\n");

local $SIG{ALRM}=sub{ 
   printf STDERR ("Timeout Exitcode=101\n");
   exit(101);
};
alarm(30);

my $bind = join('\\', $domain, $user);
my $chkFilter="sAMAccountName=".uc($user);
my $base="DC=$domain,DC=cds,DC=t-internal,DC=com";
if ($user=~m/\@/){
   $bind=$user;
   $chkFilter="userPrincipalName=".$user;
}
my $pass = <STDIN>;
chomp($pass);

sub LDAPerrorHandler
{
   my ($from, $mesg) = @_;

   if (defined($from) && defined($from->error)){
      printf STDERR ("LDAP-Error: %s\n",$from->error);
   }
   $rc=1;
}

my $ldap = Net::LDAP->new($host, 
    scheme => 'ldaps', 
    timeout => 5, 
    onerror => \&LDAPerrorHandler
);
$mesg=$ldap->bind($bind,password=>$pass);
if ($mesg){
   $mesg=$ldap->search(base=>$base,filter=>$chkFilter,attrs=>['dn']);
   if (ref($mesg) && $mesg->entries){
      foreach my $entr ($mesg->entries()) {
        printf("DN: '%s'\n",$entr->dn);
      }   
      $rc=0;
   }
}

$mesg=$ldap->unbind;

printf STDERR ("Exitcode=$rc\n");

exit($rc);

1;

