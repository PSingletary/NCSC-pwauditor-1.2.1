# pwauditor
Password Auditor Tool

Use Steps
0. Download the DSInternals PowerShell libraries [https://www.powershellgallery.com/packages/DSInternals/2.22] and place the DSInternals root folder into the same folder as this script
1. Run the pwauditor command as per EXAMPLE below
2. Retrieve the results from results.txt and results.json in the pwauditor folder
3. If you are happy to, send the results.txt file to NCSC. This file contains anonymous high-level statistics which we can use within our research projects.

OPTIONAL
4. Run the pwauditor command again using "-unsuppress 1" to generate de-anonymised data for your own use
5. DO NOT SEND UNSUPPRESSED OUTPUT TO NCSC

This script requires Windows Management Framework 3.0 (often installed by default).

<#
.SYNOPSIS
A password audit tool that checks hashes of passwords in AD against weak passwords in blacklists, and looks for duplicated passwords
        
.DESCRIPTION
The script checks how many user accounts use a password in the blacklist, how many users that have
passwords that never expire and how many passwords are reused between users. This information 
is given for each blacklist file provided.
        
.PARAMETER blacklists
Blacklist files, including paths, to use. If nothing is provided script shall search localy for top_10.txt, top_100.txt, top_10000.txt and top_10_augmented.txt
        
.PARAMETER DC
The domain controller domain name e.g. password.com
Use powershell comand Get-ADDomainController command and use parameter called Domain
        
.PARAMETER NC
The domain controllers Naming Context e.g. dc=pw,dc=com
Use powershell comand Get-ADDomainController and use parameter called DefaultPartition

.PARAMETER organisation
The organisation that owns the domain controller this is being run on. This is only used to differentiate result sets and is a user defined string e.g. "NCSC".

.PARAMETER type - Optional
The AD account type (e.g. 'User'), default is User

.PARAMTER unsuppress - Optional
Changes the output to show detailed results that includes:
* all accounts that share same password and if that password is blacklisted
* all accounts that have a weak password (one in blacklist) including plaintext password
        
.EXAMPLE 
.\pwauditor -DC PW.com -NC "dc=pw,dc=com" -organisation NCSC
Script will look for the following blacklist in the same path as it
top_10.txt, top_100.txt, top_10000.txt
Result is count of weak passwords and duplicated passwords both to screen and to text file 
    Results for file: top_10000.txt
    Number of blacklisted passwords used : 12
    Number of duplicated passwords       : 5
    - Number of duplications of password 1 : 2
    - Number of duplications of password 2 : 3
    - Number of duplications of password 3 : 5
    - Number of duplications of password 4 : 2
    - Number of duplications of password 5 : 2
Time to run:  1140 ms


.EXAMPLE
.\pwauditor -DC PW.com -NC "dc=pw,dc=com" -blacklists top_10.txt,top100.txt,top_1000.txt,top_10_augmented.txt -organisation NCSC
If you want to specify your own blacklist files then use the -blacklists argument
    
.NOTES
Must be run with admin privilages on the Domain Controller
        
.DEPENDENCIES
Uses module DSInternals, which should be placed, unzipped, in the same folder as this script

.OUTPUT
The results are written to results.txt and results.json in same folder as the script is run    
#>