 <#
.SYNOPSIS
A password audit tool that checks hashes of passwords in AD against weak passwords in blacklists
        
.DESCRIPTION
The script checks how many user accounts use a password in the blacklist, how many users that have
passwords that never expire and how many passwords are reused between users. This information 
is given for each blacklist file provided.
        
.PARAMETER blacklists
Blacklist files, including paths, to use. If nothing is provided script shall search localy for top_10.txt, top_100.txt, top_10000.txt and top_10_augmented.txt'
        
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

 param (
    [string[]] $blacklists =  @('top_10.txt', 'top_100.txt', 'top_10000.txt', 'top_1000.txt', 'top_1000_mangled.txt'),
    [Parameter(Mandatory=$True)]
    [string]$DC,
    [Parameter(Mandatory=$True)]
    [string]$NC,
    [Parameter(Mandatory=$True)]
    [string]$organisation,
    [string]$type = 'User',
    [bool]$unsuppress = 0
 )

$version = '1.2'
$result_file = "results.txt"
$result_json = "results.json"

if ($unsuppress){
    Write-Host "WARNING: The results of this script may contain usernames and plaintext passwords. DO NOT SEND UNSUPPRESSED OUTPUT TO NCSC. THIS OPTION IS FOR YOUR INTERNAL USE ONLY"
}


# Import required DSInternals modules
# This assumes that the DSInternals folder is a subfolder to where this script has been copied
# This means that DSInternals does not have to be copied to C:\Windows\System32\WindowsPowerShell\v1.0\Modules
Import-Module .\DSInternals\DSInternals.psm1
Import-Module .\DSInternals\DSInternals.PowerShell.dll

Try
{

    $TimeNow = Get-Date -Format dd.MM.yyyy-HH:mm:ss
    #$json_output = @()

    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $Stopwatch.start()

    $accounts = Get-ADReplicationAccount -All -Server $DC -NamingContext $NC |
    Where {$_.SamAccountType -eq $type} -ErrorAction Stop

    #clear results files and write header information
    If (Test-Path $result_file){
        Clear-Content $result_file
    }
    If (Test-Path $result_json){
        Clear-Content $result_json
    }

    "PWAuditor " + $version >> $result_file
    "`n" >> $result_file
    "Organisation: " + $organisation >> $result_file
    "Number of User Accounts: " + $accounts.Count >> $result_file
    "`n" >> $result_file

    if ($unsuppress){
        "******DUPLICATED PASSWORDS******" >> $result_file
        "`n" >> $result_file

        #show number of duplicated passwords
        $result = $accounts | Test-PasswordQuality -IncludeDisabledAccounts
        "Total number of duplicated passwords: " + $result.DuplicatePasswordGroups.Count >> $result_file

        $duplicatedPwds = @()

        #Display how many users reused each duplicated password - Note this is not just for weak passwords but for all
        $count = 0
        ForEach($group in $result.DuplicatePasswordGroups){
            $count++

            "- Number of duplicates of duplicated password number " + $count + ": " + $group.Count >> $result_file

            $hashTables = @()
    
            ForEach($file in $blacklists){
                $Dictionary = Get-Content $file
                $DictionaryHashes = ConvertTo-NTHashDictionary -Input $Dictionary
                $properties = @{'DictionaryFileName' = $file;
                                'Hashes' = $DictionaryHashes}
                $object = New-Object -TypeName PSObject -Prop $properties
                $hashTables += $object 
            }

            $accountWithDuplicatedPwd = $accounts | Where {$_.SamAccountName -eq $group[0]}
            $duplicatedPwdNTHash = $accountWithDuplicatedPwd.NTHash

            $Blacklisted = "NO"
            $BlacklistedPwd = ""
            $BlacklistFile = "" ##Assumes passwords are not duplicated across blacklist files otherwise only get last blacklist file that password is in
        
            ForEach($hashTableObject in $hashTables){
                if ($hashTableObject.hashes.ContainsKey($duplicatedPwdNTHash)){
                    "This duplicated password is also in the blacklisted password dictionary: " + $hashTableObject.DictionaryFileName >> $result_file
                    "The duplicated password is: " + $hashTableObject.hashes[$duplicatedPwdNTHash] >> $result_file
                    $BlackListed = "YES"
                    $BlacklistedPwd = $hashTableObject.hashes[$duplicatedPwdNTHash]
                    $BlacklistFile = $hashTableObject.DictionaryFileName
                }
            }

            "The following users share this password: " >> $result_file
            $group | ForEach-Object{"`t" + $_} >> $result_file
            "`n" >> $result_file

            $properties = [ordered]@{'GroupNo' = $count;
                        'NumberOfUsersWithThisPwd' = $group.Count;
                        'Blacklisted' = $Blacklisted;
                        'BlacklistedPwd' = $BlacklistedPwd;
                        'BlacklistFile' = $BlacklistFile;
                        'UsersWithThisPassword' = $group}
            $duplicatedPwdsObject = New-Object -TypeName PSObject -Prop $properties

            $duplicatedPwds += $duplicatedPwdsObject

        }

        "`n" >> $result_file
        "******DUPLICATED PASSWORDS******" >> $result_file
        "`n" >> $result_file
        "******WEAK PASSWORDS******" >> $result_file
    
        $WeakPwds = @()
        $WeakPwdsCount = @()

        ForEach($file in $blacklists){
            $Dict = Get-Content $file
            $hashdictionary = ConvertTo-NTHashDictionary -Input $Dict

            $result = $accounts | Test-PasswordQuality -WeakPasswordHashes $hashdictionary -IncludeDisabledAccounts -ShowPlainTextPasswords

            "`n" >> $result_file

            "Results for file: " + $file >> $result_file
            "Number of blacklisted passwords used: " + $result.WeakPassword.Count >> $result_file

            if ($result.WeakPassword.Count -gt 0){
                "The users and bad passwords found are as follows:" >> $result_file
                $result.WeakPassword >> $result_file
                "`n" >> $result_file

                $detailedWeakPasswordTable = @()

                ForEach($key in $result.WeakPassword.Keys){
                    $duplicated = "NO"
                    $usersThatSharePwd = @()
                    if ($result.PasswordNeverExpires -contains $key){
                        $neverExpires = "TRUE"                        
                    }
                    ForEach($group in $result.DuplicatePasswordGroups){
                        if ($group -contains $key){
                            $duplicated = "YES"
                            $NumberOfUsersWithSamePwd = $group.Count
                            $usersThatSharePwd = $group
                        }
                    }
                    $properties = [ordered]@{'SamAccountName' = $key;
                                             'Password' = $result.WeakPassword[$key];
                                             'Duplicated' = $duplicated;
                                             'NumberOfUsersWithSamePwd' = $NumberOfUsersWithSamePwd
                                             'UsersThatHaveSamePassword' = $usersThatSharePwd}
                    $object = New-Object -TypeName PSObject -Prop $properties
                    $detailedWeakPasswordTable += $object
                }

                "The detailed table for users with bad passwords from this dictionary file is as follows:" >> $result_file
                $detailedWeakPasswordTable | Format-Table -Property SamAccountName, Password, Duplicated, NumberOfUsersWithSamePwd, UsersThatHaveSamePassword >> $result_file 

                $properties = [ordered]@{'BlackListFile' = $file;
                                         'Results' = $detailedWeakPasswordTable}
                $WeakPwdsObject = New-Object -TypeName PSObject -Prop $properties
                $WeakPwds += $WeakPwdsObject

                $WeakPwdsCountHashTable = @{}

                ForEach($key in $result.WeakPassword.Keys){
                    if ($WeakPwdsCountHashTable[$result.WeakPassword[$key]]){
                        $WeakPwdsCountHashTable[$result.WeakPassword[$key]] += 1
                    }
                    else{
                        $WeakPwdsCountHashTable[$result.WeakPassword[$key]] = 1
                    }
                }

                $properties = [ordered]@{'BlackListFile' = $file;
                                         'BadPasswordsCounts' = $WeakPwdsCountHashTable}
                $WeakPwdsCountObject = New-Object -TypeName PSObject -Prop $properties
                $WeakPwdsCount += $WeakPwdsCountObject

                'The count of unique weak passwords found for users from this dictionary is as follows: ' >> $result_file
                $WeakPwdsCountHashTable >> $result_file

            }

         }

       
        "`n" >> $result_file
        "******WEAK PASSWORDS******" >> $result_file

        $properties = [ordered]@{'PWAuditorVersion' = $version;
                                 'Organisation' = $organisation;
                                 'NumberOfUserAccounts' = $accounts.Count;
                                 'RunOn' = $TimeNow;
                                 'DuplicatedPwdResults' = $duplicatedPwds;
                                 'WeakPwdsResults' = $WeakPwds;
                                 'WeakPwdsCounts' = $WeakPwdsCount}

        $PWAuditorObject = New-Object -TypeName PSObject -Prop $properties
    
    }
    else{

        #show number of duplicated passwords
        $result = $accounts | Test-PasswordQuality -IncludeDisabledAccounts
        "Total number of duplicated passwords: " + $result.DuplicatePasswordGroups.Count >> $result_file

        $duplicatedPwds = @()

        #Display how many users reused each duplicated password - Note this is not just for weak passwords but for all
        $count = 0
        ForEach($group in $result.DuplicatePasswordGroups){
            $count++

            "- Number of duplicates of duplicated password number " + $count + ": " + $group.Count >> $result_file       

            $properties = [ordered]@{'GroupNo' = $count;
                                    'NumberOfUsersWithThisPwd' = $group.Count}
            $duplicatedPwdsObject = New-Object -TypeName PSObject -Prop $properties

            $duplicatedPwds += $duplicatedPwdsObject
        }
   
    
        $WeakPwds = @()

        ForEach($file in $blacklists){
            $Dict = Get-Content $file
            $hashdictionary = ConvertTo-NTHashDictionary -Input $Dict

            $result = $accounts | Test-PasswordQuality -WeakPasswordHashes $hashdictionary -IncludeDisabledAccounts

            "Results for file: " + $file >> $result_file
            "Number of blacklisted passwords used: " + $result.WeakPassword.Count >> $result_file

            $properties = [ordered]@{'BlackListFile' = $file;
                                     'TotalPasswords' = $result.WeakPassword.Count}
            $WeakPwdsObject = New-Object -TypeName PSObject -Prop $properties
            $WeakPwds += $WeakPwdsObject
        }

        $properties = [ordered]@{'PWAuditorVersion' = $version;
                                 'Organisation' = $organisation;
                                 'NumberOfUserAccounts' = $accounts.Count;
                                 'RunOn' = $TimeNow;
                                 'DuplicatedPwdResults' = $duplicatedPwds;
                                 'WeakPwdsResults' = $WeakPwds}

        $PWAuditorObject = New-Object -TypeName PSObject -Prop $properties

    }

    $StopWatch.stop()

    "`n" >> $result_file
    "Time taken to run: " + $StopWatch.Elapsed.Milliseconds + "ms" >>  $result_file
    "Run on: " + $TimeNow >> $result_file

    $json_output = $PWAuditorObject | ConvertTo-Json -depth 5
    $json_output > $result_json

    Write-Host "Command written successfully and output written to results.txt and results.json"
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Host "Error: " $ErrorMessage " " $FailedItem

    #if script errors delete output files if they exist
    Write-Host "Command failed"
    If (Test-Path $result_file){
        Remove-Item $result_file
    }
    If (Test-Path $result_json){
        Remove-Item $result_json
    }
    Exit
}