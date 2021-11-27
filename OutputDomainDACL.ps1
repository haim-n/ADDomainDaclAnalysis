# This script outputs all permissions granted on the domain root and AdminSDHolder objects of all domains in the current forest into CSV files, and also looks for specific elevated permissions granted for Exchange groups that should be removed.

# file outputs:
$RootCSV = "_DomainRootPermissions.csv"
$AdminSDHolderCSV = "_AdminSDHolderPermissions.csv"
$generalOutput = "ADRootPermissionsAnalysis.txt"

# delete existing file
if (Test-Path $generalOutput) {Remove-Item $generalOutput}

# import AD module, exit script if the module doesn't exist
Import-Module activedirectory -ErrorAction SilentlyContinue
if (!(Get-Module activedirectory))
{
    Write-Host The Active Directory PowerShell module could not be imported. -ForegroundColor Yellow
    Write-Host Please run the script on a machine with AD RSAT tools installed. -ForegroundColor Yellow
    exit
}

# get all domains in the forst
$Domains = (Get-ADForest).domains

# loop over all domains
foreach ($Domain in $Domains)
{
    $Domain + " domain:" | Out-File $generalOutput -Append
    "------------------------" | Out-File $generalOutput -Append
    # check permissions on domain root object
    "$Domain root object:`n" | Out-File $generalOutput -Append
    $DomainRootDN = (Get-ADDomain).DistinguishedName
    $DomainRootPermissions = (Get-ADObject $DomainRootDN -Properties *).nTSecurityDescriptor.access
    # export to CSV
    $DomainRootPermissions | export-csv ($Domain + $RootCSV) -NoTypeInfo
    Write-Host Exported $domain domain root object permissions into ($Domain + $RootCSV) -ForegroundColor Green
    "All permissions granted on the $Domain domain root object were exported into " + ($Domain + $RootCSV) +"`n." | Out-File $generalOutput -Append
    # specifically check for overly permissive WriteDACL ACEs that were remediated in Exchange 2019 CU1, Exchange 2016 CU 12, Exchange 2013 CU22
    # see this for details: https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed
    $PermissiveDomainRootPermissions = $DomainRootPermissions | ? {($_.ActiveDirectoryRights -like "*WriteDacl*") -and ($_.IdentityReference -eq "ESLAB\Exchange Windows Permissions") -and ($_.PropagationFlags -ne "InheritOnly")}
    if ($PermissiveDomainRootPermissions -eq $null)
    {
        "The Exchange Windows Permissions group doesn't have rights to modify the permissions of the $domain domain root object." | Out-File $generalOutput -Append
        "This is the hardended configuration." | Out-File $generalOutput -Append
        "See the following links for more information on this matter:" | Out-File $generalOutput -Append
        "https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed" | Out-File $generalOutput -Append
        "https://adsecurity.org/?p=4119" | Out-File $generalOutput -Append
    }
    else
    {
        "It seems that the Exchange Windows Permissions group has rights to modify the permissions of the $domain domain root object." | Out-File $generalOutput -Append
        "This is NOT SECURE and should be mitigated. This means that Exchange server objects can escalate permissions by modifying the domain root object's permissions, granting replication permissions and performing DCSync." | Out-File $generalOutput -Append
        "See the following links for more information on this matter:" | Out-File $generalOutput -Append
        "https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed" | Out-File $generalOutput -Append
        "https://adsecurity.org/?p=4119" | Out-File $generalOutput -Append
        "`nThe actual permissions found are:" | Out-File $generalOutput -Append
        $PermissiveDomainRootPermissions | Out-File $generalOutput -Append
    }
    "------------------------" | Out-File $generalOutput -Append
    # check permissions on domain AdminSDHolder object
    "$Domain AdminSDHolder object:`n" | Out-File $generalOutput -Append
    $AdminSDHolderDN = "CN=AdminSDHolder,CN=System," + $DomainRootDN
    $AdminSDHolderPermissions = (Get-ADObject $AdminSDHolderDN -Properties *).nTSecurityDescriptor.access
    # export to CSV
    $AdminSDHolderPermissions | export-csv ($Domain + $AdminSDHolderCSV) -NoTypeInfo
    Write-Host Exported $domain AdminSDHolder object permissions into ($Domain + $AdminSDHolderCSV) -ForegroundColor Green
    "All permissions granted on the $Domain AdminSDHolder object were exported into " + ($Domain + $AdminSDHolderCSV) +"`n." | Out-File $generalOutput -Append
    # specifically check for overly permissive WriteDACL ACE that was remediated in Exchange 2019 CU1, Exchange 2016 CU 12
    # see this for details: https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed
    $PermissiveAdminSDHolderPermissions = $AdminSDHolderPermissions | ? {($_.ActiveDirectoryRights -like "*WriteDacl*") -and ($_.IdentityReference -eq "ESLAB\Exchange Trusted Subsystem")}
        if ($PermissiveAdminSDHolderPermissions -eq $null)
    {
        "The Exchange Trusted Subsystem group doesn't have rights to modify the permissions of $domain objects protected by AdminSDHolder (i.e., objects with admincount=1 such as the Domain Admins group)." | Out-File $generalOutput -Append
        "This is the hardended configuration." | Out-File $generalOutput -Append
        "See the following link for more information on this matter:" | Out-File $generalOutput -Append
        "https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed" | Out-File $generalOutput -Append
    }
    else
    {
        "It seems that the Exchange Trusted Subsystem group has rights to modify the permissions of $domain objects protected by AdminSDHolder (i.e., objects with admincount=1 such as the Domain Admins group)." | Out-File $generalOutput -Append
        "This is NOT SECURE and should be mitigated. This means that Exchange server objects can escalate permissions by modifying highly privileged domain groups." | Out-File $generalOutput -Append
        "See the following link for more information on this matter:" | Out-File $generalOutput -Append
        "https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed" | Out-File $generalOutput -Append
        "`nThe actual permissions found are:" | Out-File $generalOutput -Append
        $PermissiveAdminSDHolderPermissions | Out-File $generalOutput -Append
    }    
    "========================`n" | Out-File $generalOutput -Append
}
Write-Host See the $generalOutput file for analysis of potentially overly permissive and risky Exchange permissions. -ForegroundColor Green