# ADDomainDaclAnalysis
Outputs the permissions granted on the root AD domain and AdminSDHolder objects of all domains in the current forests into CSV files in the current directory.

Also searches for specific elevated permissions granted for Exchange groups that should be removed, and outputs the analysis into a text file.
See the following links for additional information on the matter:
https://support.microsoft.com/en-us/topic/reducing-permissions-required-to-run-exchange-server-when-you-use-the-shared-permissions-model-e1972d47-d714-fd76-1fd5-7cdcb85408ed
https://adsecurity.org/?p=4119 (🙏 Sean Metcalf).

Requires AD PowerShell module, from the RSAT toolbox, since it runs the "Get-ADObject" and "Get-ADForest" commands.

Not thoroughly tested. No guarantees.
