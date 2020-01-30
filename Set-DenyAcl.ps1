<#FileSystemRights  : Delete
AccessControlType : Deny
IdentityReference : %DOMAINNAME%\%Customer%-Share-Documents-Standard
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None
#>

#New-Object System.Security.AccessControl.FileSystemAccessRule($IdentityReference, $FileSystemRights, $AccessControlType)
#New-Object System.Security.AccessControl.FileSystemAccessRule($IdentityReference, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)


#region variables
$share = "D:\Projekte"
$identityRef = "DOMAIN\KG-Share-Documents-Standard"
$domainName = "DOMAIN"
$accountName = "Owner"
$logFilePath = "C:\AdminScripts\AclLog.txt"
#endregion variables


#region code
$directories = Get-ChildItem $share -Directory
#$directories
$cycleCount = 0
$ownerRef = $domainName + "\" + $accountName


foreach ($directory in $directories) {
    Write-Host "Working on $directory" -NoNewline
    $acl = Get-Acl $directory.FullName
    Write-Host ", Owner:" $acl.Owner

    $denyRules = @($acl.Access | ? AccessControlType -eq Deny)
    if (($denyRules.Length -eq 0) -or ($acl.Owner -ne $ownerRef)) {
        if ($cycleCount -eq 0) {
            Add-Content -Path $logFilePath (Get-Date -Format "yyyy-MM-dd hh:mm")
            $cycleCount++
        }
        
        if ($denyRules.Length -eq 0) {
            Add-Content -Path $logFilePath "Adding AccessRule to $directory"
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($identityRef,"Delete","None","None","Deny")
            $acl.AddAccessRule($accessRule)
        }

        if ($acl.Owner -ne $ownerRef) {
            Add-Content -Path $logFilePath "Changing Owner for $directory from " -NoNewline
            Add-Content -Path $logFilePath $acl.Owner -NoNewline
            Add-Content -Path $logFilePath " to $domainName\$accountName"
            $Account = New-Object System.Security.Principal.NTAccount($domainName,$accountName)
            $acl.SetOwner($Account)
        }

        Set-Acl $directory.FullName -AclObject $acl
    }
}
#endregion code
