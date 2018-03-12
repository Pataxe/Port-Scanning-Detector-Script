<#
    .SYNOPSIS
    Connect to the local or remote firewall and enable logging then watch and alert the user in the event of a network scan being detected by the script

    .DESCRIPTION
    A tool to provide the user a way to enable local or remote firewalls and then monitor the firewall logs for port scans on the system.

    .PARAMETER OpenPorts
    These will be optional ports that the firewall will keep open

    .EXAMPLE
    .\fw.ps1 80, 443
    This would open ports 443 and 80 and block all the rest when running this script
    Example Output:
                        Checking log for scanning attempts
                        Sleeping for 1 minute . . . . . . . . . . . . . . . . . . . . . . . .
                        Checking log for scanning attempts
                        Sleeping for 1 minute . . . . . . . . . . . . . . . . . . . . . . . .
                        Checking log for scanning attempts
                        Sleeping for 1 minute . . . . . . . . . . . . . . . . . . . . . . . .
                        Checking log for scanning attempts
                        Possible Scan Attempt detected from IP Address 10.0.1.133, please check C:\Logs\Keep_For_Analysis\scan_attempts.log
                        Sleeping for 1 minute . . . . . . . . . . . . . . . . . . . . . . . .
                        Checking log for scanning attempts
                        Sleeping for 1 minute . . . . . . . . . . . . . . .

    .NOTES
    ********* You need to run this as an administrator **********
    Windows firewall only logs dropped packets on ports that it currently has services running on.
    So if you do not see a lot of scans it does not mean that they didnt happen, it just doesnt get logged
    Sources:
    https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=win10-ps
    https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=win10-ps
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_split?view=powershell-6
    https://blogs.technet.microsoft.com/heyscriptingguy/2014/07/17/using-the-split-method-in-powershell/
    Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4
    Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4
    Created by Patrick Maher - CSC 443
#>

param ([Parameter()][ValidateCount(1,20)] [string[]]  $OpenPorts)

#where to store the firewall logs
$logname = "C:\Logs\pfirewall.log"
$temp_logname = "C:\Logs\pfirewall_temp.log"
#where to copy the file to for later analysis
$preserve_location = "C:\Logs\Keep_For_Analysis\scan_attempts.log"
$log_directory = "C:\Logs\Keep_For_Analysis\"
#Check if the file locations exits and if not then create them
New-Item -ErrorAction Ignore -ItemType directory -Path $log_directory | Out-Null
#counter for possible scan attempts
$scan_counter = 0
#get the ips for the Host
$ips= Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4 | ForEach-Object -MemberName IPAddress
#get the dns ips so that they can be excluded
$dns_ips = Get-WmiObject Win32_NetworkAdapterConfiguration | ForEach-Object -MemberName DNSServerSearchOrder
#boolean variable to keep the result of the postive match found
$scan_found = $false
#store the ips to block here
$ips_to_block = @()

#enable the firewall
 set-NetFirewallProfile -Enabled True
#enable logging for blocked connections
 set-NetFirewallProfile -LogAllowed False -LogBlocked True -LogFileName $logname
 #get a list of all the firewall rule names for the next loop
 $fw_rule_names = get-netfirewallRule | foreach-object -membername DisplayName

#create rule to block all inbound, returning packets will be allowed - Windowws only allows port ranges by Protocol, can add more protocols later
if($fw_rule_names -notcontains "Block All Ports - Inbound TCP")
{new-NetFirewallRule -DisplayName "Block All Ports - Inbound TCP" -Description "Blocks all inbound ports" -Direction Inbound  -Protocol TCP -LocalPort 1-65535 -Action Block | out-null
 new-NetFirewallRule -DisplayName "Block All Ports - Inbound UDP" -Description "Blocks all inbound ports" -Direction Inbound  -Protocol UDP -LocalPort 1-65535 -Action Block | out-null}
#if this is a server add ports to leave open rule, specified on the cli
ForEach ($port in $OpenPorts)
{
  $rule_name = "Blacklist Exception for Port $port"
  if($fw_rule_names -notcontains $rule_name)
  #assumes TCP, should be anther parameter to be more robust
  { new-NetFirewallRule -DisplayName $rule_name -Description "Allow inbound traffic on port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | out-null}
}

#define two new ojects to store the current and previous log file entries for comparision
#New-Object System.Object #define the Object
$currentEntryObject=New-Object System.Object
$previousEntryObject=New-Object System.Object
$objectArray = @($currentEntryObject, $previousEntryObject)
#add & initialize members of the two new objects
foreach($obj in $objectArray)
{
  $obj | Add-Member -type NoteProperty -Name "Date" -Value ""
  $obj | Add-Member -type NoteProperty -Name "Time" -Value ""
  $obj | Add-Member -type NoteProperty -Name "Action" -Value ""
  $obj | Add-Member -type NoteProperty -Name "Protocol" -Value ""
  $obj | Add-Member -type NoteProperty -Name "SourceIP" -Value ""
  $obj | Add-Member -type NoteProperty -Name "DestinationIP" -Value ""
}

#while loop to run until user interrupts
while($true)
{
  Write-Host "Checking log for scanning attempts"

  #open the log file to parse
  $logs = Get-Content $logname
  #parse the logs
  foreach($log in $logs)
  {
    #split the log entry into seperate elements for comparison
    $entry=$log.split()

    #put the elements we want to track into seperate variable and reassemble into an Object
    #not sure of we need all of these but it seems like a good selection
    $date=$entry[0]
    $time=$entry[1]
    $action=$entry[2]
    $protocol=$entry[3]
    $source_ip=$entry[4]
    $dest_ip=$entry[5]

    #set the current object to now be the previous objects
    $previousEntryObject=$currentEntryObject

    #add this entry to the currentObject
    $currentEntryObject.Date=$date
    $currentEntryObject.Time=$time
    $currentEntryObject.Action=$action
    $currentEntryObject.Protocol=$protocol
    $currentEntryObject.SourceIP = $source_ip
    $currentEntryObject.DestinationIP=$dest_ip

    #check if the destination IP is this box's IP address
    if($ips -contains $currentEntryObject.DestinationIP)
    {
      #check to make sure we are not getting a positive on the dns servers
      if($dns_ips -notcontains $currentEntryObject.SourceIP)
      {
        #A match has been found, now check to see if the address has been repeated
        #Theory being that if an entry shows up a few times in a row it is a port scans
        #Initially matching this host as the destination eliminates broadcast traffic as a false positive
        #Could also maybe count the number of times an IP appears n the log
        if($currentEntryObject.SourceIP -eq $previousEntryObject.SourceIP)
        {
          #Write-Host $scan_counter
          #increment the scanner counter
          $scan_counter += 1
          #check if the scan counter has hit 5, this means that there were 5 consecutive unsolicited packets from the same source IP
          if($scan_counter -eq 5)
          {
            $scan_counter = 0
            $scan_found = $true
            #add the ip to the list of ips to blocked
            #first check to make sure we have not already added this ip
            if($ips_to_block -notcontains $currentEntryObject.SourceIP)
            {
              $ips_to_block += $currentEntryObject.SourceIP
            }
          }
        }
      }
      else #not conscetutive source ips so reset the counter
      {
        $scan_counter = 0
      }
    } #closing bracket for
  } #closing bracket for foreach($log in $logs)

  #the log file has been parsed successfully so now process the results
  if($scan_found -eq $true)
  {
    $scan_date = Get-Date
    #write-host "Possible scan attempt Found"
    #append the log file into the Keep_For_Analysis folder
    Add-Content -Path $preserve_location "Possible Scan Attempts for $scan_date "
    Add-Content -Path $preserve_location -Value $logs
    Add-Content -Path $preserve_location "    "
    #clear the log file for future logs to be written to it
    #This is the only method I could create to clear the log file - set the log to write to another file, then clear the real log, then set it back
    #Logs may be missed this way but its as close as I can get it to get them all
    #Could always call the log checker on the temp log too - have rotating log catchers if the server has a lot of logged firewall events
    set-NetFirewallProfile -LogFileName $temp_logname
    Clear-Content $logname
    set-NetFirewallProfile -LogFileName $logname
    #add a firewall rule to block the ips that attempted to port scan
    foreach($ip in $ips_to_block)
    {
      #reload firewall rules names array incase new rules have been added
      $fw_rule_names = get-netfirewallRule | foreach-object -membername DisplayName
      #filename for possible new firewall rule
      $rule_name = "Blacklisted IP: - $ip -Inbound"
      $rule_name_out = "Blacklisted IP: - $ip -Outbound"
      #check if we have previously created a rule for this IP
      if($fw_rule_names -notcontains $rule_name)
      {
        #does not exist, create the rule now
        new-NetFirewallRule -DisplayName $rule_name -Name $rule_name -Description "Blocks the IP $ip which may be port scanning" -Direction Inbound -RemoteAddress $ip -Action Block | out-null
        new-NetFirewallRule -DisplayName $rule_name_out -Name $rule_name_out -Description "Blocks the IP $ip which may be port scanning" -Direction Outbound -RemoteAddress $ip -Action Block | out-null
        Write-Host "Possible Scan Attempt detected from IP Address $ip, please check $preserve_location"
      }
    }
  }
  #sleep for 1 minute
  write-host "Sleeping for 1 minute . . . . . . . . . . . . . . . . . . . . . . . ."
  Start-sleep -seconds 60
} #closing bracket for while loop
#add some network stuff here later to do this on remote computers
