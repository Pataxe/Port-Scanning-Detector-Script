# Lab 08 - Port Scanning Detector Script

### ********* You need to run this as an administrator **********
   
Windows firewall only logs dropped packets on ports that it currently has services running on. So if you do not see a lot of scans it does not mean that they didnt happen, it just doesnt get logged
    
I created this for work to deploy on the network to look for possible scanning attempts and general server hardening in an effort to identify any intrusion attempts and increase the overall security.  It still needs a better way to alert, I was thinking of having it send an email, and I was going to test it on the Guest WiFi network at work.

I had intended to add the ability to run it on remote servers as well but i was afraid that i was going to lock myself out of the test servers.  I may go back and add it later when I have a fw rule that i know will keep letting me in.
    

## [Port Scanning Detector Script] (scanner_detect.ps1)

This is a command line script that will create firewall rules based on what is passed to it as a command line argument.  It will keep open any TCP ports that you pass to it at run time, and block all others.
	
Once the rules are created it will then pars the firewall log to watch for possible port scan attempts by watching for consecutive appearances in the firewall log where the destination is the hosts IP address.  This was the way to do it since it will not block regular broadcast traffic this way.
	
When a possible port scan is detected it will create a rule disallowing any traffic to and from the suspicous IP address and alert the user and then copy the log to be inspected later.  It will then sleep for a minute and try again.
	
----

Sources:

https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=win10-ps 

https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=win10-ps

https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_split?view=powershell-6

https://blogs.technet.microsoft.com/heyscriptingguy/2014/07/17/using-the-split-method-in-powershell/

			


