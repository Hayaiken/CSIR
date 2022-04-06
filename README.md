# CSIR
Collection of Security Related Queries 

Goals:
    - Practicing Powershell
    - Collecting Security Related Information


How To Use:

    - Run The Code From Powershell / Powershell ISE As Administrator
    - Run The Code From CMD As Administrator Using The Command "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Maximized -File CSIR.ps1"

What it Collects:

	 a - All                           	 b - Workstation Info   	 c - Workstation GPO                 	 d - Security Software Status   
	 e - Windows Update Service Status 	 f - Local Users        	 g - Local Administrators            	 h - Users Profile              
	 i - Deleted Local Accounts        	 j - Users GPO          	 k - Last Successful Logon (10 Days) 	 l - Last Failed Logon (10 Days)
	 m - Groupless Firewall Rules      	 n - Intsalled Programs 	 o - Run Registry                    	 p - SMB                        
	 q - Wireless Network              	 r - TaskScheduler List 	 s - Workstation Services            	 t - Security Settings          
	 u - TCP Connections               	 v - RDP                	 w - Browsers Extensions 

Note:
    The code isn't function based, as you can take any process and use it as a standalone with minor modificaitons.

    
Outputs:
  Outputs can be seen on:
                          - Console
                          - HTML file stored inside the "C:\" directory , and can be modified to your liking.


To modify:
    - Convert it into function based
    - Create a simple interactive GUI
    
