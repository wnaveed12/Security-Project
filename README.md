# Security-Project

This project allows you to setup a Krack Attack against a Weaker OS System like Ubuntu , which in our case is the Victim VM . While , also diplaying bad packets and a PMF method which will protect against the code. 

In Order to run this code you have to have two virtual systems , one Kali Linux(Attacker VM and AP) and one Ubuntu ( Victim VM that will run code for PMF and Capture Bad Packets )

On The Kali Linux youll be setting up a Krack Attack , the readme for this script is included in that branch. You will also be setting up an Access Point on this machine which it will connect to along with the Victim VM(Ubuntu) this can only be done using a network adapter. 

Once the AP is connected make sure both VMs are connected to it , once the attack begins the Victim VM will capture bad packets and perform PMF. 

On the Victim VM - Ubuntu you'll add the protection.py which will run on its own and it has a gui so all you have to do is "cd" to where the directory is for the code and type in "python protection.py".
Make sure python is installed with other prequisites. 
