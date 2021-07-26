# rbk_ntap_vol_backup
A project to handle backing up NTAP volumes with different qtree security styles on Rubrik.

Note:  This project was originally written for a specific customer so it may not fit all situations.  But you are welcome to use the code and adapt to your needs.

The idea behind this project is to help protecct NetApp volumes that have qtrees of mulutiple security styles.  While it is a Rubrik best practice to keep the qtree security styles within a volume the same, this isn't always the case in the real world.  One way to handle this is to have a share at each qtree and point Rubrik to those qtrees.  

However, another approach is to have a top-level volume NFS export and SMB share and use fileset includes to ensure that the UNIX qtrees are backed up over NFS and the others are done via SMB.  This script is meant to automate the process of creating and updating those fileset templates in order to keep the filesets up to date.  This is intended for large environmnts where automatiojn would be helpful.

The script is written in Python and works with both Python 2 and 3.  It does require the 'rubrik-cdm' module to be installed.  It includes the NetApp SDK modules and assumes the they live in the same directory where the script is being run.  If that's not the case, change the sys.path.append('./NetApp') line near the top of the script to match your environment.

The script makes some assumptions beyond the Python config mentioned above:

1. The Rubrik NAS hosts are already created
2. A top level NFS and SMB share exists on the Rubrik for each volume
3. You will assign an SLA to each fileset
4. All of the affected shares will use NAS DA or all will not.

Some of these assumptions could be changed in furture releases as needed but these exist as of today.

The syntax is as follows:

<pre>
Usage: rbk_ntap_vol_backup.py: [-hD] [-c rubrik_creds] [-t Rbk API token] [-n NTAP creds] [-m map_file] ntap rubrik
-h : --help : Prints Usage
-c | --rubrik_creds= : Rubrik login creds [user:password]
-t | --token= : Rubrik API token
-n | --ntap_creds= : NetApp Creds [user:password]
-m | --map_file= : name of SVM map file [def: svm_map.csv]
ntap : Name or IP of the NetApp Cluster Management LIF
rubrik : Name of IP of the Rurbik
</pre>

Note that if either set of credentials are not provided on the command line (or an API token for the Rubrik), then the script will prompt the user for credentials.
