Description
===========
This Powershell script will start Tenable scans for an authorized user. This was designed to work with Jenkins.


Requirements:
-------------
1. Tenable Security Center Account
2. Jenkins Account 


Instructions:
-------------
1. Log into Jenkins
2. Create a new build with the following parameters:
** Username (String)
** Password (Password)
** Hosts (String)
** ScanType (Choice)
** CaseNumber (String) This is optional.

