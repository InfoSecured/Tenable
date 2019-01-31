Description
===========
This Powershell script will pull new vulnerabilities for a specified query, then create new Salesforce cases for them and assign them to the specified Team for distribution. 


Requirements:
-------------
1. Tenable Security Center Account
2. Salesforce Connected App 
3. Salesforce Client_ID, Client_Secret, Security Token
4. Salesforce login credentials


Special Params:
---------------
1. There is a special file you can place on the system on which this script is running that will add additional descriptions to cases.
