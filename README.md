# SSL Checker
## _Automate the checking of the SSL Certificates_

Curremtly the information is held on a spreadsheet, this can be prone to human error especially with the expiry dates. This is where this code comes in.

The spreadsheet was split into three worksheets.
Visa , Node 4 and Nasstar.
The latter, Nasstar code still has to be sorted.
##### Dependencies: 
hosts.py
The file that extracts the information from the current spreadsheet

The **MASTER** spreadsheet had entries that did not respond, therefore I made a copy of the file and deleted any entry that failed. A compare can be made between the two spreadsheets to determine the failed URL to look at later. 
#### Visa - visa_certs_check.py
- Removed URL 
- Code output to SQL SQLite3 file
#### Node 4 - node_four_certs_check.py
- Removed URL
- Code output to SQL SQLite 3

#### Nasstar - nasstar_certs_check.py
-
### Exe Example
Using Pyinstaller I created a distro of the Visa Checker. No installation and should run on Windows without issue. Open in CMD/PS.

#### Requirements
See the attached text file
_pip install -r requirements.txt_
