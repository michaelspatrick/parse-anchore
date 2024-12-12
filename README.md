This script simply parses anchore output text and generates output in CSV format for import into a spreadsheet.

Steps:
1.  Copy text from anchore
2.  Save text to a file on the server named, "vulns.txt".
3.  Run the script: ./parse.php
4.  Copy the output and save to a file such as CVEs.csv on your laptop.
5.  Import that into Google Sheets. 

Web:
I crated a simple web application.  There is a form upload that takes the text and then parses it and immediately downloads as a CSV file.  The index.php page calls parse-web.php page.
