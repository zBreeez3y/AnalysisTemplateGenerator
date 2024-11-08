# AnalysisTemplateGenerator
A python3 GUI script that creates a security analysis template and pre-generated recommendations based off per-alert details.

![image](https://github.com/user-attachments/assets/b5a2ccca-4e8d-4d73-aa75-6fe40ab6b223)
![image](https://github.com/user-attachments/assets/b7f6a7e1-58d8-4d0b-ad31-e1623b6a2d53)

## What is ATG? 
Analysis Tempalte Generator is a Python3 script that provides a GUI for an analyst to paste alert details during a security investigation. Upon determing whether the alert can be closed, or escalated to the customer, ATG will generate an analysis template with the alert based upon the details provided by the analyst, and a pre-generated recommendation based on the alert type and saves it to a TXT file in the scripts PWD. The script will also open thee file in notepad for you 
  - You can change lines 235, 465 to provide your text editor of choice

ATG will auto defang public IP addresses and URL's, and provides the template with general markdown text formatting. 

## Setup/Usage
- Install Python3
- Run: `python3 .\ATG.py`
- Leave open during investigation and provide details
  - Note: Must provide date/time in `xxxx-xx-xx xx:xx:xx` format
- Select whether you're escalating or closing alert
- Optional: Provide addtional non-default fields/values
- Select "Submit"
