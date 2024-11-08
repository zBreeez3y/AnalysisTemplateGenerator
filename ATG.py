 #!/usr/env/python3

import os
import ipaddress
import re 
from tkinter import *
from tkinter import ttk
import tkinter.messagebox
import subprocess
import json
import requests
import urllib.parse
import webbrowser


#Creating root GUI window
gui = Tk()
gui.title("Analysis Template Generator")
gui.geometry('660x415+500+350')
headline = Label(gui, text="Analysis Template Generator").place(x=225, y=5)
cwd = os.path.realpath(__file__)
new_cwd = cwd.replace(os.path.basename(__file__), "")

#Creating GUI labels
host_label = Label(gui, text="Hostname:").place(x=40, y=50)
user_label = Label(gui, text="User:").place(x=40, y=95)
descr_label = Label(gui, text="Description (Alert Title):").place(x=40, y=140)
file_label = Label(gui, text="File:").place(x=40, y=185)
hash_label = Label(gui, text="Hash Value:").place(x=40, y=230)
filepath_label = Label(gui, text="File Path:").place(x=40, y=275)
date_label = Label(gui, text="Date/Time:").place(x=40, y=320)
commandline_label = Label(gui, text="Command Line:").place(x=260, y=50)
srcip_label = Label(gui, text="Source IP:").place(x=260, y=95)
destip_label = Label(gui, text="Destination IP:").place(x=260, y=140)
srcport_label = Label(gui, text="Source Port:").place(x=260, y=185)
destport_label = Label(gui, text="Destination Port:").place(x=260, y=230)
url_label = Label(gui, text="URL:").place(x=260, y=275)
parentprocess_label = Label(gui, text="Parent Process:").place(x=260, y=320)


#Declaring string variable for storing user input
host_var = StringVar() 
user_var = StringVar()  
descr_var = StringVar()  
file_var = StringVar()  
hsh_var = StringVar() 
filepath_var = StringVar()  
date_var = StringVar()    
commandline_var = StringVar()  
srcip_var = StringVar()  
destip_var = StringVar() 
srcport_var = StringVar()
destport_var = StringVar() 
url_var = StringVar()  
parentprocess_var = StringVar()


#Creating entry area for user input
host_entry = Entry(gui, textvariable=host_var, width=25).place(x=40, y=70)
user_entry = Entry(gui, textvariable=user_var, width=25).place(x=40, y=115)
descr_entry = Entry(gui, textvariable=descr_var, width=25).place(x=40, y=160)
file_entry = Entry(gui, textvariable=file_var, width=25).place(x=40, y=205) 
hsh_entry = Entry(gui, textvariable=hsh_var, width=25).place(x=40, y=250) 
filepath_entry = Entry(gui, textvariable=filepath_var, width=25).place(x=40, y=295) 
date_entry = Entry(gui, textvariable=date_var, width=25).place(x=40, y=340) 
commandline_entry = Entry(gui, textvariable=commandline_var, width=25).place(x=260, y=70) 
srcip_entry = Entry(gui, textvariable=srcip_var, width=25).place(x=260, y=115) 
destip_entry = Entry(gui, textvariable=destip_var, width=25).place(x=260, y=160)
srcport_entry = Entry(gui, textvariable=srcport_var, width=25).place(x=260, y=205) 
destport_entry = Entry(gui, textvariable=destport_var, width=25).place(x=260, y=250) 
url_entry = Entry(gui, textvariable=url_var, width=25).place(x=260, y=295) 
parentprocess_entry = Entry(gui, textvariable=parentprocess_var, width=25).place(x=260, y=340) 


#Creating Integer variable for Close Alert checkbox result, and create the Close Alert checkbox itself
ca_button = IntVar()
ca_cb = Checkbutton(gui, text="Close Alert", variable=ca_button).place(x=500, y=110)


#Creating Integer variable for Escalate checkbox result, and create the Escalate checkbox itself
escalate_button = IntVar()
escalate_cb = Checkbutton(gui, text="Escalate", variable=escalate_button).place(x=500, y=75)


#Creating dictionary to stoare Key:Value pairs for custom details added
custom_details = {}


#Function to define submit button action
def submit():


	#Setting detail variables
	host=host_var.get()
	user=user_var.get()
	descr=descr_var.get()
	file=file_var.get()
	hsh=hsh_var.get()
	filepath=filepath_var.get()
	date=date_var.get()
	commandline=commandline_var.get()
	srcip=srcip_var.get()
	destip=destip_var.get()
	srcport=srcport_var.get()
	destport=destport_var.get()
	url=url_var.get()
	parentprocess=parentprocess_var.get()
	closealert = ca_button.get()
	escalate = escalate_button.get()


	#Creating dictionary to store Key:Value pairs for provided entries
	provided_entries = {}


	#If string exists in detail entry, append string value to provided_entries dictionary
	if host:
		provided_entries.update(Host=defang(host))

	if user:
		provided_entries.update(User=user)

	if descr:
		provided_entries.update(Description=descr)

	if file:
		provided_entries.update(File=file)

	if hsh:
		if re.match("[a-zA-Z0-9]{32}$", hsh):
			provided_entries.update(MD5=hsh)
		elif re.match("[a-zA-Z0-9]{40}$", hsh):
			provided_entries.update(SHA1=hsh)
		elif re.match("[a-zA-Z0-9]{64}$", hsh):
			provided_entries.update(SHA256=hsh)
		else:
			msg = tkinter.messagebox.showinfo(
				"Error!", 
				"Hash character length is incorrect. \n\nPlease provide MD5, SHA1, or SHA256 hash"
				)
			return
	
	if filepath:
		provided_entries.update(FilePath=filepath)

	if commandline:
		provided_entries.update(CommandLine=defang(commandline))

	if srcip:
		provided_entries.update(SourceIP=defang(srcip))

	if destip:
		provided_entries.update(DestinationIP=defang(destip))

	if srcport:
		provided_entries.update(SourcePort=srcport)

	if destport:
		provided_entries.update(DestinationPort=destport)

	if url:
		provided_entries.update(URL=defang(url))

	if parentprocess:
		provided_entries.update(ParentProcess=parentprocess)


	#Create list of alert details & remove description/time from entry Dictionary since these will be stated prior to listing details
	provided_entries.pop('Date', None)
	provided_entries.pop('Description', None)
	details = []

	#Create list of custom details, if any are provided
	if custom_details:
		custom_details_list = []
		for detail in custom_details:
			custom_details_list.append(f'{detail}: {custom_details[detail]}')


	#Append entry dictionary K/V pairs to details list
	for entry in provided_entries:
		details.append(f'{entry}: {provided_entries[entry]}')


	#Some Error Handling
	while (closealert and escalate):
		msg = tkinter.messagebox.showinfo("Error!", "You may only select one box.")
		return

	while not (closealert or escalate):
		msg = tkinter.messagebox.showinfo("Error!", "You must check either Escalate or Close Alert.")
		return

	if escalate:
		while not rec.get():
			msg = tkinter.messagebox.showinfo("Error!", "You must select a recommendation when escalating")
			return


	#If close alert Checkbutton is checked, use close alert template
	if closealert: 
		cwd = os.path.realpath(__file__)
		new_cwd = cwd.replace(os.path.basename(__file__), "")
		file = new_cwd + 'details.txt'
		if custom_details:
			with open(file, 'w+') as f:
				f.write(
				'Description:' + ('\n' * 2) + 
				'Technical details:' + ('\n' * 2) +
				'\n'.join(details).replace('**', "") +
				'\n' +
				'\n'.join(custom_details_list).replace('**', "") + 
				('\n' * 2) +
				'Supporting Evidence:' + 
				('\n' *2) +
				'Analyst Notes:'
				)	
			f.close()
		else:
			with open(file, 'w+') as f:
				f.write(
				'Description:' + ('\n' * 2) + 
				'Technical details:' + ('\n' * 2) +
				'\n'.join(details).replace('**', "") +
				('\n' * 2) +
				'Supporting Evidence:' + 
				('\n' *2) +
				'Analyst Notes:'
				)	
			f.close()

			
		#Open escalation template for copy/paste into Ticketing System
		try:
			subprocess.Popen(['notepad', file])
			exit()
		except:
			exit()




	#If Escalate Checkbutton is checked, use escalate template
	if escalate:
		while not date:
			msg = tkinter.messagebox.showinfo("Error!", "You must provide date/time for escalation. \n\nFormat: 'year-month-day time'")
			return

		while not (re.match("[0-9]{4}\-[0-9]{2}\-[0-9]{2}\s[0-9]{2}\:[0-9]{2}\:[0-9]{2}", date)):
			msg = tkinter.messagebox.showinfo("Error!", "Date/Time is in an incorrect format. \n\nFormat: 'year-month-day time'")
			return
	
		#Splitting date/time
		time = date.split()

		while not descr:
			msg = tkinter.messagebox.showinfo("Error!", "You must provide the alert description.")
			return
	
		#Splitting date/time
		time = date.split()

		#Setting current working directory and creating escalation template
		cwd = os.path.realpath(__file__)
		new_cwd = cwd.replace(os.path.basename(__file__), "")
		file = new_cwd + 'details.txt'
		if custom_details:
			with open(file, 'w+') as f:
				f.write(
					f'Hello Team,' + ('\n' * 2) +
					'On ' + time[0] + ' at ' + time[1] + ', [insert company name] was alerted to the following alert: ' +
					('\n' * 2) +
					'"' + f'**{descr}**' + '"' +
					('\n' * 2) +
					'The alert details are as follows: ' +
					('\n' * 2) +
					'\n'.join(details) +
					'\n' + 
					'\n'.join(custom_details_list) +
					('\n' * 3) +
					"**What Happened?**" + 
					('\n' * 3) +
					'**What Should I Do?** ' +
					'\n'
					)
			f.close()
		else:
			with open(file, 'w+') as f:
				f.write(
					f'Hello Team,' + ('\n' * 2) +
					'On ' + time[0] + ' at ' + time[1] + ', [insert company name] was alerted to the following alert: ' +
					('\n' * 2) +
					'"' + f'**{descr}**' + '"' +
					('\n' * 2) +
					'The alert details are as follows: ' +
					('\n' * 2) +
					'\n'.join(details) +
					('\n' * 3) +
					"**What Happened?**" + 
					('\n' * 3) +
					'**What Should I Do?** ' +
					('\n' * 2)
					)
			f.close()


		#Recommendation text
		mal_contained = (
			"As a precaution, [insert company name] recommend performing additional scans on {} to ensure no further infection has occurred. Also, consider wiping and reinstalling the Operating System and applications on {}.".format(host_var.get(), host_var.get()) + ('\n' * 2) +
			"[insert company name] is here to assist you with your cases. If you have any questions, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or create additional cases as more information becomes available."
			)

		mal_notcontained = (
			"[insert company name] recommend that you immediately contain {} and consider initiating your incident response plan to ensure the malware has not spread to other hosts inside your environment. If you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number].".format(host_var.get()) + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		pup = (
			"[insert company name] recommend reviewing the impact of {} on your environment and uninstalling it when possible. It’s also best practice to educate your workforce to inform them of the problems associated with this type of software.".format(file_var.get()) + ('\n' * 2) +
			"If you have any questions, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]."
			)

		latestagetools = (
			"If this is part of a planned security testing exercise, please notify us immediately so [insert company name] can stand down and avoid any containment steps." + ('\n' * 2) +
			"If this is not part of a planned security testing exercise, [insert company name] recommend immediate initiation of your incident response plan to identify root cause of the attacker’s access. If you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number]." + ('\n' *2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		admin_abuse = (
			"[insert company name] recommend immediately reviewing this activity to determine if it was performed by an authorized member of your organization. If this was authorized, please let [insert company name] know via the portal or by replying to your case email, so [insert company name] can monitor and differentiate this from other signals of potential admin abuse." + ('\n' * 2) +
			"If this is unexpected behavior and you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		threat_match = (
			"As a precaution, [insert company name] recommend performing additional scans on {} to ensure no further infection has occurred. Also, consider wiping and reinstalling the Operating System and applications on {}.".format(host_var.get(), host_var.get()) + ('\n' * 2) +
			"[insert company name] is here to assist you with your cases. If you have any questions, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) + 
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or create additional cases as more information becomes available."
			)

		deception = (
			"[insert company name] recommend immediately reviewing this activity to determine if it was performed by an authorized member of your organization. If this was authorized, please let [insert company name] know via the portal or by replying to your case email, so [insert company name] can monitor and differentiate this from other signals of potential admin abuse." + ('\n' * 2) +
			"If this is unexpected behavior and you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		large_data_transfer = (
			"[insert company name] recommend immediately reviewing this activity to determine if it was performed by an authorized member of your organization. If this was authorized, please let [insert company name] know via the portal or by replying to your case email, so [insert company name] can monitor and differentiate this from other signals of potential admin abuse." + ('\n' * 2) +
			"If this is unexpected behavior and you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		service_interrupt = (
			"[insert company name] recommend immediately investigating the affected systems to identify any potential misconfiguration, connectivity, hardware, or other service health issues." + ('\n' * 2) + 
			"If you have any questions, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		service_restored = (
			"Since the service interruption was restored, nothing is required at this time. This serves as notification of the temporary service interruption." + ('\n' * 2) +
			"If you have any questions, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		vuln_id = (
			"[insert company name] recommend leveraging this information to inform your vulnerability management program in order to plan to either patch or mitigate the vulnerability." + ('\n' * 2) +
			"[insert company name] is here to assist you with your cases. If you have any questions, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		abn_behavior = (
			"[insert company name] recommend reviewing this activity to determine if it is authorized and expected. If this is suspicious, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		auth_abuse = (
			"If this authentication service endpoint is single factor authentication, [insert company name] recommend rotating user credentials as a safeguard. As you review internally, if you see signs of account takeover or compromise beyond the indicators in this alert, [insert company name] recommend formally initiating your incident response plan to contain the compromise. If you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number]." + ('\n' * 2) +
			"If this authentication service endpoint is multi-factor authentication, [insert company name] recommend educating your user community about the risks of approving multi-factor authentication requests that they did not initiate. If users report receiving requests to perform a second factor authentication step, such as push notifications, automated phone calls, or SMS text auth codes, then [insert company name] recommend immediately initiating your incident response plan. Secondary authentication requests likely indicate that attackers have successfully harvested passwords and could then attempt additional social engineering attempts to bypass the second factor. If you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		denied_conn = (
			"[insert company name] recommend reviewing this activity to determine if authorized connections [insert company name]re accidentally blocked. Otherwise, this likely indicates \{\{data.source\}\} was working correctly as expected. If the blocked connections are unexpected and suspicious, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		allowed_con = (
			"[insert company name] recommend reviewing this activity to determine if unauthorized connections [insert company name]re known and authorized to connect. If the connections are unexpected and suspicious, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		wapp_expl_att = (
			"Please review {} and provide [insert company name] with a list of the compute components involved in hosting this service so that [insert company name] can properly investigate for signs of successful exploitation. Please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number].".format(host_var.get()) + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		wapp_expl_succ = (
			"[insert company name] recommend that you immediately contain {} and consider initiating your incident response plan to ensure the malware has not spread to other hosts inside your environment. If you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number].".format(host_var.get()) + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		diagnostic = (
			"At this time, nothing is required on your end; this message is strictly informational. If you have questions, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]."
			)

		hvt = (
			"[insert company name] recommend that you consider immediately initiating your incident response plan since this involves a known High Value Target in your organization. If you would like to invoke an incident response retainer with [insert company name], please call us immediately at [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		general = (
			"[insert company name] recommend reviewing this activity to determine if it is authorized and expected. If this is suspicious, please contact us by commenting in the portal, replying directly to your case notification email, or calling [insert phone number]." + ('\n' * 2) +
			"[insert company name] will continue to monitor activity throughout your environment and provide updates or additional cases as more information becomes available."
			)

		#If recommendation is selected, call OpenAI API prompt and append response to details file
		if rec.get():
			with open(file, 'a') as f: 
				if rec.get() == "Malware Contained":
					f.write(mal_contained)
				elif rec.get() == "Malware Not Contained":
					f.write(mal_notcontained)
				elif rec.get() == "PUP/PUA":
					f.write(pup)
				elif rec.get() == "Late-Stage Tools":
					f.write(latestagetools)
				elif rec.get() == "Potential Admin Abuse":
					f.write(admin_abuse)
				elif rec.get() ==  'Threat Indicator Match':
					f.write(threat_match)
				elif rec.get() == 'Deception': 
					f.write(deception)
				elif rec.get() == 'Large Data Transfer':
					f.write(large_data_transfer)
				elif rec.get() == "Service Interruption":
					f.write(service_interrupt)
				elif rec.get() == "Service Restored":
					f.write(service_restored)
				elif rec.get() ==  'Vulnerability Identified':
					f.write(vuln_id)
				elif rec.get() == 'Abnormal Behavior':
					f.write(abn_behavior)
				elif rec.get() == 'Authentication Abuse': 
					f.write(auth_abuse)
				elif rec.get() == 'Denied Connections': 
					f.write(denied_conn)
				elif rec.get() == 'Allowed Connections': 
					f.write(allowed_con)
				elif rec.get() ==  'WApp Exploit Attempt':
					f.write(wapp_expl_att)
				elif rec.get() ==  'WApp Exploit Success':
					f.write(wapp_expl_succ)
				elif rec.get() == 'Diagnostic':
					f.write(diagnostic)
				elif rec.get() == 'High Value Target': 
					f.write(hvt)
				elif rec.get() == "General":
					f.write(general)
			f.close()

	
		#Open escalation template for copy/paste into Ticketing System (w/ text formatting)
		try:
			subprocess.Popen(['notepad', file])
			exit()
		except:
			exit()


#Function to define "Add Detail" button action
def add_detail_window():
	
	#Create top window for adding custom details
	add_detail_window.ad_gui = Toplevel()
	x = gui.winfo_x()
	y = gui.winfo_y()
	add_detail_window.ad_gui.geometry("325x150+650+500")

	#Creating String Variables for Key and Value pair for Custom details
	add_detail_window.key_var = StringVar()
	add_detail_window.value_var = StringVar()

	#Adding Labels for Key/Value
	custom_key_label = Label(add_detail_window.ad_gui, text="Detail:").place(x=20, y=35)
	custom_key_entry = Entry(add_detail_window.ad_gui, width=15, textvariable=add_detail_window.key_var).place(x=20, y=65)
	custom_value_label = Label(add_detail_window.ad_gui, text="Value:").place(x=170, y=35)
	custome_value_entry = Entry(add_detail_window.ad_gui, width=15, textvariable=add_detail_window.value_var).place(x=170, y=65)

	#Creating add button
	add_button = Button(add_detail_window.ad_gui, text="Add", command=custom_detail_submit).place(x=125, y=100)


#Function to define custom detail "add" button action
def custom_detail_submit():
	detail_key = add_detail_window.key_var.get()
	detail_value = add_detail_window.value_var.get()
	custom_detail = {'{}'.format(detail_key):'{}'.format(defang(detail_value))}
	custom_details.update(custom_detail)

	#Close window after add button is selected
	add_detail_window.ad_gui.destroy()


#Function to defang public IP's and URL's
def defang(detail):
    detail = detail.replace('\n', "")
    ip = re.search("(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", detail)
    if ip != None: 
        private_ip = ipaddress.ip_address(detail).is_private
        if private_ip == False:
            val = str(detail)
            split_val = val.split('.')
            newval = '[.]'.join(split_val)
            return newval
        else: 
            return detail
    else:
        pass
    if re.search('(?:(?:http|https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-&?=%.]+', detail, re.IGNORECASE):
    	detail = detail.lower()
    	newval = detail.replace('http', 'hxxp').replace('://', '[://]').replace('.', '[.]')
    	return newval                                     
    else:
        return detail


#Creating combobox for recommendation template options:
rec = StringVar()
recommendation_label = Label(gui, text="Recommendations:").place(x=500, y=250)
recommendation = ttk.Combobox(gui, width=15, textvariable=rec, values=['Validation', 'Malware Contained', 'Malware Not Contained', 'PUP/PUA', 'Late-Stage Tools', 'Potential Admin Abuse', 'Threat Indicator Match', 'Deception', 'Large Data Transfer', 'Service Interruption', 'Service Restored', 'Vulnerability Identified', 'Abnormal Behavior', 'Authentication Abuse', 'Denied Connections', 'Allowed Connections', 'WApp Exploit Attempt', 'WApp Exploit Success', 'Diagnostic', 'High Value Target', 'General', 'N/A']).place(x=495, y=270)


#Creating add detail button and setting execution to add detail function
adb = Button(gui, text="Add Detail", command=add_detail_window).place(x=500, y=300)


#Creating submit button and setting it's execution to the submit function
sb = Button(gui, text="Submit", command=submit).place(x=500, y=352)


#Let it roll 
gui.mainloop()

#EzLife
