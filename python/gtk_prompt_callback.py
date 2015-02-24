#!/usr/bin/python

import gtk

def libuser_gtk_prompt_callback(prompts):
	dialog = gtk.Dialog()
	dialog.add_button(gtk.STOCK_OK, 1)
	dialog.add_button(gtk.STOCK_CANCEL, 0)

	table = gtk.Table(len(prompts), 2)
	dialog.vbox.pack_start(table)

	table.set_row_spacings(4)
	table.set_col_spacings(4)

	ret_list = []
	for i in range(len(prompts)):
		prompt = prompts[i]

		label = gtk.Label(prompt.prompt)
		label.set_alignment(1.0, 0.5)
		table.attach(label, 0, 1, i, i + 1)

		entry = gtk.Entry()
		entry.set_visibility(prompt.visible)
		entry.set_text(prompt.default_value)
		table.attach(entry, 1, 2, i, i + 1)

		ret_list.append((prompt, entry))
		
	table.show_all()

	print(dialog.run())

	for (prompt, entry) in ret_list:
		prompt.value = entry.get_text()

#regcall(libuser_gtk_prompt_callback, "give me some info")

class fake_prompt:
	def __init__(self, prompt, visible, default_value, value):
		self.prompt = prompt
		self.visible = visible
		self.default_value = default_value
		self.value = value

	def __repr__(self):
		return repr({"prompt" : self.prompt, "visible" : self.visible, "default_value" : self.default_value, "value" : self.value})  
	
def harness():
	list = []
	for t in [	("User", 1, "crutcher", ""),
			("Password", 0, "defpasswd", ""),
			("Real Name", 1, "Crutcher Dunnavant", ""),
			("Home Dir", 1, "Home Dir", ""),
			("Shell", 1, "/bin/bash", "")	]:
		list.append(fake_prompt(*t))
	
	libuser_gtk_prompt_callback(list)

	print(list)

harness()
