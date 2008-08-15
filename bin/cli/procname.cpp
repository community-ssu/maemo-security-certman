// -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

#include <stdio.h>
#include <iostream>
#include <sec_common.h>

int main(void)
{
	string my_proc_name;
	string test;
	if (process_name(my_proc_name))
		cout << my_proc_name + "\n";
	else
		cout << "ERROR: cannot access process name file\n";
	absolute_pathname(my_proc_name.c_str(), test);
	if (test != my_proc_name)
		cout << "What hell?\n";
	return(0);
}
