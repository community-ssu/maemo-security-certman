/* -*- mode:c++; tab-width:4; c-basic-offset:4;
 *
 * This file is part of maemo-security-certman
 *
 * Copyright (C) 2009 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Juhani Mäkelä <ext-juhani.3.makela@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/// \file xmlpp.cpp
/// \brief The xmlpp test program, a test parser and pretty printer

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "../../lib/security/c_xmldoc.h"
#include <maemosec_common.h>

#if 0
static void print_output(c_wordlist* model, c_xmlnode* node)
{
	for (int i = 0; i < model->nbrof_words(); i++) {
		const char* str = model->word(i);
		if (*str == '@') {
			if (*(str + 1))
				printf("%s", node->attribute(str + 1, false, ""));
			else
				printf("%s", node->content());
		} else
			printf("%s", str);
	}
	printf("\n");
}


static void show_nodes(c_xmlnode* of_node, const char* path)
{
	c_fstring topname;
	c_fstring line;
	char* sep;

	if (path) {
		sep = strchr(path, '/');
		if (sep) {
			topname.append(path, sep - path);
			sep++;
		} else {
			topname.append(path);
		}

		for (int i = 0; i < of_node->nbrof_children(); i++) {
			c_xmlnode* child = of_node->child(i);
			if (topname.equals(child->name())) {
				show_nodes(child, sep);
			}
		}

	} else {
		if (outputs.nbrof_values()) {
			for (int i = 0; i < outputs.nbrof_values(); i++) {
				print_output(outputs.value(i), of_node);
			}
		} else {
			c_fstring *output = of_node->as_fstring(false, 0, 0);
			printf("%s\n", output->as_string());
			delete(output);
		}
	}
}


static void parse_output_string(const char* str, c_wordlist* to_list)
{
	const char *start, *c, *t;
	c_fstring help;

	c = start = str;
	while (*c) {
		switch (*c) 
			{
			case '@':
				// Reference
				if (c > start) {
					help.reset();
					help.append(start, c - start);
					to_list->add(help.as_string());
				}
				for (t = c + 1; *t && *t != '@'; t++);
				if (*t != *c)
					ERROR("Invalid output string, closing '%c' not found", *c);
				help.reset();
				help.append(c, t - c);
				to_list->add(help.as_string());
				c = t + 1;
				start = c;
				break;
			default:
				c++;
			}
	}
	if (c > start) {
		help.reset();
		help.append(start, c - start);
		to_list->add(help.as_string());
	}
}
#endif

int 
main(int argc, char* argv[])
{
	char* xpath = NULL;
	string fpath;
	c_xmldoc xdoc;
	signed char opt;
	bool pretty_print = true;
	bool include_header = true;
	int indent_width = 4;

	while ((opt = getopt (argc, argv, "vbri:")) != (char)-1) {
		
		switch (opt) {
		case 'v':
			absolute_pathname(argv[0], fpath);
			printf("%s\n", fpath.c_str());
			break;

		case 'b':
			// 'Bare'
			include_header = false;
			break;

		case 'r':
			// 'Raw'
			pretty_print = false;
			break;

		case 'i':
			indent_width = atoi(optarg);
			break;

		case 'x':
			xpath = optarg;
			break;

		case 'o':
			break;
		}
	}

	if (optind == argc) {
		printf ("Usage: xmlpp -v [-x <node-path>] [-o <output-string>...] <filename>\n"
				" -v to show the version\n"
				" -x to search for the given path in the document\n"
				" -o to define the output(s) printed if the given path is found\n"
				"    (use @attr-name@ to refer to attribute values and @@ to content)\n"
				);
		return(-1);
	}

	try {
		xdoc.parse_file (argv[optind]);
		if (!xdoc.root()) {
			fprintf(stderr, "No xml document parsed\n");
			return -1;
		}

		if (include_header)
			printf("%s\n", xdoc.as_string(pretty_print).c_str());
		else {
			if (pretty_print)
				printf("%s", xdoc.root()->as_string(true, indent_width, 0).c_str());
			else
				printf("%s", xdoc.root()->as_string(false, 0, 0).c_str());
		}

	} catch (string* error) {
		fprintf (stderr, "ERROR: %s\n", error->c_str());
		delete(error);
	}
	return(0);
}
