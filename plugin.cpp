// Copyright (C) 2014 oct0xor
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License 2.0 for more details.
// 
// A copy of the GPL 2.0 should have been included with the program.
// If not, see http ://www.gnu.org/licenses/

#include <ida.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <idp.hpp>

extern debugger_t debugger;

static bool init_plugin(void);

bool plugin_inited;

//--------------------------------------------------------------------------
// Initialize debugger plugin
static plugmod_t* idaapi init(void)
{
	if (init_plugin())
	{
		dbg = &debugger;
		plugin_inited = true;
		return PLUGIN_KEEP;
	}
	return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
	if (plugin_inited)
	{
		//term_plugin();
		plugin_inited = false;
	}
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static bool idaapi run(size_t /*arg*/)
{
	return true;
}

//--------------------------------------------------------------------------
// Initialize PPC debugger plugin
static bool init_plugin(void)
{
	if (ph.id != PLFM_PPC)
		return false;

	return true;
}

//--------------------------------------------------------------------------
char comment[] = "DECI3 debugger plugin by oct0xor.";

char help[] =
        "DECI3 debugger plugin by oct0xor.\n"
		"\n"
		"This module lets you debug programs running in Playstation 3.\n";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_DBG,					// plugin flags
  init,							// initialize

  term,							// terminate. this pointer may be NULL.

  run,							// invoke plugin

  comment,						// long comment about the plugin
								// it could appear in the status line
								// or as a hint

  help,							// multiline help about the plugin

  "DECI3 debugger plugin",		// the preferred short name of the plugin

  ""							// the preferred hotkey to run the plugin
};
