/* 
 *  hook loading functionality
 *
 *  Copyright (C) 2013 Juan Caballero <juan.caballero@imdea.org>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _HOOK_PLUGIN_LOADER_H_
#define _HOOK_PLUGIN_LOADER_H_

enum confType { pactive = 0, ini };

typedef void (*init_plugin_t)();

#ifdef __cplusplus
extern "C" {
#endif
void load_hook_plugins(unsigned int *mon_cr3, /* cr3 of proc to monitor*/
		  const char *const pa_path,  /* path of plugins.active */
		  const char *const pl_path,  /* path of plugins        */
		  enum confType); 

/*
** This function will load and initialize all hooks in a given plugin 
**   e.g., (*.so) file
** The plugin is responsible for adding the appropriate hooks.
*/
void load_hooks_in_plugin(unsigned int *mon_cr3, /* cr3 of proc to monitor */
                       const char *const plugin_path, /* path of plugin file */	
                       const char *const pl_path); /* plugin directory */

/* Unload all hooks */
void unload_hook_plugins();

int
should_hook(const char *mod_name, const char *fun_name);

#ifdef __cplusplus
};
#endif

#endif /*_PLUGIN_LOADER_H_*/
