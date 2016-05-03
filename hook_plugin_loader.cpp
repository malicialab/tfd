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

#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>
#include <set>
#include <string>
#include <vector>
#include "config.h"
#include "hook_plugin_loader.h"

extern "C" {
#ifdef PLUGIN_TFD
/* llconf */
#include <llconf/ini.h>
#include <llconf/nodes.h>
#include <llconf/entry.h>
#include <llconf/modules.h>
#endif

#include "DECAF_main.h"
};


using namespace std;

static set < string > plugin_files;
static set < pair < string, string > >functions;
static set < pair < string, string> > excluded_functions;
static vector<void *> handles;

/* Parse a plugins.active file */
static void parse_config(const char *const pa_path)
{
  FILE *plugins = fopen(pa_path, "r");

  if (0 == plugins) {
    fprintf(stderr,
            "Error opening plugin configuration file (plugins.active)."
            "  I'll let you continue, but you'll have no hooks.\n");
    return;
  }

  char buf[1024];
  int line_no = 1;
  int mode = -1;
  char *result = NULL;

  result = fgets(buf, 1024, plugins);
  if (result != buf) {
    fprintf(stderr, "Error reading from configuration file.\n"
            "  I'll let you continue, but you'll have no hooks.\n");
    return;
  }
  while (!feof(plugins)) {

    if (buf[strlen(buf) - 1] != '\n') {
      fprintf(stderr,
              "WW: Line %d in plugin config file is too long and has"
              "been truncated.\n", line_no);
    }

    /* if line contains comment character, remove rest of line */
    char *semi = strchr(buf, ';');
    if (0 != semi)
      *semi = '\0';

    int blank = 1;
    for (unsigned int i = 0; i < strlen(buf); ++i) {
      if (buf[i] != ' ' && buf[i] != '\t' && buf[i] != '\n') {
        blank = 0;
      }
    }
    if (1 == blank)
      goto next;

    char token[512];
    if (1 != sscanf(buf, " %s ", token)) {
      fprintf(stderr, "EE: Syntax error on line %d of plugin config file."
              " I'll pretend like it didn't happen.\n", line_no);

      goto next;
    }

    if (!strcmp(token, ".plugins:")) {
      mode = 0;
    }
    else if (!strcmp(token, ".functions:")) {
      mode = 1;
    }
    else if (!strcmp(token, ".excluded_functions:")) {
      mode = 2;
    }
    else {
      if (0 == mode) {
        plugin_files.insert(token);
      }
      else if (1 == mode || 2== mode) {
        char module[256];
        char function[256];

        char *first_colon = strchr(token, ':');
        char *second_colon = strrchr(token, ':');
        if ((0 == first_colon || 0 == second_colon ||
            (first_colon + 1 != second_colon))) {
          fprintf(stderr,
                  "EE: Syntax error on line %d of plugin config file."
                  " I'll pretend like it didn't happen.\n", line_no);
          fprintf(stderr, "buf: '%s'\ntoken: '%s'\n", buf, token);
          goto next;
        }

        *first_colon = '\0';
        strcpy(module, token);
        strcpy(function, second_colon + 1);

        if(1== mode)
          functions.insert(pair < string, string > (module, function));
        else
          excluded_functions.insert(
            pair < string, string > (module, function));
      }
      else {
        fprintf(stderr,
                "EE: When the first non-comment line I read isn't a"
                " modeline, i get terribly confused. See sample.\n");
        fclose(plugins);
        return;
      }
    }

next:
    ++line_no;
    result = fgets(buf, 1024, plugins);
    if (result != buf) {
      fprintf(stderr, "Error reading from configuration file.\n"
        "  I'll let you continue, but you'll have no hooks.\n");
      return;
    }
  }

  fprintf(stderr, "Files to load as plugins:\n");
  for (set < string >::iterator it = plugin_files.begin();
        it != plugin_files.end(); ++it) 
  {
    fprintf(stderr, "\t%s\n", it->c_str());
  }

  fprintf(stderr, "Module/function pairs to load:\n");
  for (set < pair < string, string > >::iterator it = functions.begin();
        it != functions.end(); ++it) 
  {
    fprintf(stderr, "\t%s::%s\n", it->first.c_str(), it->second.c_str());
  }

  fclose(plugins);
}

#ifdef PLUGIN_TFD
/* Parse an ini file containing hook information */
static void parse_plugin_ini(const char *file_name)
{
  struct cnfnode *cn_root, *cn_node;
  struct cnfmodule *mod_ini;
  struct cnfresult *cnf_res;
  char module[256];
  char function[256];

  register_ini(NULL);
  mod_ini = find_cnfmodule("ini");
  cn_root = cnfmodule_parse_file(mod_ini, file_name);

  cnf_res = cnf_find_entry(cn_root, "hook plugins");
  if(cnf_res) {
    for(cn_node = cnf_res->cnfnode->first_child; cn_node != NULL; 
        cn_node = cn_node->next) 
    {
      if(cn_node->value && !strcasecmp(cn_node->value, "yes"))
        plugin_files.insert(cn_node->name);
    }
  }

  cnf_res = cnf_find_entry(cn_root, "functions");
  if(cnf_res) {
    for(cn_node = cnf_res->cnfnode->first_child; cn_node != NULL; 
        cn_node = cn_node->next) 
    {
      char *first_colon = strchr(cn_node->name, ':');
          char *second_colon = strrchr(cn_node->name, ':');
      if (0 == first_colon || 0 == second_colon ||
                  (first_colon + 1 != second_colon)) {
                //fprintf(stderr, " Syntax error: %s \n", cn_node->name);
                continue;
      }

      *first_colon = '\0';
          strcpy(module, cn_node->name);
          strcpy(function, second_colon + 1);

      if(cn_node->value && !strcasecmp(cn_node->value, "yes"))
        functions.insert(pair < string, string > (module, function));
      else
        excluded_functions.insert(pair < string, string > (module, function));
    }
  }

  monitor_printf(default_mon, "Files to load as plugins:\n");

  for (set < string >::iterator it = plugin_files.begin();
    it != plugin_files.end(); ++it) {
    monitor_printf(default_mon, "\t%s\n", it->c_str());
  }

  monitor_printf(default_mon, "Module/function pairs to load:\n");
  for (set < pair < string, string > >::iterator it = functions.begin();
          it != functions.end(); ++it) {
    monitor_printf(default_mon, "\t%s::%s\n", 
        it->first.c_str(), it->second.c_str());
  }

  destroy_cnftree(cn_root);
}
#endif


/*
** This function will find all plugin (*.so) files in the pl_path directory
** that are specified in the plugins.active file.
** All plugins will then have init_plugin called in them.
** Each plugin is responsible for adding the appropriate hooks.
*/
void load_hook_plugins(unsigned int *mon_cr3, /* cr3 of proc to monitor */
                       const char *const pa_path, /* path of plugins.active */
                       const char *const pl_path, /* path of plugins */
                       enum confType file_type)

{
  /* load hook plugins */
  if (file_type == pactive)
    parse_config(pa_path);
#ifdef PLUGIN_TFD
  else
    parse_plugin_ini(pa_path);
#endif

  set < string >::iterator it = plugin_files.begin();
  for (; it != plugin_files.end(); ++it) {
    //printf("Loading %s:: ", it->c_str());
    char path[512];
    char *error = 0;
    sprintf(path, "%s/%s", pl_path, it->c_str());
    monitor_printf(default_mon, "Loading: %s\n", path);

    dlerror();
    void *handle = dlopen(path, RTLD_NOW);
    if (0 != (error = dlerror())) {
      printf("error: %s\n", error);
    }
    else {
      init_plugin_t init_plugin = 
        (init_plugin_t)dlsym(handle, "internal_init_plugin");

      if (0 != (error = dlerror())) {
        printf("error initializing: %s\n", error);
      }
      else {
        init_plugin();
        handles.push_back(handle);
      }
    }
  }
}

/*
** This function will load and initialize all hooks in a given plugin 
**   e.g., (*.so) file
** The plugin is responsible for adding the appropriate hooks.
*/
void load_hooks_in_plugin(unsigned int *mon_cr3, /* cr3 of proc to monitor */
                     const char *const plugin_name, /* path of plugin file */
                     const char *const pl_path) /* path of plugins */
{
  char plugin_path[512];

  // Get plugin path
  snprintf(plugin_path, 512, "%s/%s", pl_path, plugin_name);

  // Make sure we hook all functions in plugin
  functions.insert(pair < string, string > ("*", "*"));

  // Load SO file
  //printf("Loading %s:: ", plugin_path);
  char *error = 0;
  dlerror();
  void *handle = dlopen(plugin_path, RTLD_NOW);
  if (0 != (error = dlerror())) {
    printf("error: %s\n", error);
  }
  else {
    init_plugin_t init_plugin = 
      (init_plugin_t)dlsym(handle, "internal_init_plugin");

    if (0 != (error = dlerror())) {
      printf("error initializing: %s\n", error);
    }
    else {
      init_plugin();
      handles.push_back(handle);
    }
  }
}


/**
 * This function unloads all the hook plugins
 */
void unload_hook_plugins()
{
  for(uint32_t i=0; i<handles.size(); i++) {
    //unload it
  
    dlclose(handles[i]);
  }
  
  handles.clear();
}


/*
** this function is provided to hooks to allow them to check which functions
** the configuration file has requested they hook
*/
int should_hook(const char *const mod_name, const char *const fun_name)
{
  if (excluded_functions.find(pair < string, string > (mod_name, fun_name)) !=
      excluded_functions.end())
    return 0;

  if (excluded_functions.find(pair < string, string > (mod_name, "*")) !=
      excluded_functions.end())
    return 0;

  if (excluded_functions.find(pair < string, string > ("*", fun_name)) !=
      excluded_functions.end())
    return 0;

  if (excluded_functions.find(pair < string, string > ("*", "*")) !=
      excluded_functions.end())
    return 0;

  
  if (functions.find(pair < string, string > (mod_name, fun_name)) !=
      functions.end())
    return 1;

  if (functions.find(pair < string, string > (mod_name, "*")) !=
      functions.end())
    return 1;

  if (functions.find(pair < string, string > ("*", fun_name)) !=
      functions.end())
    return 1;

  if (functions.find(pair < string, string > ("*", "*")) !=
      functions.end())
    return 1;

  return 0;
}

