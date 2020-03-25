/*
 * upf_adf.c - 3GPP TS 29.244 UPF adf
 *
 * Copyright (c) 2017 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <vlib/vlib.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>

#include <hs/hs.h>
#include "upf/upf_adf.h"
#include "upf/upf_ipfilter.h"
#include <upf/upf_pfcp.h>

typedef struct
{
  regex_t *expressions;
  acl_rule_t *acl;
  u32 *flags;
  unsigned int * ids;
  hs_database_t *database;
  hs_scratch_t *scratch;
  u32 ref_cnt;
} upf_adf_entry_t;

typedef struct
{
  int res;
  u32 id;
} upf_adf_cb_args_t;

static upf_adf_entry_t *upf_adf_db = NULL;

static void
upf_adf_cleanup_db_entry (upf_adf_entry_t * entry)
{
  regex_t *regex = NULL;

  vec_foreach (regex, entry->expressions)
  {
    vec_free (*regex);
  }

  if (entry->database)
    hs_free_database (entry->database);

  hs_free_scratch (entry->scratch);
  vec_free (entry->expressions);
  vec_free (entry->acl);
  vec_free (entry->flags);
  vec_free (entry->ids);

  memset (entry, 0, sizeof (upf_adf_entry_t));
}

static int
upf_adf_remove (u32 db_index)
{
  upf_adf_entry_t *entry = NULL;

  entry = pool_elt_at_index (upf_adf_db, db_index);
  upf_adf_cleanup_db_entry (entry);
  pool_put (upf_adf_db, entry);

  return 0;
}

static int
upf_adf_create_update_db (upf_adf_app_t * app)
{
#if CLIB_DEBUG > 1
  upf_main_t *gtm = &upf_main;
#endif
  upf_adf_entry_t *entry = NULL;
  hs_compile_error_t *compile_err = NULL;
  int error = 0;
  u32 index = 0;
  u32 rule_index = 0;
  upf_adr_t *rule = NULL;

  if (!hash_elts(app->rules_by_id)) {
    if (app->db_index != ~0) {
      upf_adf_remove(app->db_index);
      app->db_index = ~0;
    }
    return 0;
  }

  if (app->db_index != ~0)
    {
      entry = pool_elt_at_index (upf_adf_db, app->db_index);
      upf_adf_cleanup_db_entry (entry);
    }
  else
    {
      pool_get (upf_adf_db, entry);
      if (!entry)
	return -1;

      memset (entry, 0, sizeof (*entry));
      app->db_index = entry - upf_adf_db;
    }

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);

     if (rule->regex) {
       regex_t regex = vec_dup(rule->regex);

       adf_debug("app id: %u, regex: %s", app - gtm->upf_apps, regex);

       vec_add1(entry->expressions, regex);
       vec_add1(entry->flags, HS_FLAG_SINGLEMATCH);
       vec_add1(entry->ids, rule->id);
     } else {
       adf_debug("app id: %u, ip filter: %U", app - gtm->upf_apps, format_ipfilter, &rule->acl_rule);
       vec_add1(entry->acl, rule->acl_rule);
     }
  }));
  /* *INDENT-ON* */

  if (entry->database) {
    hs_free_database(entry->database);
    entry->database = NULL;
  }

  if (vec_len (entry->expressions) == 0) {
    goto done;
  }

  if (hs_compile_multi
      ((const char **) entry->expressions, entry->flags, entry->ids,
       vec_len (entry->expressions), HS_MODE_BLOCK, NULL, &entry->database,
       &compile_err) != HS_SUCCESS)
    {
      adf_debug ("Error: %s", compile_err->message);
      error = -1;
      goto done;
    }

  if (hs_alloc_scratch (entry->database, &entry->scratch) != HS_SUCCESS)
    {
      hs_free_database (entry->database);
      entry->database = NULL;
      error = -1;
      goto done;
    }

done:
  return error;
}

static int
upf_adf_event_handler (unsigned int id, unsigned long long from,
		       unsigned long long to, unsigned int flags, void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  upf_adf_cb_args_t *args = (upf_adf_cb_args_t *) ctx;

  args->res = 1;
  args->id = id;

  return 0;
}

int
upf_adf_lookup (u32 db_index, u8 * str, uint16_t length, u32 * id)
{
  upf_adf_entry_t *entry = NULL;
  int ret = 0;
  upf_adf_cb_args_t args = { };

  if (db_index == ~0)
    return -1;

  if (!entry->database)
    return -1;

  entry = pool_elt_at_index (upf_adf_db, db_index);
  ret =
    hs_scan (entry->database, (const char *) str, length, 0, entry->scratch,
	     upf_adf_event_handler, (void *) &args);
  if (ret != HS_SUCCESS)
    return -1;

  if (args.res == 0)
    return -1;

  if (id)
    *id = args.id;

  return 0;
}

u32
upf_adf_get_adr_db (u32 application_id, acl_rule_t ** acl)
{
  upf_main_t *sm = &upf_main;
  upf_adf_app_t *app;

  if (application_id == ~0)
    return ~0;

  app = pool_elt_at_index (sm->upf_apps, application_id);
  if (app->db_index != ~0 && !pool_is_free_index (upf_adf_db, app->db_index))
    {
      upf_adf_entry_t *entry = pool_elt_at_index (upf_adf_db, app->db_index);
      clib_atomic_add_fetch (&entry->ref_cnt, 1);
      if (acl)
        *acl = entry->acl;
    }

  return app->db_index;
}

void
upf_adf_put_adr_db (u32 db_index)
{
  if (db_index != ~0)
    {
      upf_adf_entry_t *entry = pool_elt_at_index (upf_adf_db, db_index);
      clib_atomic_add_fetch (&entry->ref_cnt, -1);
    }
}

static u32
upf_adf_adr_ref_count (u32 db_index)
{
  if (db_index != ~0)
    {
      upf_adf_entry_t *entry = pool_elt_at_index (upf_adf_db, db_index);
      return entry->ref_cnt;
    }

  return 0;
}

static clib_error_t *
upf_adf_app_add_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  u64 up_seid = 0;
  upf_session_t *sess = NULL;
  upf_pdr_t *pdr = NULL;
  u16 pdr_id = 0;
  u8 add_flag = ~0;
  upf_main_t *gtm = &upf_main;
  uword *p = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add session 0x%lx pdr %u name %_%v%_",
		    &up_seid, &pdr_id, &name))
	{
	  add_flag = 1;
	  break;
	}
      if (unformat (line_input, "update session 0x%lx pdr %u name %_%v%_",
		    &up_seid, &pdr_id, &name))
	{
	  add_flag = 0;
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  sess = pfcp_lookup (up_seid);
  if (sess == NULL)
    {
      error = clib_error_return (0, "could not find a session");
      goto done;
    }

  pdr = pfcp_get_pdr (sess, PFCP_ACTIVE, pdr_id);
  if (pdr == NULL)
    {
      error = clib_error_return (0, "could not find a pdr");
      goto done;
    }

  p = hash_get_mem (gtm->upf_app_by_name, name);
  if (!p)
    {
      goto done;
    }

  ASSERT (!pool_is_free_index (gtm->upf_apps, p[0]));

  if (add_flag == 0)
    {
      upf_adf_put_adr_db (pdr->pdi.adr.db_id);

      pdr->pdi.fields &= ~F_PDI_APPLICATION_ID;
      pdr->pdi.adr.application_id = ~0;
      pdr->pdi.adr.db_id = ~0;
    }
  else if (add_flag == 1)
    {
      pdr->pdi.fields |= F_PDI_APPLICATION_ID;
      pdr->pdi.adr.application_id = p[0];
      /* no ACLs at this point */
      pdr->pdi.adr.db_id = upf_adf_get_adr_db (p[0], NULL);
    }

  vlib_cli_output (vm, "ADR DB id: %u", pdr->pdi.adr.db_id);

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_adf_app_add_command, static) =
{
  .path = "upf adf app",
  .short_help = "upf adf app <add|update> session <id> pdr <id> name <app name>",
  .function = upf_adf_app_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_adf_url_test_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *sm = &upf_main;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  u8 *url = NULL;
  u32 id = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u url %_%v%_", &id, &url))
	break;
      else if (unformat (line_input, "name %v url %_%v%_", &name, &url))
	break;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (~0 == id && name != NULL)
    {
      uword *p = NULL;

      p = hash_get_mem (sm->upf_app_by_name, name);
      if (!p)
	{
	  error = clib_error_return (0, "application does not exist...");
	  goto done;
	}
      id = p[0];
    }

  if (upf_adf_lookup (id, url, vec_len (url), &id) < 0)
    vlib_cli_output (vm, "No matched found");
  else
    vlib_cli_output (vm, "Matched found, Id: %u", id);

done:
  vec_free (url);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_adf_url_test_command, static) =
{
  .path = "upf adf test db",
  .short_help = "upf adf test db [<id> | name <name>] url <url>",
  .function = upf_adf_url_test_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_adf_show_db_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  upf_main_t *sm = &upf_main;
  uword *p = NULL;
  upf_adf_entry_t *e;
  upf_adf_app_t *app;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  p = hash_get_mem (sm->upf_app_by_name, name);
  if (!p)
    goto done;

  app = pool_elt_at_index (sm->upf_apps, p[0]);
  if (app->db_index == ~0)
    {
      error = clib_error_return (0, "DB does not exist...");
      goto done;
    }

  e = pool_elt_at_index (upf_adf_db, app->db_index);
  for (int i = 0; i < vec_len (e->expressions); i++)
    {
      vlib_cli_output (vm, "id %u regex '%s'", e->ids[i], e->expressions[i]);
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_adf_show_db_command, static) =
{
  .path = "show upf adf app",
  .short_help = "show upf adf app <name>",
  .function = upf_adf_show_db_command_fn,
};
/* *INDENT-ON* */

/* Action function shared between message handler and debug CLI */

static int
vnet_upf_rule_add_del (u8 * app_name, u32 rule_index, u8 add, regex_t regex, acl_rule_t * acl_rule);

static int vnet_upf_app_add_del (u8 * name, u32 flags, u8 add);

int
upf_app_add_del (upf_main_t * sm, u8 * name, u32 flags, int add)
{
  int rv = 0;

  rv = vnet_upf_app_add_del (name, flags, add);

  return rv;
}

int
upf_rule_add_del (upf_main_t * sm, u8 * name, u32 id, int add, u8 * regex, acl_rule_t * acl_rule)
{
  int rv = 0;

  rv = vnet_upf_rule_add_del (name, id, add, regex, acl_rule);

  return rv;
}

static int
vnet_upf_app_add_del (u8 * name, u32 flags, u8 add)
{
  upf_main_t *sm = &upf_main;
  upf_adf_app_t *app = NULL;
  u32 index = 0;
  u32 rule_index = 0;
  uword *p = NULL;

  p = hash_get_mem (sm->upf_app_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (sm->upf_apps, app);
      memset (app, 0, sizeof (*app));

      app->name = vec_dup (name);
      app->flags = flags;
      app->rules_by_id = hash_create ( /* initial length */ 32, sizeof (uword));

      app->db_index = ~0;

      hash_set_mem (sm->upf_app_by_name, app->name, app - sm->upf_apps);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      app = pool_elt_at_index (sm->upf_apps, p[0]);

      if (upf_adf_adr_ref_count (app->db_index) != 0)
	return VNET_API_ERROR_INSTANCE_IN_USE;

      /* *INDENT-OFF* */
      hash_foreach(rule_index, index, app->rules_by_id,
      ({
	 upf_adr_t *rule = NULL;
	 rule = pool_elt_at_index(app->rules, index);
	 vnet_upf_rule_add_del(app->name, rule->id, 0, NULL, NULL);
      }));
      /* *INDENT-ON* */

      hash_unset_mem (sm->upf_app_by_name, app->name);
      if (app->db_index != ~0)
        upf_adf_remove (app->db_index);
      vec_free (app->name);
      hash_free (app->rules_by_id);
      pool_free (app->rules);
      clib_memset (app, 0, sizeof (*app));
      pool_put (sm->upf_apps, app);
    }

  return 0;
}

static clib_error_t *
upf_app_add_del_command_fn (vlib_main_t * vm,
			    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  u32 flags = 0;
  u8 add = 1;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "proxy"))
	flags |= UPF_ADR_PROXY;
      if (unformat (line_input, "name %_%v%_", &name))
	break;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!name)
    {
      error = clib_error_return (0, "id needs to be set");
      goto done;
    }

  rv = vnet_upf_app_add_del (name, flags, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "application is in use...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_app_add_del_command, static) =
{
 .path = "create upf application",
 .short_help = "create upf application name <name> [proxy] [add|del]",
 .function = upf_app_add_del_command_fn,
};
/* *INDENT-ON* */

static int
vnet_upf_rule_add_del (u8 * app_name, u32 rule_index, u8 add, regex_t regex, acl_rule_t * acl_rule)
{
  upf_main_t *sm = &upf_main;
  uword *p = NULL;
  upf_adf_app_t *app = NULL;
  upf_adr_t *rule = NULL;
  int res = 0;

  p = hash_get_mem (sm->upf_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (sm->upf_apps, p[0]);

  if (upf_adf_adr_ref_count (app->db_index) != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  p = hash_get (app->rules_by_id, rule_index);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (app->rules, rule);
      memset (rule, 0, sizeof (*rule));
      rule->id = rule_index;
      if (regex != 0)
        rule->regex = vec_dup(regex);
      if (acl_rule)
        rule->acl_rule = *acl_rule;

      hash_set (app->rules_by_id, rule_index, rule - app->rules);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      rule = pool_elt_at_index (app->rules, p[0]);
      vec_free (rule->regex);
      hash_unset (app->rules_by_id, rule_index);
      clib_memset (rule, 0, sizeof (*rule));
      pool_put (app->rules, rule);
    }

  res = upf_adf_create_update_db (app);
  if (res < 0)
    return res;

  return 0;
}

static clib_error_t *
upf_application_rule_add_del_command_fn (vlib_main_t * vm,
					 unformat_input_t * input,
					 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  regex_t regex = NULL;
  acl_rule_t rule;
  u8 *app_name = NULL;
  u32 rule_index = 0;
  int rv = 0;
  int add = 1;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_ rule %u", &app_name, &rule_index))
	{
	  if (unformat (line_input, "del"))
	    {
	      add = 0;
	      break;
	    }
	  else if (unformat (line_input, "add"))
	    {
	      add = 1;

	      if (unformat (line_input, "l7 regex %_%s%_", &regex))
		{
		  break;
		}
	      else if (unformat (line_input, "ipfilter %_%U%_", unformat_ipfilter, &rule))
                {
                  break;
                }
	      else
		{
		  error = clib_error_return (0, "unknown input `%U'",
					     format_unformat_error, input);
		  goto done;
		}
	    }
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  rv = vnet_upf_rule_add_del (app_name, rule_index, add, regex, &rule);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "rule already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application or rule does not exist...");
      break;

    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "application is in use...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (regex);
  vec_free (app_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_application_rule_add_del_command, static) =
{
  .path = "upf application",
  .short_help = "upf application <name> rule <id> (add | del) "
  "[l7 regex <regex> | ipfilter <ipfilter>]",
  .function = upf_application_rule_add_del_command_fn,
};
/* *INDENT-ON* */

u8 *
format_upf_adr (u8 * s, va_list * args)
{
  upf_adr_t *rule = va_arg (*args, upf_adr_t *);

  s = format (s, "rule %u", rule->id);

  if (rule->regex)
    s = format (s, " regex '%s'", rule->regex);
  else
    s = format (s, " ipfilter '%U'", format_ipfilter, &rule->acl_rule);

  return s;
}

static void
upf_show_rules (vlib_main_t * vm, upf_adf_app_t * app)
{
  u32 index = 0;
  u32 rule_index = 0;
  upf_adr_t *rule = NULL;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);
     vlib_cli_output (vm, "%U", format_upf_adr, rule);
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
upf_show_app_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  uword *p = NULL;
  clib_error_t *error = NULL;
  upf_adf_app_t *app = NULL;
  upf_main_t *sm = &upf_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  p = hash_get_mem (sm->upf_app_by_name, name);
  if (!p)
    {
      error = clib_error_return (0, "unknown application name");
      goto done;
    }

  app = pool_elt_at_index (sm->upf_apps, p[0]);
  upf_show_rules (vm, app);

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_app_command, static) =
{
  .path = "show upf application",
  .short_help = "show upf application <name>",
  .function = upf_show_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_apps_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  upf_main_t *sm = &upf_main;
  u8 *name = NULL;
  u32 index = 0;
  int verbose = 0;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    {
	      verbose = 1;
	      break;
	    }
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      unformat_free (line_input);
	      return error;
	    }
	}

      unformat_free (line_input);
    }

  /* *INDENT-OFF* */
  hash_foreach(name, index, sm->upf_app_by_name,
  ({
     upf_adf_app_t *app = NULL;
     app = pool_elt_at_index(sm->upf_apps, index);
     vlib_cli_output (vm, "app: %v", app->name);

     if (verbose)
       {
	 upf_show_rules(vm, app);
       }
  }));
  /* *INDENT-ON* */

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_apps_command, static) =
{
  .path = "show upf applications",
  .short_help = "show upf applications [verbose]",
  .function = upf_show_apps_command_fn,
};
/* *INDENT-ON* */


int
upf_update_app (upf_main_t * sm, u8 * app_name, u32 num_rules, u32 * ids, u32 * regex_lengths, u8 ** regexes)
{
  upf_adf_app_t *app = NULL;
  uword *p = NULL;
  upf_adr_t *rule = NULL;
  u32 index = 0;
  u32 rule_index = 0;
  int res = 0;

  p = hash_get_mem (sm->upf_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (sm->upf_apps, p[0]);

  // TODO: fix 'app in use'
  if (upf_adf_adr_ref_count (app->db_index) != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
    rule = pool_elt_at_index(app->rules, index);
    vec_free (rule->regex);
    clib_memset (rule, 0, sizeof (*rule));
    pool_put_index (app->rules, index);
  }));
  /* *INDENT-ON* */

  hash_free (app->rules_by_id);
  app->rules_by_id = hash_create (num_rules, sizeof (uword));

  for (u32 n = 0; n < num_rules; n++) {
    pool_get (app->rules, rule);
    memset (rule, 0, sizeof (*rule));
    rule->id = ids[n];
    rule->regex = vec_new (u8, regex_lengths[n]);
    clib_memcpy_fast (rule->regex, regexes[n], regex_lengths[n]);
    hash_set (app->rules_by_id, rule->id, rule - app->rules);
  }

  res = upf_adf_create_update_db (app);
  if (res < 0)
    return res;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
