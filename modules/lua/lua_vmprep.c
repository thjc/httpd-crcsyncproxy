/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mod_lua.h"
#include "http_log.h"
#include "apr_reslist.h"
#include "apr_uuid.h"
#include "lua_config.h"
#include "apr_file_info.h"

/* forward dec'l from this file */

static void pstack_dump(lua_State* L, apr_pool_t* r, int level, const char* msg) {
    ap_log_perror(APLOG_MARK, level, 0, r, "Lua Stack Dump: [%s]", msg);

    int i;
    int top = lua_gettop(L);
    for (i = 1; i<= top; i++) {
        int t = lua_type(L, i);
        switch(t) {
            case LUA_TSTRING: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  '%s'", i, lua_tostring(L, i));
                break;
            }
            case LUA_TUSERDATA: {
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  userdata", i);                
                break;
            }
            case LUA_TLIGHTUSERDATA: {
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  lightuserdata", i);
                break;
            }
            case LUA_TNIL: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  NIL", i);
                break;
            }
            case LUA_TNONE: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  None", i);
                break;
            }
            case LUA_TBOOLEAN: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  %s", i,  lua_toboolean(L, i) ? "true" : "false");
                break;
            }
            case LUA_TNUMBER: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  %g", i, lua_tonumber(L, i));
                break;
            }
            case LUA_TTABLE: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  <table>", i);
                break;
            }
            case LUA_TTHREAD: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  <thread>", i);
                break;
            }
            case LUA_TFUNCTION: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  <function>", i);
                break;
            }
            default: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  unkown: [%s]", i, lua_typename(L, i));
                break;                
            }
        }
    }
}

/* BEGIN modules*/

/* BEGIN apache lmodule  */

void apl_load_apache2_lmodule(lua_State *L) {
    lua_getglobal(L, "package");
    lua_getfield(L, -1, "loaded");
    lua_newtable(L);    
    lua_setfield(L, -2, "apache2");
    lua_setglobal(L, "apache2");
    lua_pop(L, 1); /* empty stack */

    lua_getglobal(L, "apache2");
    lua_pushinteger(L, OK);
    lua_setfield(L, -2, "OK");

    lua_pushinteger(L, DECLINED);
    lua_setfield(L, -2, "DECLINED");

    lua_pushinteger(L, DONE);
    lua_setfield(L, -2, "DONE");
   
    lua_pushstring(L, ap_get_server_banner());
    lua_setfield(L, -2, "version");

    lua_pushinteger(L, HTTP_MOVED_TEMPORARILY);
    lua_setfield(L, -2, "HTTP_MOVED_TEMPORARILY");
    
    /*
    lua_pushinteger(L, HTTP_CONTINUE);
    lua_setfield(L, -2, "HTTP_CONTINUE");
    lua_pushinteger(L, HTTP_SWITCHING_PROTOCOLS);
    lua_setfield(L, -2, "HTTP_SWITCHING_PROTOCOLS");
    lua_pushinteger(L, HTTP_PROCESSING);
    lua_setfield(L, -2, "HTTP_PROCESSING");
    lua_pushinteger(L, HTTP_OK);
    lua_setfield(L, -2, "HTTP_OK");
    lua_pushinteger(L, HTTP_CREATED);
    lua_setfield(L, -2, "HTTP_CREATED");
    lua_pushinteger(L, HTTP_ACCEPTED);
    lua_setfield(L, -2, "HTTP_ACCEPTED");
    lua_pushinteger(L, HTTP_NON_AUTHORITATIVE);
    lua_setfield(L, -2, "HTTP_NON_AUTHORITATIVE");
    lua_pushinteger(L, HTTP_NO_CONTENT);
    lua_setfield(L, -2, "HTTP_NO_CONTENT");
    lua_pushinteger(L, HTTP_RESET_CONTENT);
    lua_setfield(L, -2, "HTTP_RESET_CONTENT");
    lua_pushinteger(L, HTTP_PARTIAL_CONTENT);
    lua_setfield(L, -2, "HTTP_PARTIAL_CONTENT");
    lua_pushinteger(L, HTTP_MULTI_STATUS);
    lua_setfield(L, -2, "HTTP_MULTI_STATUS");
    lua_pushinteger(L, HTTP_MULTIPLE_CHOICES);
    lua_setfield(L, -2, "HTTP_MULTIPLE_CHOICES");
    lua_pushinteger(L, HTTP_MOVED_PERMANENTLY);
    lua_setfield(L, -2, "HTTP_MOVED_PERMANENTLY");
    lua_pushinteger(L, HTTP_SEE_OTHER);
    lua_setfield(L, -2, "HTTP_SEE_OTHER");
    lua_pushinteger(L, HTTP_NOT_MODIFIED);
    lua_setfield(L, -2, "HTTP_NOT_MODIFIED");
    lua_pushinteger(L, HTTP_USE_PROXY);
    lua_setfield(L, -2, "HTTP_USE_PROXY");
    lua_pushinteger(L, HTTP_TEMPORARY_REDIRECT);
    lua_setfield(L, -2, "HTTP_TEMPORARY_REDIRECT");
    lua_pushinteger(L, HTTP_BAD_REQUEST);
    lua_setfield(L, -2, "HTTP_BAD_REQUEST");
    lua_pushinteger(L, HTTP_UNAUTHORIZED);
    lua_setfield(L, -2, "HTTP_UNAUTHORIZED");
    lua_pushinteger(L, HTTP_PAYMENT_REQUIRED);
    lua_setfield(L, -2, "HTTP_PAYMENT_REQUIRED");
    lua_pushinteger(L, HTTP_FORBIDDEN);
    lua_setfield(L, -2, "HTTP_FORBIDDEN");
    lua_pushinteger(L, HTTP_NOT_FOUND);
    lua_setfield(L, -2, "HTTP_NOT_FOUND");
    lua_pushinteger(L, HTTP_METHOD_NOT_ALLOWED);
    lua_setfield(L, -2, "HTTP_METHOD_NOT_ALLOWED");
    lua_pushinteger(L, HTTP_NOT_ACCEPTABLE);
    lua_setfield(L, -2, "HTTP_NOT_ACCEPTABLE");
    lua_pushinteger(L, HTTP_PROXY_AUTHENTICATION_REQUIRED);
    lua_setfield(L, -2, "HTTP_PROXY_AUTHENTICATION_REQUIRED");
    lua_pushinteger(L, HTTP_REQUEST_TIME_OUT);
    lua_setfield(L, -2, "HTTP_REQUEST_TIME_OUT");
    lua_pushinteger(L, HTTP_CONFLICT);
    lua_setfield(L, -2, "HTTP_CONFLICT");
    lua_pushinteger(L, HTTP_GONE);
    lua_setfield(L, -2, "HTTP_GONE");
    lua_pushinteger(L, HTTP_LENGTH_REQUIRED);
    lua_setfield(L, -2, "HTTP_LENGTH_REQUIRED");
    lua_pushinteger(L, HTTP_PRECONDITION_FAILED);
    lua_setfield(L, -2, "HTTP_PRECONDITION_FAILED");
    lua_pushinteger(L, HTTP_REQUEST_ENTITY_TOO_LARGE);
    lua_setfield(L, -2, "HTTP_REQUEST_ENTITY_TOO_LARGE");
    lua_pushinteger(L, HTTP_REQUEST_URI_TOO_LARGE);
    lua_setfield(L, -2, "HTTP_REQUEST_URI_TOO_LARGE");
    lua_pushinteger(L, HTTP_UNSUPPORTED_MEDIA_TYPE);
    lua_setfield(L, -2, "HTTP_UNSUPPORTED_MEDIA_TYPE");
    lua_pushinteger(L, HTTP_RANGE_NOT_SATISFIABLE);
    lua_setfield(L, -2, "HTTP_RANGE_NOT_SATISFIABLE");
    lua_pushinteger(L, HTTP_EXPECTATION_FAILED);
    lua_setfield(L, -2, "HTTP_EXPECTATION_FAILED");
    lua_pushinteger(L, HTTP_UNPROCESSABLE_ENTITY);
    lua_setfield(L, -2, "HTTP_UNPROCESSABLE_ENTITY");
    lua_pushinteger(L, HTTP_LOCKED);
    lua_setfield(L, -2, "HTTP_LOCKED");
    lua_pushinteger(L, HTTP_FAILED_DEPENDENCY);
    lua_setfield(L, -2, "HTTP_FAILED_DEPENDENCY");
    lua_pushinteger(L, HTTP_UPGRADE_REQUIRED);
    lua_setfield(L, -2, "HTTP_UPGRADE_REQUIRED");
    lua_pushinteger(L, HTTP_INTERNAL_SERVER_ERROR);
    lua_setfield(L, -2, "HTTP_INTERNAL_SERVER_ERROR");
    lua_pushinteger(L, HTTP_NOT_IMPLEMENTED);
    lua_setfield(L, -2, "HTTP_NOT_IMPLEMENTED");
    lua_pushinteger(L, HTTP_BAD_GATEWAY);
    lua_setfield(L, -2, "HTTP_BAD_GATEWAY");
    lua_pushinteger(L, HTTP_SERVICE_UNAVAILABLE);
    lua_setfield(L, -2, "HTTP_SERVICE_UNAVAILABLE");
    lua_pushinteger(L, HTTP_GATEWAY_TIME_OUT);
    lua_setfield(L, -2, "HTTP_GATEWAY_TIME_OUT");
    lua_pushinteger(L, HTTP_VERSION_NOT_SUPPORTED);
    lua_setfield(L, -2, "HTTP_VERSION_NOT_SUPPORTED");
    lua_pushinteger(L, HTTP_VARIANT_ALSO_VARIES);
    lua_setfield(L, -2, "HTTP_VARIANT_ALSO_VARIES");
    lua_pushinteger(L, HTTP_INSUFFICIENT_STORAGE);
    lua_setfield(L, -2, "HTTP_INSUFFICIENT_STORAGE");
    lua_pushinteger(L, HTTP_NOT_EXTENDED);
    lua_setfield(L, -2, "HTTP_NOT_EXTENDED");
    */
} 

/* END apache2 lmodule */

/*  END library functions */

/* callback for cleaning up a lua vm when pool is closed */
static apr_status_t cleanup_lua(void *l) {
  lua_close((lua_State*) l);
  return APR_SUCCESS;
}

static void munge_path(lua_State *L, 
                       const char *field,
                       const char *sub_pat, 
                       const char *rep_pat,
                       apr_pool_t *pool, 
                       apr_array_header_t *paths, 
                       const char *file) {
  lua_getglobal(L, "package");
  lua_getfield(L, -1, field);
  const char* current = lua_tostring(L, -1);
  const char* parent_dir = ap_make_dirstr_parent(pool, file);
  const char* pattern = apr_pstrcat(pool, parent_dir, sub_pat, NULL);
  luaL_gsub(L, current, rep_pat, pattern);
  lua_setfield(L, -3, field);
  lua_getfield(L, -2, field);
  const char* modified = lua_tostring(L, -1);
  lua_pop(L, 2);
  
  char * part = apr_pstrdup(pool, modified);
  int i;
  for (i = 0; i < paths->nelts; i++) {
    const char *new_path = ((const char**)paths->elts)[i];
    part = apr_pstrcat(pool, part, ";", new_path, NULL);
  }
  lua_pushstring(L, part);
  lua_setfield(L, -2, field);
  lua_pop(L, 1); /* pop "package" off the stack     */
}

lua_State* apl_get_lua_state(apr_pool_t* lifecycle_pool, 
                            char* file, 
                            apr_array_header_t* package_paths, 
                            apr_array_header_t* package_cpaths,
                            apl_lua_state_open_callback cb,
                            void* btn) {
    
    lua_State* L;
    ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, lifecycle_pool, "obtaining lua_State");
    if (!apr_pool_userdata_get((void**)&L, file, lifecycle_pool)) {
        ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, lifecycle_pool, "creating lua_State with file %s", file);
        /* not available, so create */
        L =  luaL_newstate();
        luaL_openlibs(L);        
        if (package_paths) 
            munge_path(L, "path", "?.lua", "./?.lua", lifecycle_pool, package_paths, file);
        if (package_cpaths) 
            munge_path(L, "cpath", "?.so", "./?.so", lifecycle_pool, package_cpaths, file);
        
        if (cb) {
            cb(L, lifecycle_pool, btn);
        }
        
        luaL_loadfile(L, file);
        lua_pcall(L, 0, LUA_MULTRET, 0);
        apr_pool_userdata_set(L, file, &cleanup_lua, lifecycle_pool);
        
        lua_pushlightuserdata(L, lifecycle_pool);
        lua_setfield(L, LUA_REGISTRYINDEX, "Apache2.Wombat.pool");  
    }
    return L;
}






