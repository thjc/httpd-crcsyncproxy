// Ben messing around some more...

#include "httpd.h"
#include "http_config.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"

#include <ctype.h>

static const char s_szCaseFilterName[]="CaseFilter";
module case_filter_in_module;

typedef struct
{
    int bEnabled;
} CaseFilterInConfig;

typedef struct
{
    apr_bucket_brigade *pbbTmp;
} CaseFilterInContext;

static void *CaseFilterInCreateServerConfig(apr_pool_t *p,server_rec *s)
{
    CaseFilterInConfig *pConfig=apr_pcalloc(p,sizeof *pConfig);

    pConfig->bEnabled=0;

    return pConfig;
}

static void CaseFilterInInsertFilter(request_rec *r)
{
    CaseFilterInConfig *pConfig=ap_get_module_config(r->server->module_config,
						     &case_filter_in_module);
    CaseFilterInContext *pCtx;

    if(!pConfig->bEnabled)
	return;

    pCtx=apr_palloc(r->pool,sizeof *pCtx);
    pCtx->pbbTmp=apr_brigade_create(r->pool);
    ap_add_input_filter(s_szCaseFilterName,pCtx,r,NULL);
}

static apr_status_t CaseFilterInFilter(ap_filter_t *f,
				       apr_bucket_brigade *pbbOut,
				       ap_input_mode_t eMode,apr_size_t *nBytes)
{
    CaseFilterInContext *pCtx=f->ctx;
    apr_status_t ret;

    ap_assert(APR_BRIGADE_EMPTY(pCtx->pbbTmp));
    
    ret=ap_get_brigade(f->next,pCtx->pbbTmp,eMode,nBytes);
    if(eMode == AP_MODE_PEEK || ret != APR_SUCCESS)
	return ret;

    while(!APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
	apr_bucket *pbktIn=APR_BRIGADE_FIRST(pCtx->pbbTmp);
	apr_bucket *pbktOut;
	const char *data;
	apr_size_t len;
	char *buf;
	int n;

	// It is tempting to do this...
	//APR_BUCKET_REMOVE(pB);
	//APR_BRIGADE_INSERT_TAIL(pbbOut,pB);
	// and change the case of the bucket data, but that would be wrong
	// for a file or socket buffer, for example...

	if(APR_BUCKET_IS_EOS(pbktIn)) {
	    APR_BUCKET_REMOVE(pbktIn);
	    APR_BRIGADE_INSERT_TAIL(pbbOut,pbktIn);
	    break;
	}

	ret=apr_bucket_read(pbktIn,&data,&len,eMode);
	if(ret != APR_SUCCESS)
	    return ret;

	buf=malloc(len);
	for(n=0 ; n < len ; ++n)
	    buf[n]=toupper(data[n]);

	pbktOut=apr_bucket_heap_create(buf,len,0,NULL);
	APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
	apr_bucket_delete(pbktIn);
    }

    return APR_SUCCESS;
}
	    
	
static const char *CaseFilterEnable(cmd_parms *cmd, void *dummy, int arg)
    {
    CaseFilterInConfig *pConfig
      =ap_get_module_config(cmd->server->module_config,&case_filter_in_module);
    pConfig->bEnabled=arg;

    return NULL;
    }

static const command_rec CaseFilterInCmds[] = 
    {
    AP_INIT_FLAG("CaseFilterIn", CaseFilterEnable, NULL, RSRC_CONF,
                 "Run an input case filter on this host"),
    { NULL }
    };


static void CaseFilterInRegisterHooks(apr_pool_t *p)
    {
    ap_hook_insert_filter(CaseFilterInInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_input_filter(s_szCaseFilterName,CaseFilterInFilter,
			      AP_FTYPE_CONTENT);
    }

module case_filter_in_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    CaseFilterInCreateServerConfig,
    NULL,
    CaseFilterInCmds,
    CaseFilterInRegisterHooks
};
