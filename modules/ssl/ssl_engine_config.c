/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_config.c
**  Apache Configuration Directives
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */

                                      /* ``Damned if you do,
                                           damned if you don't.''
                                               -- Unknown        */
#include "mod_ssl.h"

/*  _________________________________________________________________
**
**  Support for Global Configuration
**  _________________________________________________________________
*/

#define SSL_MOD_CONFIG_KEY "ssl_module"

SSLModConfigRec *ssl_config_global_create(server_rec *s)
{
    apr_pool_t *pool = s->process->pool;
    SSLModConfigRec *mc;

    apr_pool_userdata_get((void **)&mc, SSL_MOD_CONFIG_KEY,
                          pool);

    if (mc) {
        return mc; /* reused for lifetime of the server */
    }

    /*
     * allocate an own subpool which survives server restarts
     */
    mc = (SSLModConfigRec *)apr_palloc(pool, sizeof(*mc));
    mc->pPool = pool;
    mc->bFixed = FALSE;

    /*
     * initialize per-module configuration
     */
    mc->nSessionCacheMode      = SSL_SCMODE_UNSET;
    mc->szSessionCacheDataFile = NULL;
    mc->nSessionCacheDataSize  = 0;
    mc->pSessionCacheDataMM    = NULL;
    mc->pSessionCacheDataRMM   = NULL;
    mc->tSessionCacheDataTable = NULL;
    mc->nMutexMode             = SSL_MUTEXMODE_UNSET;
    mc->szMutexFile            = NULL;
    mc->pMutex                 = NULL;
    mc->aRandSeed              = apr_array_make(pool, 4,
                                                sizeof(ssl_randseed_t));
    mc->tVHostKeys             = apr_hash_make(pool);
    mc->tPrivateKey            = apr_hash_make(pool);
    mc->tPublicCert            = apr_hash_make(pool);
#ifdef SSL_EXPERIMENTAL_ENGINE
    mc->szCryptoDevice         = NULL;
#endif

    memset(mc->pTmpKeys, 0, sizeof(mc->pTmpKeys));

    apr_pool_userdata_set(mc, SSL_MOD_CONFIG_KEY,
                          apr_pool_cleanup_null,
                          pool);

    return mc;
}

void ssl_config_global_fix(SSLModConfigRec *mc)
{
    mc->bFixed = TRUE;
}

BOOL ssl_config_global_isfixed(SSLModConfigRec *mc)
{
    return mc->bFixed;
}

/*  _________________________________________________________________
**
**  Configuration handling
**  _________________________________________________________________
*/

/*
 *  Create per-server SSL configuration
 */
void *ssl_config_server_create(apr_pool_t *p, server_rec *s)
{
    SSLSrvConfigRec *sc = apr_palloc(p, sizeof(*sc));

    sc->mc                     = ssl_config_global_create(s);
    sc->bEnabled               = UNSET;
    sc->szCACertificatePath    = NULL;
    sc->szCACertificateFile    = NULL;
    sc->szCertificateChain     = NULL;
    sc->szLogFile              = NULL;
    sc->szCipherSuite          = NULL;
    sc->nLogLevel              = SSL_LOG_NONE;
    sc->nVerifyDepth           = UNSET;
    sc->nVerifyClient          = SSL_CVERIFY_UNSET;
    sc->nSessionCacheTimeout   = UNSET;
    sc->nPassPhraseDialogType  = SSL_PPTYPE_UNSET;
    sc->szPassPhraseDialogPath = NULL;
    sc->nProtocol              = SSL_PROTOCOL_ALL;
    sc->fileLogFile            = NULL;
    sc->pSSLCtx                = NULL;
    sc->szCARevocationPath     = NULL;
    sc->szCARevocationFile     = NULL;
    sc->pRevocationStore       = NULL;

#ifdef SSL_EXPERIMENTAL_PROXY
    sc->nProxyVerifyDepth             = UNSET;
    sc->szProxyCACertificatePath      = NULL;
    sc->szProxyCACertificateFile      = NULL;
    sc->szProxyClientCertificateFile  = NULL;
    sc->szProxyClientCertificatePath  = NULL;
    sc->szProxyCipherSuite            = NULL;
    sc->nProxyProtocol                = SSL_PROTOCOL_ALL & ~SSL_PROTOCOL_TLSV1;
    sc->bProxyVerify                  = UNSET;
    sc->pSSLProxyCtx                  = NULL;
#endif

    memset((void*)sc->szPublicCertFiles, 0, sizeof(sc->szPublicCertFiles));
    memset((void*)sc->szPrivateKeyFiles, 0, sizeof(sc->szPrivateKeyFiles));
    memset(sc->pPublicCert,       0, sizeof(sc->pPublicCert));
    memset(sc->pPrivateKey,       0, sizeof(sc->pPrivateKey));

    return sc;
}

/*
 *  Merge per-server SSL configurations
 */
void *ssl_config_server_merge(apr_pool_t *p, void *basev, void *addv)
{
    int i;
    SSLSrvConfigRec *base = (SSLSrvConfigRec *)basev;
    SSLSrvConfigRec *add  = (SSLSrvConfigRec *)addv;
    SSLSrvConfigRec *new  = (SSLSrvConfigRec *)apr_palloc(p, sizeof(*new));

    cfgMerge(mc, NULL);
    cfgMergeString(szVHostID);
    cfgMergeBool(bEnabled);
    cfgMergeString(szCACertificatePath);
    cfgMergeString(szCACertificateFile);
    cfgMergeString(szCertificateChain);
    cfgMergeString(szLogFile);
    cfgMergeString(szCipherSuite);
    cfgMerge(nLogLevel, SSL_LOG_NONE);
    cfgMergeInt(nVerifyDepth);
    cfgMerge(nVerifyClient, SSL_CVERIFY_UNSET);
    cfgMergeInt(nSessionCacheTimeout);
    cfgMerge(nPassPhraseDialogType, SSL_PPTYPE_UNSET);
    cfgMergeString(szPassPhraseDialogPath);
    cfgMerge(nProtocol, SSL_PROTOCOL_ALL);
    cfgMerge(fileLogFile, NULL);
    cfgMerge(pSSLCtx, NULL);
    cfgMerge(szCARevocationPath, NULL);
    cfgMerge(szCARevocationFile, NULL);
    cfgMerge(pRevocationStore, NULL);

    for (i = 0; i < SSL_AIDX_MAX; i++) {
        cfgMergeString(szPublicCertFiles[i]);
        cfgMergeString(szPrivateKeyFiles[i]);
        cfgMerge(pPublicCert[i], NULL);
        cfgMerge(pPrivateKey[i], NULL);
    }

#ifdef SSL_EXPERIMENTAL_PROXY
    cfgMergeInt(nProxyVerifyDepth);
    cfgMergeString(szProxyCACertificatePath);
    cfgMergeString(szProxyCACertificateFile);
    cfgMergeString(szProxyClientCertificateFile);
    cfgMergeString(szProxyClientCertificatePath);
    cfgMergeString(szProxyCipherSuite);
    cfgMerge(nProxyProtocol, (SSL_PROTOCOL_ALL & ~SSL_PROTOCOL_TLSV1));
    cfgMergeBool(bProxyVerify);
    cfgMerge(pSSLProxyCtx, NULL);
#endif

    return new;
}

/*
 *  Create per-directory SSL configuration
 */
void *ssl_config_perdir_create(apr_pool_t *p, char *dir)
{
    SSLDirConfigRec *dc = apr_palloc(p, sizeof(*dc));

    dc->bSSLRequired  = FALSE;
    dc->aRequirement  = apr_array_make(p, 4, sizeof(ssl_require_t));
    dc->nOptions      = SSL_OPT_NONE|SSL_OPT_RELSET;
    dc->nOptionsAdd   = SSL_OPT_NONE;
    dc->nOptionsDel   = SSL_OPT_NONE;

    dc->szCipherSuite          = NULL;
    dc->nVerifyClient          = SSL_CVERIFY_UNSET;
    dc->nVerifyDepth           = UNSET;

#ifdef SSL_EXPERIMENTAL_PERDIRCA
    dc->szCACertificatePath    = NULL;
    dc->szCACertificateFile    = NULL;
#endif

    return dc;
}

/*
 *  Merge per-directory SSL configurations
 */
void *ssl_config_perdir_merge(apr_pool_t *p, void *basev, void *addv)
{
    SSLDirConfigRec *base = (SSLDirConfigRec *)basev;
    SSLDirConfigRec *add  = (SSLDirConfigRec *)addv;
    SSLDirConfigRec *new  = (SSLDirConfigRec *)apr_palloc(p, sizeof(*new));

    cfgMerge(bSSLRequired, FALSE);
    cfgMergeArray(aRequirement);

    if (add->nOptions & SSL_OPT_RELSET) {
        new->nOptionsAdd =
            (base->nOptionsAdd & ~(add->nOptionsDel)) | add->nOptionsAdd;
        new->nOptionsDel =
            (base->nOptionsDel & ~(add->nOptionsAdd)) | add->nOptionsDel;
        new->nOptions    =
            (base->nOptions    & ~(new->nOptionsDel)) | new->nOptionsAdd;
    }
    else {
        new->nOptions    = add->nOptions;
        new->nOptionsAdd = add->nOptionsAdd;
        new->nOptionsDel = add->nOptionsDel;
    }

    cfgMergeString(szCipherSuite);
    cfgMerge(nVerifyClient, SSL_CVERIFY_UNSET);
    cfgMergeInt(nVerifyDepth);

#ifdef SSL_EXPERIMENTAL_PERDIRCA
    cfgMergeString(szCACertificatePath);
    cfgMergeString(szCACertificateFile);
#endif

    return new;
}

/*
 *  Configuration functions for particular directives
 */

const char *ssl_cmd_SSLMutex(cmd_parms *cmd, void *ctx,
                             const char *arg)
{
    const char *err;
    SSLModConfigRec *mc = myModConfig(cmd->server);

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (ssl_config_global_isfixed(mc)) {
        return NULL;
    }

    if (strcEQ(arg, "none") || strcEQ(arg, "no")) {
        mc->nMutexMode  = SSL_MUTEXMODE_NONE;
    }
    else if (strlen(arg) > 5 && strcEQn(arg, "file:", 5)) {
        const char *file = ap_server_root_relative(cmd->pool, arg+5);
        if (!file) {
            return apr_pstrcat(cmd->pool, "Invalid SSLMutex file: path ", 
                               arg+5, NULL);
        }
        mc->nMutexMode  = SSL_MUTEXMODE_USED;
        mc->szMutexFile =
            (char *)apr_psprintf(mc->pPool, "%s.%lu",
                                 file, (unsigned long)getpid());
    }
    else if (strcEQ(arg, "sem") || strcEQ(arg, "yes")) {
        mc->nMutexMode  = SSL_MUTEXMODE_USED;
        mc->szMutexFile = NULL; /* APR determines temporary filename */
    }
    else {
        return apr_pstrcat(cmd->pool, "Invalid SSLMutex argument ", 
                           arg, NULL);
    }

    return NULL;
}

const char *ssl_cmd_SSLPassPhraseDialog(cmd_parms *cmd, void *ctx,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;
    int arglen = strlen(arg);

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (strcEQ(arg, "builtin")) {
        sc->nPassPhraseDialogType  = SSL_PPTYPE_BUILTIN;
        sc->szPassPhraseDialogPath = NULL;
    }
    else if ((arglen > 5) && strEQn(arg, "exec:", 5)) {
        sc->nPassPhraseDialogType  = SSL_PPTYPE_FILTER;
        /* ### This is broken, exec: may contain args, no? */
        sc->szPassPhraseDialogPath =
            ap_server_root_relative(cmd->pool, arg+5);
        if (!sc->szPassPhraseDialogPath) {
            return apr_pstrcat(cmd->pool,
                               "Invalid SSLPassPhraseDialog exec: path ",
                               arg+5, NULL);
        }
        if (!ssl_util_path_check(SSL_PCM_EXISTS,
                                 sc->szPassPhraseDialogPath,
                                 cmd->pool))
        {
            return apr_pstrcat(cmd->pool,
                               "SSLPassPhraseDialog: file '",
                               sc->szPassPhraseDialogPath,
                               "' does not exist", NULL);
        }

    }
    else if ((arglen > 1) && (arg[0] == '|')) {
        sc->nPassPhraseDialogType  = SSL_PPTYPE_PIPE;
        sc->szPassPhraseDialogPath = arg + 1;
    }
    else {
        return "SSLPassPhraseDialog: Invalid argument";
    }

    return NULL;
}

#ifdef SSL_EXPERIMENTAL_ENGINE
const char *ssl_cmd_SSLCryptoDevice(cmd_parms *cmd, void *ctx,
                                    const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err;
    ENGINE *e;
#if SSL_LIBRARY_VERSION >= 0x00907000
    static int loaded_engines = FALSE;

    /* early loading to make sure the engines are already 
       available for ENGINE_by_id() above... */
    if (!loaded_engines) {
        ENGINE_load_builtin_engines();
        loaded_engines = TRUE;
    }
#endif
    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (strcEQ(arg, "builtin")) {
        mc->szCryptoDevice = NULL;
    }
    else if ((e = ENGINE_by_id(arg))) {
        mc->szCryptoDevice = arg;
        ENGINE_free(e);
    }
    else {
        return "SSLCryptoDevice: Invalid argument";
    }

    return NULL;
}
#endif

const char *ssl_cmd_SSLRandomSeed(cmd_parms *cmd, void *ctx,
                                  const char *arg1, 
                                  const char *arg2,
                                  const char *arg3)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err;
    ssl_randseed_t *seed;
    int arg2len = strlen(arg2);

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (ssl_config_global_isfixed(mc)) {
        return NULL;
    }

    seed = apr_array_push(mc->aRandSeed);

    if (strcEQ(arg1, "startup")) {
        seed->nCtx = SSL_RSCTX_STARTUP;
    }
    else if (strcEQ(arg1, "connect")) {
        seed->nCtx = SSL_RSCTX_CONNECT;
    }
    else {
        return apr_pstrcat(cmd->pool, "SSLRandomSeed: "
                           "invalid context: `", arg1, "'",
                           NULL);
    }

    if ((arg2len > 5) && strEQn(arg2, "file:", 5)) {
        seed->nSrc   = SSL_RSSRC_FILE;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+5);
    }
    else if ((arg2len > 5) && strEQn(arg2, "exec:", 5)) {
        seed->nSrc   = SSL_RSSRC_EXEC;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+5);
    }
    else if ((arg2len > 4) && strEQn(arg2, "egd:", 4)) {
        seed->nSrc   = SSL_RSSRC_EGD;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+4);
    }
    else if (strcEQ(arg2, "builtin")) {
        seed->nSrc   = SSL_RSSRC_BUILTIN;
        seed->cpPath = NULL;
    }
    else {
        seed->nSrc   = SSL_RSSRC_FILE;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2);
    }

    if (seed->nSrc != SSL_RSSRC_BUILTIN) {
        if (!seed->cpPath) {
            return apr_pstrcat(cmd->pool,
                               "Invalid SSLRandomSeed path ",
                               arg2, NULL);
        }
        if (!ssl_util_path_check(SSL_PCM_EXISTS, seed->cpPath, cmd->pool)) {
            return apr_pstrcat(cmd->pool,
                               "SSLRandomSeed: source path '",
                               seed->cpPath, "' does not exist", NULL);
        }
    }

    if (!arg3) {
        seed->nBytes = 0; /* read whole file */
    }
    else {
        if (seed->nSrc == SSL_RSSRC_BUILTIN) {
            return "SSLRandomSeed: byte specification not "
                   "allowed for builtin seed source";
        }

        seed->nBytes = atoi(arg3);

        if (seed->nBytes < 0) {
            return "SSLRandomSeed: invalid number of bytes specified";
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLEngine(cmd_parms *cmd, void *ctx, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->bEnabled = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLCipherSuite(cmd_parms *cmd, void *ctx,
                                   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;

    if (cmd->path) {
        dc->szCipherSuite = (char *)arg;
    }
    else {
        sc->szCipherSuite = arg;
    }

    return NULL;
}

#define SSL_FLAGS_CHECK_FILE \
    (SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO)

#define SSL_FLAGS_CHECK_DIR \
    (SSL_PCM_EXISTS|SSL_PCM_ISDIR)

static const char *ssl_cmd_check_file(cmd_parms *parms,
                                      const char **file)
{
    const char *filepath = ap_server_root_relative(parms->pool, *file);

    if (!filepath) {
        return apr_pstrcat(parms->pool, parms->cmd->name,
                           ": Invalid file path ", *file, NULL);
    }
    *file = filepath;

    if (ssl_util_path_check(SSL_FLAGS_CHECK_FILE, *file, parms->pool)) {
        return NULL;
    }

    return apr_pstrcat(parms->pool, parms->cmd->name,
                       ": file '", *file, 
                       "' does not exist or is empty", NULL);

}

static const char *ssl_cmd_check_dir(cmd_parms *parms,
                                     const char **dir)
{
    const char *dirpath = ap_server_root_relative(parms->pool, *dir);

    if (!dirpath) {
        return apr_pstrcat(parms->pool, parms->cmd->name,
                           ": Invalid dir path ", *dir, NULL);
    }
    *dir = dirpath;

    if (ssl_util_path_check(SSL_FLAGS_CHECK_DIR, *dir, parms->pool)) {
        return NULL;
    }

    return apr_pstrcat(parms->pool, parms->cmd->name,
                       ": directory '", *dir, 
                       "' does not exist", NULL);

}

#define SSL_AIDX_CERTS 1
#define SSL_AIDX_KEYS  2

static const char *ssl_cmd_check_aidx_max(cmd_parms *parms,
                                          const char *arg,
                                          int idx)
{
    SSLSrvConfigRec *sc = mySrvConfig(parms->server);
    const char *err, *desc=NULL, **files=NULL;
    int i;

    if ((err = ssl_cmd_check_file(parms, &arg))) {
        return err;
    }

    switch (idx) {
      case SSL_AIDX_CERTS:
        desc = "certificates";
        files = sc->szPublicCertFiles;
        break;
      case SSL_AIDX_KEYS:
        desc = "private keys";
        files = sc->szPrivateKeyFiles;
        break;
    }

    for (i = 0; i < SSL_AIDX_MAX; i++) {
        if (!files[i]) {
            files[i] = arg;
            return NULL;
        }
    }

    return apr_psprintf(parms->pool,
                        "%s: only up to %d "
                        "different %s per virtual host allowed", 
                         parms->cmd->name, SSL_AIDX_MAX, desc);
}

const char *ssl_cmd_SSLCertificateFile(cmd_parms *cmd, void *ctx,
                                       const char *arg)
{

    const char *err;

    if ((err = ssl_cmd_check_aidx_max(cmd, arg, SSL_AIDX_CERTS))) {
        return err;
    }

    return NULL;
}

const char *ssl_cmd_SSLCertificateKeyFile(cmd_parms *cmd, void *ctx,
                                          const char *arg)
{
    const char *err;

    if ((err = ssl_cmd_check_aidx_max(cmd, arg, SSL_AIDX_KEYS))) {
        return err;
    }

    return NULL;
}

const char *ssl_cmd_SSLCertificateChainFile(cmd_parms *cmd, void *ctx,
                                            const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->szCertificateChain = arg;

    return NULL;
}

const char *ssl_cmd_SSLCACertificatePath(cmd_parms *cmd, void *ctx,
                                         const char *arg)
{
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;
#endif
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

#ifdef SSL_EXPERIMENTAL_PERDIRCA
    if (cmd->path) {
        dc->szCACertificatePath = arg;
    }
    else {
        sc->szCACertificatePath = arg;
    }
#else
    sc->szCACertificatePath = arg;
#endif

    return NULL;
}

const char *ssl_cmd_SSLCACertificateFile(cmd_parms *cmd, void *ctx,
                                         const char *arg)
{
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;
#endif
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

#ifdef SSL_EXPERIMENTAL_PERDIRCA
    if (cmd->path) {
        dc->szCACertificateFile = arg;
    }
    else {
        sc->szCACertificateFile = arg;
    }
#else
    sc->szCACertificateFile = arg;
#endif

    return NULL;
}

const char *ssl_cmd_SSLCARevocationPath(cmd_parms *cmd, void *ctx,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    sc->szCARevocationPath = arg;

    return NULL;
}

const char *ssl_cmd_SSLCARevocationFile(cmd_parms *cmd, void *ctx,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->szCARevocationFile = arg;

    return NULL;
}

static const char *ssl_cmd_verify_parse(cmd_parms *parms,
                                        const char *arg,
                                        ssl_verify_t *id)
{
    if (strcEQ(arg, "none") || strcEQ(arg, "off")) {
        *id = SSL_CVERIFY_NONE;
    }
    else if (strcEQ(arg, "optional")) {
        *id = SSL_CVERIFY_OPTIONAL;
    }
    else if (strcEQ(arg, "require") || strcEQ(arg, "on")) {
        *id = SSL_CVERIFY_REQUIRE;
    }
    else if (strcEQ(arg, "optional_no_ca")) {
        *id = SSL_CVERIFY_OPTIONAL_NO_CA;
    }
    else {
        return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                           ": Invalid argument '", arg, "'",
                           NULL);
    }

    return NULL;
}

const char *ssl_cmd_SSLVerifyClient(cmd_parms *cmd, void *ctx,
                                    const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    ssl_verify_t id;
    const char *err;

    if ((err = ssl_cmd_verify_parse(cmd, arg, &id))) {
        return err;
    }
    
    if (cmd->path) {
        dc->nVerifyClient = id;
    }
    else {
        sc->nVerifyClient = id;
    }

    return NULL;
}

static const char *ssl_cmd_verify_depth_parse(cmd_parms *parms,
                                              const char *arg,
                                              int *depth)
{
    if ((*depth = atoi(arg)) >= 0) {
        return NULL;
    }

    return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                       ": Invalid argument '", arg, "'",
                       NULL);
}

const char *ssl_cmd_SSLVerifyDepth(cmd_parms *cmd, void *ctx,
                                   const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    int depth;
    const char *err;

    if ((err = ssl_cmd_verify_depth_parse(cmd, arg, &depth))) {
        return err;
    }

    if (cmd->path) {
        dc->nVerifyDepth = depth;
    }
    else {
        sc->nVerifyDepth = depth;
    }

    return NULL;
}

#define MODSSL_NO_SHARED_MEMORY_ERROR \
    "SSLSessionCache: shared memory cache not useable on this platform"

const char *ssl_cmd_SSLSessionCache(cmd_parms *cmd, void *ctx,
                                    const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err, *colon;
    char *cp, *cp2;
    int arglen = strlen(arg);

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (ssl_config_global_isfixed(mc)) {
        return NULL;
    }

    if (strcEQ(arg, "none")) {
        mc->nSessionCacheMode      = SSL_SCMODE_NONE;
        mc->szSessionCacheDataFile = NULL;
    }
    else if ((arglen > 4) && strcEQn(arg, "dbm:", 4)) {
        mc->nSessionCacheMode      = SSL_SCMODE_DBM;
        mc->szSessionCacheDataFile = ap_server_root_relative(mc->pPool, arg+4);
        if (!mc->szSessionCacheDataFile) {
            return apr_psprintf(cmd->pool,
                                "SSLSessionCache: Invalid cache file path %s",
                                arg+4);
        }
    }
    else if ((arglen > 6) && strcEQn(arg, "shmht:", 6)) {
#if !APR_HAS_SHARED_MEMORY
        return MODSSL_NO_SHARED_MEMORY_ERROR;
#endif
        mc->nSessionCacheMode = SSL_SCMODE_SHMHT;
        colon = ap_strchr_c(arg, ':');
        mc->szSessionCacheDataFile =
            ap_server_root_relative(mc->pPool, colon+1);
        if (!mc->szSessionCacheDataFile) {
            return apr_psprintf(cmd->pool,
                                "SSLSessionCache: Invalid cache file path %s",
                                colon+1);
        }
        mc->tSessionCacheDataTable = NULL;
        mc->nSessionCacheDataSize  = 1024*512; /* 512KB */

        if ((cp = strchr(mc->szSessionCacheDataFile, '('))) {
            *cp++ = NUL;

            if (!(cp2 = strchr(cp, ')'))) {
                return "SSLSessionCache: Invalid argument: "
                       "no closing parenthesis";
            }

            *cp2 = NUL;

            mc->nSessionCacheDataSize = atoi(cp);

            if (mc->nSessionCacheDataSize <= 8192) {
                return "SSLSessionCache: Invalid argument: "
                       "size has to be >= 8192 bytes";
            }

            if (mc->nSessionCacheDataSize >= APR_SHM_MAXSIZE) {
                return apr_psprintf(cmd->pool,
                                    "SSLSessionCache: Invalid argument: "
                                    "size has to be < %d bytes on this "
                                    "platform", APR_SHM_MAXSIZE);
            }
        }
    }
    else if (((arglen > 4) && strcEQn(arg, "shm:", 4)) ||
             ((arglen > 6) && strcEQn(arg, "shmcb:", 6))) {
#if !APR_HAS_SHARED_MEMORY
        return MODSSL_NO_SHARED_MEMORY_ERROR;
#endif
        mc->nSessionCacheMode      = SSL_SCMODE_SHMCB;
        colon = ap_strchr_c(arg, ':');
        mc->szSessionCacheDataFile =
            ap_server_root_relative(mc->pPool, colon+1);
        if (!mc->szSessionCacheDataFile) {
            return apr_psprintf(cmd->pool,
                                "SSLSessionCache: Invalid cache file path %s",
                                colon+1);
        }
        mc->tSessionCacheDataTable = NULL;
        mc->nSessionCacheDataSize  = 1024*512; /* 512KB */

        if ((cp = strchr(mc->szSessionCacheDataFile, '('))) {
            *cp++ = NUL;

            if (!(cp2 = strchr(cp, ')'))) {
                return "SSLSessionCache: Invalid argument: "
                       "no closing parenthesis";
            }

            *cp2 = NUL;

            mc->nSessionCacheDataSize = atoi(cp);

            if (mc->nSessionCacheDataSize <= 8192) {
                return "SSLSessionCache: Invalid argument: "
                       "size has to be >= 8192 bytes";

            }

            if (mc->nSessionCacheDataSize >= APR_SHM_MAXSIZE) {
                return apr_psprintf(cmd->pool,
                                    "SSLSessionCache: Invalid argument: "
                                    "size has to be < %d bytes on this "
                                    "platform", APR_SHM_MAXSIZE);

            }
        }
	else {
            return "SSLSessionCache: Invalid argument";
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLSessionCacheTimeout(cmd_parms *cmd, void *ctx,
                                           const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->nSessionCacheTimeout = atoi(arg);

    if (sc->nSessionCacheTimeout < 0) {
        return "SSLSessionCacheTimeout: Invalid argument";
    }

    return NULL;
}

#define SSL_FLAGS_LOG_CONTEXT \
    (NOT_IN_LIMIT|NOT_IN_DIRECTORY|NOT_IN_LOCATION|NOT_IN_FILES)

const char *ssl_cmd_SSLLog(cmd_parms *cmd, void *ctx,
                           const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd, SSL_FLAGS_LOG_CONTEXT))) {
        return err;
    }

    sc->szLogFile = arg;

    return NULL;
}

const char *ssl_cmd_SSLLogLevel(cmd_parms *cmd, void *ctx,
                                const char *level)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd, SSL_FLAGS_LOG_CONTEXT))) {
        return err;
    }

    if (strcEQ(level, "none")) {
        sc->nLogLevel = SSL_LOG_NONE;
    }
    else if (strcEQ(level, "error")) {
        sc->nLogLevel = SSL_LOG_ERROR;
    }
    else if (strcEQ(level, "warn")) {
        sc->nLogLevel = SSL_LOG_WARN;
    }
    else if (strcEQ(level, "info")) {
        sc->nLogLevel = SSL_LOG_INFO;
    }
    else if (strcEQ(level, "trace")) {
        sc->nLogLevel = SSL_LOG_TRACE;
    }
    else if (strcEQ(level, "debug")) {
        sc->nLogLevel = SSL_LOG_DEBUG;
    }
    else {
        return "SSLLogLevel: Invalid argument";
    }

    return NULL;
}

const char *ssl_cmd_SSLOptions(cmd_parms *cmd, void *ctx,
                               const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;
    ssl_opt_t opt;
    int first = TRUE;
    char action, *w;

    while (*arg) {
        w = ap_getword_conf(cmd->pool, &arg);
        action = NUL;

        if ((*w == '+') || (*w == '-')) {
            action = *(w++);
        }
        else if (first) {
            dc->nOptions = SSL_OPT_NONE;
            first = FALSE;
        }

        if (strcEQ(w, "StdEnvVars")) {
            opt = SSL_OPT_STDENVVARS;
        }
        else if (strcEQ(w, "CompatEnvVars")) {
            opt = SSL_OPT_COMPATENVVARS;
        }
        else if (strcEQ(w, "ExportCertData")) {
            opt = SSL_OPT_EXPORTCERTDATA;
        }
        else if (strcEQ(w, "FakeBasicAuth")) {
            opt = SSL_OPT_FAKEBASICAUTH;
        }
        else if (strcEQ(w, "StrictRequire")) {
            opt = SSL_OPT_STRICTREQUIRE;
        }
        else if (strcEQ(w, "OptRenegotiate")) {
            opt = SSL_OPT_OPTRENEGOTIATE;
        }
        else {
            return apr_pstrcat(cmd->pool,
                               "SSLOptions: Illegal option '", w, "'",
                               NULL);
        }

        if (action == '-') {
            dc->nOptionsAdd &= ~opt;
            dc->nOptionsDel |=  opt;
            dc->nOptions    &= ~opt;
        }
        else if (action == '+') {
            dc->nOptionsAdd |=  opt;
            dc->nOptionsDel &= ~opt;
            dc->nOptions    |=  opt;
        }
        else {
            dc->nOptions    = opt;
            dc->nOptionsAdd = opt;
            dc->nOptionsDel = SSL_OPT_NONE;
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLRequireSSL(cmd_parms *cmd, void *ctx)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;

    dc->bSSLRequired = TRUE;

    return NULL;
}

const char *ssl_cmd_SSLRequire(cmd_parms *cmd, void *ctx,
                               const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)ctx;
    ssl_expr *expr;
    ssl_require_t *require;

    if (!(expr = ssl_expr_comp(cmd->pool, (char *)arg))) {
        return apr_pstrcat(cmd->pool, "SSLRequire: ",
                           ssl_expr_get_error(), NULL);
    }

    require = apr_array_push(dc->aRequirement);
    require->cpExpr = apr_pstrdup(cmd->pool, arg);
    require->mpExpr = expr;

    return NULL;
}

static const char *ssl_cmd_protocol_parse(cmd_parms *parms,
                                          const char *arg,
                                          ssl_proto_t *options)
{
    ssl_proto_t thisopt;

    *options = SSL_PROTOCOL_NONE;

    while (*arg) {
        char *w = ap_getword_conf(parms->temp_pool, &arg);
        char action = '\0';

        if ((*w == '+') || (*w == '-')) {
            action = *(w++);
        }

        if (strcEQ(w, "SSLv2")) {
            thisopt = SSL_PROTOCOL_SSLV2;
        }
        else if (strcEQ(w, "SSLv3")) {
            thisopt = SSL_PROTOCOL_SSLV3;
        }
        else if (strcEQ(w, "TLSv1")) {
            thisopt = SSL_PROTOCOL_TLSV1;
        }
        else if (strcEQ(w, "all")) {
            thisopt = SSL_PROTOCOL_ALL;
        }
        else {
            return apr_pstrcat(parms->temp_pool,
                               parms->cmd->name,
                               ": Illegal protocol '",
                               w, "'", NULL);
        }

        if (action == '-') {
            *options &= ~thisopt;
        }
        else if (action == '+') {
            *options |= thisopt;
        }
        else {
            *options = thisopt;
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLProtocol(cmd_parms *cmd, void *ctx,
                                const char *opt)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    return ssl_cmd_protocol_parse(cmd, opt, &sc->nProtocol);
}

#ifdef SSL_EXPERIMENTAL_PROXY

const char *ssl_cmd_SSLProxyProtocol(cmd_parms *cmd, char *struct_ptr,
                                     const char *opt)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    return ssl_cmd_protocol_parse(cmd, opt, &sc->nProxyProtocol);
}

const char *ssl_cmd_SSLProxyCipherSuite(cmd_parms *cmd, char *struct_ptr,
                                        char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->szProxyCipherSuite = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyVerify(cmd_parms *cmd, char *struct_ptr,
                                   int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->bProxyVerify = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyVerifyDepth(cmd_parms *cmd, char *struct_ptr,
                                        char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    int depth;
    const char *err;

    if ((err = ssl_cmd_verify_depth_parse(cmd, arg, &depth))) {
        return err;
    }

    sc->nProxyVerifyDepth = depth;

    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificateFile(cmd_parms *cmd,
                                              char *struct_ptr,
                                              char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->szProxyCACertificateFile = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificatePath(cmd_parms *cmd,
                                              char *struct_ptr,
                                              char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->szProxyCACertificatePath = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificateFile(cmd_parms *cmd,
                                                   char *struct_ptr,
                                                   char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->szProxyClientCertificateFile = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificatePath(cmd_parms *cmd,
                                                   char *struct_ptr,
                                                   char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    sc->szProxyClientCertificatePath = arg;

    return NULL;
}

#endif /* SSL_EXPERIMENTAL_PROXY */

