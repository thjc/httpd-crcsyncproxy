/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

/*
** Declarations for the filesystem repository implementation
*/

#ifndef _DAV_FS_REPOS_H_
#define _DAV_FS_REPOS_H_

/* the subdirectory to hold all DAV-related information for a directory */
#define DAV_FS_STATE_DIR		".DAV"
#define DAV_FS_STATE_FILE_FOR_DIR	".state_for_dir"
#define DAV_FS_LOCK_NULL_FILE	        ".locknull"


/* ensure that our state subdirectory is present */
void dav_fs_ensure_state_dir(ap_pool_t *p, const char *dirname);

/* return the storage pool associated with a resource */
ap_pool_t *dav_fs_pool(const dav_resource *resource);

/* return the full pathname for a resource */
const char *dav_fs_pathname(const dav_resource *resource);

/* return the directory and filename for a resource */
void dav_fs_dir_file_name(const dav_resource *resource,
			  const char **dirpath,
			  const char **fname);

/* return the list of locknull members in this resource's directory */
dav_error * dav_fs_get_locknull_members(const dav_resource *resource,
                                        dav_buffer *pbuf);


/* DBM functions used by the repository and locking providers */
extern const dav_hooks_db dav_hooks_db_dbm;

dav_error * dav_dbm_open_direct(ap_pool_t *p, const char *pathname, int ro,
				dav_db **pdb);
void dav_dbm_get_statefiles(ap_pool_t *p, const char *fname,
			    const char **state1, const char **state2);


#endif /* _DAV_FS_REPOS_H_ */
