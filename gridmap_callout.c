/* $Id: gridmap_callout.c 802 2014-04-21 14:51:46Z jalt $ */
/*
 * University of Illinois/NCSA Open Source License
 *
 * Copyright © 2014 NCSA.  All rights reserved.
 *
 * Developed by:
 *
 * Storage Enabling Technologies (SET)
 *
 * Nation Center for Supercomputing Applications (NCSA)
 *
 * http://www.ncsa.illinois.edu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the .Software.),
 * to deal with the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 *    + Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimers.
 *
 *    + Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimers in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    + Neither the names of SET, NCSA
 *      nor the names of its contributors may be used to endorse or promote
 *      products derived from this Software without specific prior written
 *      permission.
 *
 * THE SOFTWARE IS PROVIDED .AS IS., WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS WITH THE SOFTWARE.
 */

/*
 * System includes.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>

/*
 * LDAP includes.
 */
#include <ldap.h>

/*
 * PAM includes.
 */
#include <security/pam_appl.h>

/*
 * Globus includes.
 */
#include <globus_error_gssapi.h>
#include <globus_common.h>
#include <globus_error.h>
#include <gssapi.h>

#define PAM_SERVICE_NAME "gridftp"
#define FILTER_FORMAT "(gridmap=%s)"

#define GRIDMAP_LOOKUP_OVERRIDE "/etc/grid-security/gridmap_override"

globus_object_t *
globus_error_construct_error(
    globus_module_descriptor_t *        base_source,
    globus_object_t *                   base_cause,
    int                                 type,
    const char *                        source_file,
    const char *                        source_func,
    int                                 source_line,
    const char *                        short_desc_format,
    ...);

#define MAKE_ERROR(__FORMAT, ...) \
	globus_error_put(           \
		globus_error_construct_error(NULL,     /* base_source       */ \
		                             NULL,     /* base_cause        */ \
		                             0,        /* type              */ \
		                             __FILE__, /* source_file       */ \
		                             __func__, /* source_func       */ \
		                             __LINE__, /* source_line       */ \
		                             __FORMAT, /* short_desc_format */ \
		                             ##__VA_ARGS__));

#define MAKE_GSS_ERROR(__ERRSTR, __MAJOR_STATUS, __MINOR_STATUS) \
	globus_error_put(                               \
		globus_error_wrap_gssapi_error(             \
			NULL,           /* base_source       */ \
			__MAJOR_STATUS, /* major status      */ \
			__MINOR_STATUS, /* minor status      */ \
			0,              /* type              */ \
			__FILE__,       /* file              */ \
			__func__,       /* function          */ \
			__LINE__,       /* line              */ \
			"%s",           /* short_desc_format */ \
			__ERRSTR))


static int
DnEscapeLength(char * DN)
{
	int index  = 0;
	int length = 0;

	for (index = 0; index < strlen(DN); index++)
	{
		if (DN[index] == '(' || DN[index] == ')' || DN[index] == '*')
			length++;
	}

	return length;
}

static void
EscapeFilter(char * Filter)
{
	int i = 0;

	/* Skip the inner and outter parenthesis */
	for (i = 1; i < (strlen(Filter) - 1); i++)
	{
		if (Filter[i] == '(' || Filter[i] == ')' || Filter[i] == '*')
		{
			/* Add one to the length for '\0' */
			memmove(&Filter[i+1], &Filter[i], strlen(Filter)-i+1);
			Filter[i++] = '\\';
		}
	}
}

static globus_result_t
LdapLookUpUser(char * GsiDn, 
               char * DesiredUserName,
               char * UserName,
               int    UserNameLength)
{
	int                retval        = 0;
	int                count         = 0;
	int                escape_length = 0;
	int                version       = 3;
	char            *  filter        = NULL;
	char            ** values        = NULL;
	char            *  attrs[]       = {"uid", NULL};
	LDAP            *  ldap          = NULL;
	LDAPMessage     *  ldap_result   = NULL;
	LDAPMessage     *  ldap_entry    = NULL;
	globus_result_t    result        = GLOBUS_SUCCESS;

	/* Determine how many escape characters we'll need. */
	escape_length = DnEscapeLength(GsiDn);

	/* Allocate the filter. */
	filter = (char *) malloc(strlen(GsiDn) +
	                         strlen(FILTER_FORMAT) +
	                         escape_length + 1);
	if (filter == NULL)
	{
		result = MAKE_ERROR("malloc(): %s", strerror(errno));
		goto cleanup;
	}

	/* Construct the filter. */
	sprintf(filter, FILTER_FORMAT, GsiDn);

	/* Escape the filter. */
	EscapeFilter(filter);

	/* Initialize the connection to the ldap server. */
	retval = ldap_initialize(&ldap, NULL);
	if (retval != LDAP_SUCCESS)
	{
		result = MAKE_ERROR("ldap_initialize(): %s", ldap_err2string(retval));
		goto cleanup;
	}

	/* Set this to protocol 3. */
	retval = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (retval != LDAP_OPT_SUCCESS)
	{
		result = MAKE_ERROR("ldap_set_option(): %s", ldap_err2string(retval));
		goto cleanup;
	}

	/* Perform an anonymous bind. */
	retval = ldap_simple_bind_s(ldap, NULL, NULL);
	if (retval != LDAP_SUCCESS)
	{
		result = MAKE_ERROR("ldap_simple_bind_s(): %s", ldap_err2string(retval));
		goto cleanup;
	}

	/* Now search for our entry. */
	retval = ldap_search_ext_s(ldap,
	                           NULL,
	                           LDAP_SCOPE_CHILDREN,
	                           filter,
	                           attrs,
	                           0,    /* Attrs only  */
	                           NULL, /* serverctrls */
	                           NULL, /* clientctrls */
	                           NULL, /* timeout     */
	                           -1,   /* sizelimit   */
	                           &ldap_result);

	if (retval != LDAP_SUCCESS)
	{
		result = MAKE_ERROR("ldap_search_ext_s(): %s", ldap_err2string(retval));
		goto cleanup;
	}

	/* Check how many matches we got. */
	count = ldap_count_entries(ldap, ldap_result);
	if (count == -1)
	{
		result = MAKE_ERROR("ldap_count_entries(): %s", ldap_err2string(retval));
		goto cleanup;
	}

	/* If we received zero matches... */
	if (count == 0)
	{
		result = MAKE_ERROR("No match for %s", GsiDn);
		goto cleanup;
	}

	/* Get the first (only) entry. */
	ldap_entry = ldap_first_entry(ldap, ldap_result);
	if (ldap_entry == NULL)
	{
		/* Construct the ldap error message. */
		result = MAKE_ERROR("Error retrieving ldap entry: %s", ldap_err2string(ldap_get_errno(ldap)));
		goto cleanup;
	}

	/* Get the value(s) for this attribute. */
	values = ldap_get_values(ldap, ldap_entry, attrs[0]);
	if (values == NULL)
	{
		/* Construct the ldap error message. */
		result = MAKE_ERROR("Error retrieving ldap values: %s", ldap_err2string(ldap_get_errno(ldap)));
		goto cleanup;
	}

	/*
	 * If they don't care which account we map to or this is the map they
	 * want to map to...
	 */
	if (DesiredUserName == NULL || strcmp(DesiredUserName, values[0]) == 0)
	{
		/* Make sure we won't overflow this buffer. */
		if (strlen(values[0]) > (UserNameLength + 1))
		{
			result = MAKE_ERROR("Username is too long: %s", values[0]);
			goto cleanup;
		}

		/* Copy out the user name. */
		strcpy(UserName, values[0]);

		/* Free the returned values. */
		ldap_value_free(values);

		/* Break out, we are done. */
		goto cleanup;
	}

	/* Free the returned values. */
	ldap_value_free(values);

	/*
	 * At this point, there must be a desired username, else the previous
	 * value would have matched.
	 */

	while (--count > 0)
	{
		/* Get the next entry. */
		ldap_entry = ldap_next_entry(ldap, ldap_entry);
		if (ldap_entry == NULL)
		{
			/* Construct the ldap error message. */
			result = MAKE_ERROR("Error retrieving ldap entry: %s", ldap_err2string(ldap_get_errno(ldap)));
			goto cleanup;
		}

		/*
		 * If they don't care which account we map to or this is the map they
		 * want to map to...
		 */
		if (DesiredUserName == NULL || strcmp(DesiredUserName, values[0]) == 0)
		{
			/* Make sure we won't overflow this buffer. */
			if (strlen(values[0]) > (UserNameLength + 1))
			{
				result = MAKE_ERROR("Username is too long: %s", values[0]);
				goto cleanup;
			}

			/* Copy out the user name. */
			strcpy(UserName, values[0]);

			/* Free the returned values. */
			ldap_value_free(values);

			/* Break out, we are done. */
			goto cleanup;
		}

		/* Free the returned values. */
		ldap_value_free(values);
	}

	/* Check this assumption. */
	globus_assert(DesiredUserName != NULL);

	/*
	 * If we get here, we do not have a match.
	 */
	result = MAKE_ERROR("No mapping for DN (%s) to user (%s).", GsiDn, DesiredUserName);

cleanup:
	if (filter != NULL)
		free(filter);

	if (ldap != NULL)
	{
		/* Do we really care about an unbind error? */
		ldap_unbind_ext(ldap, NULL, NULL);
	}

	return result;
}

/*
 * Caller must free Dn.
 */
static globus_result_t
GetContextDn(gss_ctx_id_t    Context,
             char         ** Dn)
{
	globus_result_t result       = GLOBUS_SUCCESS;
	int             initiator    = 0;
	OM_uint32       major_status = 0;
	OM_uint32       minor_status = 0;
	gss_name_t      peer;
	gss_buffer_desc peer_name_buffer;

	/* Initialize the returned DN. */
	*Dn = NULL;

	/* Find out if the peer is the initiator. */
	major_status = gss_inquire_context(&minor_status,
	                                   Context,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   &initiator,
	                                   GLOBUS_NULL);

	if(GSS_ERROR(major_status))
	{
		result = MAKE_GSS_ERROR("gss_inquire_context() failed", major_status, minor_status);
		return result;
	}

	/* Get the gss name of the peer. */
	major_status = gss_inquire_context(&minor_status,
	                                   Context,
	                                   initiator ? GLOBUS_NULL : &peer,
	                                   initiator ? &peer : GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL,
	                                   GLOBUS_NULL);

	if(GSS_ERROR(major_status))
	{
		result = MAKE_GSS_ERROR("gss_inquire_context() failed", major_status, minor_status);
		return result;
	}

	/* Get the peer's display name (DN). */
	major_status = gss_display_name(&minor_status,
	                                peer,
	                                &peer_name_buffer,
	                                GLOBUS_NULL);

	if(GSS_ERROR(major_status))
	{
		result = MAKE_GSS_ERROR("gss_display_name() failed", major_status, minor_status);
		gss_release_name(&minor_status, &peer);
		return result;
	}

	/* Copy out the peer name (Dn). */
	*Dn = globus_libc_strdup(peer_name_buffer.value);

	/* Release the peer name buffer. */
	gss_release_buffer(&minor_status, &peer_name_buffer);

	/* Release the peer name. */
	gss_release_name(&minor_status, &peer);

	return result;
}

/*
 * Conversion function which is called from pam_nologin.so when 
 * /etc/nologin exists.
 */
static int
ConvFunc(int                         MsgCount,
         const struct pam_message ** Msg,
         struct pam_response **      Response,
         void                     *  AppData)
{
    return 0;
}

/*
 * Caller must free PeerName.
 */
static globus_result_t
GetPeerName(char ** PeerName)
{
	int                retval  = 0;
	socklen_t          socklen = sizeof(struct sockaddr_in);
	struct sockaddr_in sockaddr;

	/* Get the peer to stdin. */
	retval = getpeername(fileno(stdin), (struct sockaddr *)&sockaddr, &socklen);
	if (retval != 0)
		return MAKE_ERROR("getpeername(): %s", strerror(errno));

	/* Get the peername (static location). */
	*PeerName = inet_ntoa(sockaddr.sin_addr);

	/* Copy the peer name out. */
	if (*PeerName != NULL)
		*PeerName = globus_libc_strdup(*PeerName);

	return GLOBUS_SUCCESS;
}

static globus_result_t
CheckPam(char * UserName)
{
	int               retval = 0;
	char            * peer   = NULL;
	pam_handle_t    * pamh   = NULL;
	globus_result_t   result = GLOBUS_SUCCESS;
	struct pam_conv   conv   = {ConvFunc, 0};

	retval = pam_start(PAM_SERVICE_NAME, UserName, &conv, &pamh);
	if (retval != PAM_SUCCESS)
	{
		switch (retval)
		{
		case PAM_ABORT:
			result = MAKE_ERROR("pam_start(): %s", "General failure");
			break;

		case PAM_BUF_ERR:
			result = MAKE_ERROR("pam_start(): %s", "Memory buffer error");
			break;

		case PAM_SYSTEM_ERR:
			result = MAKE_ERROR("pam_start(): %s", "System error");
			break;
		}
		goto cleanup;
	}

	/* Get the address of the remote host. */
	result = GetPeerName(&peer);
	if (result != GLOBUS_SUCCESS)
		goto cleanup;

	/* Now set it in the pam handle. */
	retval = pam_set_item(pamh, PAM_RHOST, peer);
	if (retval != PAM_SUCCESS)
	{
		switch (retval)
		{
		case PAM_ABORT:
			result = MAKE_ERROR("pam_set_item(PAM_RHOST): %s", "General failure");
			break;

		case PAM_BUF_ERR:
			result = MAKE_ERROR("pam_set_item(PAM_RHOST): %s", "Memory buffer error");
			break;

		case PAM_SYSTEM_ERR:
			result = MAKE_ERROR("pam_set_item(PAM_RHOST): %s", "System error");
			break;
		}
		goto cleanup;
	}

	retval = pam_acct_mgmt(pamh, 0);
	if (retval != PAM_SUCCESS)
	{
		result = MAKE_ERROR("pam_acct_mgmt(): %s", pam_strerror(pamh, retval));
		goto cleanup;
	}

cleanup:
	pam_end(pamh, retval);

	return result;
}

static int
_CountQuotedLength(char * CPtr)
{
	int index    = 0;
	int count    = 0;
	int in_quote = 0;

	/* Count the number of characters that need to be compared. */
	for (index = 0; (!isspace(CPtr[index]) || in_quote) && CPtr[index] != '\0'; index++)
	{
		if (CPtr[index] == '"')
		{
			in_quote = !in_quote;
			continue;
		}
		count++;
	}

	return count;
}

/*
 * If the file /etc/grid-security/gridmap_override exists, lookup
 * this user and if there is a match, use the translated username
 * instead. This is an administrative override for purposes of 
 * debugging and user assistance.
 *
 * File Format:
 *  - Blank lines are ignored
 *  - Lines with '#' as the first non space character are comments
 *    and are ignored
 *  - Multiple white spaces are treated as a single white space
 *  - Lines must be < 1024 characters
 *  - All other lines are formatted as : username1 username2
 *    where username1 is actual username of authenticated user and
 *    username2 is the name the user needs to masquerade as.
 */

#define OVERRIDE_BUFFER_LENGTH 1024
static globus_result_t
_ApplyGridMapOverrides(char         * Username1,
                       char         * Username2,
                       unsigned int   BufferLength)
{
	int             count       = 0;
	int             retval      = 0;
	int             in_quote    = 0;
	FILE          * override_fp = NULL;
	char          * cptr        = NULL;
	char            buf[OVERRIDE_BUFFER_LENGTH];
	globus_result_t result = GLOBUS_SUCCESS;

	retval = access(GRIDMAP_LOOKUP_OVERRIDE, R_OK);
	if (retval)
		return MAKE_ERROR("access(/etc/grid-security/gridmap_override): %s", strerror(errno));

	override_fp = fopen(GRIDMAP_LOOKUP_OVERRIDE, "r");
	if (!override_fp)
		return MAKE_ERROR("open(/etc/grid-security/gridmap_override): %s", strerror(errno));

	while ((cptr = fgets(buf, sizeof(buf), override_fp)))
	{
		/* Ignore leading space */
		while (isspace(*cptr)) cptr++;

		/* Ignore comments. */
		if (*cptr == '#')
			continue;

		/* Count the number of characters that need to be compared. */
		count = _CountQuotedLength(cptr);

		/* Skip any leading quote. */
		if (count && *cptr == '"')
			cptr++;

		/* If we have a match... */
		if (count == strlen(Username1) && strncmp(Username1, cptr, count) == 0)
		{
			/* Move the pointer to the end of the name. */
			cptr += count;

			/* Skip any trailing quote. */
			if (*cptr == '"')
				cptr++;

			/* Ignore space */
			while (isspace(*cptr)) cptr++;

			/* Count the number of characters that need to be compared. */
			count = _CountQuotedLength(cptr);

			if (count > (BufferLength - 1))
			{
				result = MAKE_ERROR("/etc/grid-security/gridmap_override: translated name is too long: %s", cptr);
				goto cleanup;
			}

			/* Skip any leading quote. */
			if (count && *cptr == '"')
				cptr++;

			/* Copy the translation out. */
			strncpy(Username2, cptr, count);

			/* Null terminated. */
			Username2[count] = '\0';

			/* Done. */
			break;
		}
	}

cleanup:
	if (override_fp)
		fclose(override_fp);

	return result;
}

#define MAX_DN_LENGTH 128
static globus_result_t
_LdapLookupWithPam(va_list Ap, int ShouldCheckPam)
{
	globus_result_t result           = GLOBUS_SUCCESS;
	char *          users_dn         = NULL;
	char            translated_dn[MAX_DN_LENGTH];
	char *          service          = NULL;
	char *          desired_identity = NULL;
	char *          identity_buffer  = NULL;
	unsigned int    buffer_length    = 0;
	gss_ctx_id_t    context;

	/*
	 * These are the values based to use by the server upon which we must
	 * make our decision.
	 *
	 * context:          GSSAPI security from gss_accept_sec_context()
	 * service:          name of this service (currently 'file' ???)
	 * desired_identity: user name the user is requesting
	 * identity_buffer:  buffer we will store the new identity in
	 * buffer_length:    length of data in identity_buffer
	 */
	context          = va_arg(Ap, gss_ctx_id_t);
	service          = va_arg(Ap, char *);
	desired_identity = va_arg(Ap, char *);
	identity_buffer  = va_arg(Ap, char *);
	buffer_length    = va_arg(Ap, unsigned int);

	/* Get the user's GSI DN from the context. */
	result = GetContextDn(context, &users_dn);
	if (result != GLOBUS_SUCCESS)
		goto cleanup;

	memset(identity_buffer, 0, buffer_length);

	/* Try to translate the given DN. */
	_ApplyGridMapOverrides(users_dn, identity_buffer, buffer_length);

	/* If we still have a DN... */
	if (identity_buffer[0] == '\0')
	{
		/* Lookup the user in LDAP. */
		result = LdapLookUpUser(users_dn,
		                        desired_identity,
		                        identity_buffer,
		                        buffer_length);
		if (result != GLOBUS_SUCCESS)
			goto cleanup;
	}

	/*
	 * Since this is an administrative capability, errors will be
	 * ignored in order to avoid impacting real users in cases of
	 * erroneous file formats, etc.
	 */
	_ApplyGridMapOverrides(identity_buffer, identity_buffer, buffer_length);

	/* Now check with PAM. */
	if (ShouldCheckPam)
	{
		result = CheckPam(identity_buffer);
		if (result != GLOBUS_SUCCESS)
			goto cleanup;
	}

cleanup:
	if (users_dn)
		globus_free(users_dn);

	return result;
}

/**
 * Gridmap Authorization Callout Function
 *
 * This function provides a gridmap lookup in callout form.
 *
 * @param ap
 *        This function, like all functions using the Globus Callout API, is
 *        passed parameter though the variable argument list facility. The
 *        actual arguments that are passed are:
 *
 *        - The GSS Security context established during service
 *          invocation. This parameter is of type gss_ctx_id_t.
 *        - The name of the service being invoced. This parameter should be
 *          passed as a NUL terminated string. If no service string is
 *          available a value of NULL should be passed in its stead. This
 *          parameter is of type char *
 *        - A NUL terminated string indicating the desired local identity. If
 *          no identity is desired NULL may be passed. In this case the first
 *          local identity that is found will be returned. This parameter is of
 *          type char *.
 *        - A pointer to a buffer. This buffer will contain the mapped (local)
 *          identity (NUL terminated string) upon successful return. This
 *          parameter is of type char *.
 *        - The length of the above mentioned buffer. This parameter is of type
 *          unsigned int.
 *
 * @return
 *        GLOBUS_SUCCESS upon success
 *        A globus result structure upon failure (needs to be defined better)
 */
/*
 * This function is configured for use by the GSI callouts in GridFTP
 * through the gsi-authz.conf configuration file. This entry point will
 * lookup the user DN in LDAP; for PAM restrictions are NOT applied.
 */
globus_result_t
ldap_lookup(va_list Ap)
{
	return _LdapLookupWithPam(Ap, 0);
}

/*
 * This function is configured for use by the GSI callouts in GridFTP
 * through the gsi-authz.conf configuration file. This entry point will
 * lookup the user DN in LDAP and check for PAM restrictions.
 */
globus_result_t
ldap_lookup_with_pam(va_list Ap)
{
	return _LdapLookupWithPam(Ap, 1);
}

/*
 * This function is used by striped GridFTP servers (specifically the data nodes)
 * to translate GSI DNs into usernames. In order for this to override the
 * data node's internal GSI functions, it must be LD_PRELOAD'ed into the
 * GridFTP (data) process.
 *
 * This function serves to translate the DN into the default username.
 *
 * Return 0 on success, 1 on error. 
 */
int
globus_gss_assist_gridmap(char *  GsiDN,
                          char ** UserIdentity)
{
	char            username[16];
	globus_result_t result = GLOBUS_SUCCESS;

	result = LdapLookUpUser(GsiDN, NULL, username, sizeof(username));

	if (result == GLOBUS_SUCCESS)
		*UserIdentity = strdup(username);

	return (result != GLOBUS_SUCCESS);
}

/*
 * This function is used by striped GridFTP servers (specifically the data nodes)
 * to translate GSI DNs into usernames. In order for this to override the
 * data node's internal GSI functions, it must be LD_PRELOAD'ed into the
 * GridFTP (data) process.
 *
 * This function serves to translate the DN and see if DesiredUserName is
 * configured in LDAP to use this DN.
 *
 * Return 0 on success, 1 on error. 
 */
int
globus_gss_assist_userok(char * GsiDN,
                         char * DesiredUserName)
{
	char            username[16];
	globus_result_t result = GLOBUS_SUCCESS;

	result = LdapLookUpUser(GsiDN, DesiredUserName, username, sizeof(username));
	return (result != GLOBUS_SUCCESS);
}

