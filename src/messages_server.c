/**
 * \file messages_server.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 - server NETCONF messages functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libyang/libyang.h>

#include "session_server.h"
#include "libnetconf.h"

extern struct nc_server_opts server_opts;

API struct nc_server_reply *
nc_server_reply_ok(void)
{
    struct nc_server_reply *ret;

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    ret->type = NC_RPL_OK;
    return ret;
}

API struct nc_server_reply *
nc_server_reply_data(struct lyd_node *data, NC_PARAMTYPE paramtype)
{
    struct nc_server_reply_data *ret;

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    ret->type = NC_RPL_DATA;
    if (data && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        ret->data = lyd_dup(data, 1);
    } else {
        ret->data = data;
    }
    if (paramtype != NC_PARAMTYPE_CONST) {
        ret->free = 1;
    } else {
        ret->free = 0;
    }
    return (struct nc_server_reply *)ret;
}

API struct nc_server_reply *
nc_server_reply_err(struct nc_server_error *err)
{
    struct nc_server_reply_error *ret;

    if (!err) {
        ERRARG;
        return NULL;
    }

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    ret->type = NC_RPL_ERROR;
    ret->err = malloc(sizeof *ret->err);
    if (!ret->err) {
        ERRMEM;
        free(ret);
        return NULL;
    }
    ret->err[0] = err;
    ret->count = 1;
    return (struct nc_server_reply *)ret;
}

API int
nc_server_reply_add_err(struct nc_server_reply *reply, struct nc_server_error *err)
{
    struct nc_server_reply_error *err_rpl;

    if (!reply || (reply->type != NC_RPL_ERROR) || !err) {
        ERRARG;
        return -1;
    }

    err_rpl = (struct nc_server_reply_error *)reply;
    ++err_rpl->count;
    err_rpl->err = nc_realloc(err_rpl->err, err_rpl->count * sizeof *err_rpl->err);
    if (!err_rpl->err) {
        ERRMEM;
        return -1;
    }
    err_rpl->err[err_rpl->count - 1] = err;
    return 0;
}

API struct nc_server_error *
nc_err(NC_ERR tag, ...)
{
    va_list ap;
    struct nc_server_error *ret;
    NC_ERR_TYPE type;
    const char *arg1, *arg2;
    uint32_t sid;

    if (!tag) {
        ERRARG;
        return NULL;
    }

    ret = calloc(1, sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    va_start(ap, tag);

    switch (tag) {
    case NC_ERR_IN_USE:
    case NC_ERR_INVALID_VALUE:
    case NC_ERR_ACCESS_DENIED:
    case NC_ERR_ROLLBACK_FAILED:
    case NC_ERR_OP_NOT_SUPPORTED:
        type = va_arg(ap, NC_ERR_TYPE);
        if ((type != NC_ERR_TYPE_PROT) && (type == NC_ERR_TYPE_APP)) {
            goto fail;
        }
        break;

    case NC_ERR_TOO_BIG:
    case NC_ERR_RES_DENIED:
        type = va_arg(ap, NC_ERR_TYPE);
        /* nothing to check */
        break;

    case NC_ERR_MISSING_ATTR:
    case NC_ERR_BAD_ATTR:
    case NC_ERR_UNKNOWN_ATTR:
        type = va_arg(ap, NC_ERR_TYPE);
        arg1 = va_arg(ap, const char *);
        arg2 = va_arg(ap, const char *);

        if (type == NC_ERR_TYPE_TRAN) {
            goto fail;
        }
        nc_err_add_bad_attr(ret, arg1);
        nc_err_add_bad_elem(ret, arg2);
        break;

    case NC_ERR_MISSING_ELEM:
    case NC_ERR_BAD_ELEM:
    case NC_ERR_UNKNOWN_ELEM:
        type = va_arg(ap, NC_ERR_TYPE);
        arg1 = va_arg(ap, const char *);

        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            goto fail;
        }
        nc_err_add_bad_elem(ret, arg1);
        break;

    case NC_ERR_UNKNOWN_NS:
        type = va_arg(ap, NC_ERR_TYPE);
        arg1 = va_arg(ap, const char *);
        arg2 = va_arg(ap, const char *);

        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            goto fail;
        }
        nc_err_add_bad_elem(ret, arg1);
        nc_err_add_bad_ns(ret, arg2);
        break;

    case NC_ERR_LOCK_DENIED:
        sid = va_arg(ap, uint32_t);

        type = NC_ERR_TYPE_PROT;
        nc_err_set_sid(ret, sid);
        break;

    case NC_ERR_DATA_EXISTS:
    case NC_ERR_DATA_MISSING:
        type = NC_ERR_TYPE_APP;
        break;

    case NC_ERR_OP_FAILED:
        type = va_arg(ap, NC_ERR_TYPE);

        if (type == NC_ERR_TYPE_TRAN) {
            goto fail;
        }
        break;

    case NC_ERR_MALFORMED_MSG:
        type = NC_ERR_TYPE_RPC;
        break;

    default:
        goto fail;
    }

    switch (tag) {
    case NC_ERR_IN_USE:
        nc_err_set_msg(ret, "The request requires a resource that already is in use.", "en");
        break;
    case NC_ERR_INVALID_VALUE:
        nc_err_set_msg(ret, "The request specifies an unacceptable value for one or more parameters.", "en");
        break;
    case NC_ERR_TOO_BIG:
        nc_err_set_msg(ret, "The request or response (that would be generated) is too large for the implementation to handle.", "en");
        break;
    case NC_ERR_MISSING_ATTR:
        nc_err_set_msg(ret, "An expected attribute is missing.", "en");
        break;
    case NC_ERR_BAD_ATTR:
        nc_err_set_msg(ret, "An attribute value is not correct.", "en");
        break;
    case NC_ERR_UNKNOWN_ATTR:
        nc_err_set_msg(ret, "An unexpected attribute is present.", "en");
        break;
    case NC_ERR_MISSING_ELEM:
        nc_err_set_msg(ret, "An expected element is missing.", "en");
        break;
    case NC_ERR_BAD_ELEM:
        nc_err_set_msg(ret, "An element value is not correct.", "en");
        break;
    case NC_ERR_UNKNOWN_ELEM:
        nc_err_set_msg(ret, "An unexpected element is present.", "en");
        break;
    case NC_ERR_UNKNOWN_NS:
        nc_err_set_msg(ret, "An unexpected namespace is present.", "en");
        break;
    case NC_ERR_ACCESS_DENIED:
        nc_err_set_msg(ret, "Access to the requested protocol operation or data model is denied because authorization failed.", "en");
        break;
    case NC_ERR_LOCK_DENIED:
        nc_err_set_msg(ret, "Access to the requested lock is denied because the lock is currently held by another entity.", "en");
        break;
    case NC_ERR_RES_DENIED:
        nc_err_set_msg(ret, "Request could not be completed because of insufficient resources.", "en");
        break;
    case NC_ERR_ROLLBACK_FAILED:
        nc_err_set_msg(ret, "Request to roll back some configuration change was not completed for some reason.", "en");
        break;
    case NC_ERR_DATA_EXISTS:
        nc_err_set_msg(ret, "Request could not be completed because the relevant data model content already exists.", "en");
        break;
    case NC_ERR_DATA_MISSING:
        nc_err_set_msg(ret, "Request could not be completed because the relevant data model content does not exist.", "en");
        break;
    case NC_ERR_OP_NOT_SUPPORTED:
        nc_err_set_msg(ret, "Request could not be completed because the requested operation is not supported by this implementation.", "en");
        break;
    case NC_ERR_OP_FAILED:
        nc_err_set_msg(ret, "Request could not be completed because the requested operation failed for a non-specific reason.", "en");
        break;
    case NC_ERR_MALFORMED_MSG:
        nc_err_set_msg(ret, "A message could not be handled because it failed to be parsed correctly.", "en");
        break;
    default:
        goto fail;
    }

    va_end(ap);

    ret->type = type;
    ret->tag = tag;
    return ret;

fail:
    ERRARG;
    va_end(ap);
    free(ret);
    return NULL;
}

API int
nc_err_set_app_tag(struct nc_server_error *err, const char *error_app_tag)
{
    if (!err || !error_app_tag) {
        ERRARG;
        return -1;
    }

    if (err->apptag) {
        lydict_remove(server_opts.ctx, err->apptag);
    }
    err->apptag = lydict_insert(server_opts.ctx, error_app_tag, 0);

    return 0;
}

API int
nc_err_set_path(struct nc_server_error *err, const char *error_path)
{
    if (!err || !error_path) {
        ERRARG;
        return -1;
    }

    if (err->path) {
        lydict_remove(server_opts.ctx, err->path);
    }
    err->path = lydict_insert(server_opts.ctx, error_path, 0);

    return 0;
}

API int
nc_err_set_msg(struct nc_server_error *err, const char *error_message, const char *lang)
{
    if (!err || !error_message) {
        ERRARG;
        return -1;
    }

    if (err->message) {
        lydict_remove(server_opts.ctx, err->apptag);
    }
    err->message = lydict_insert(server_opts.ctx, error_message, 0);

    if (err->message_lang) {
        lydict_remove(server_opts.ctx, err->message_lang);
    }
    if (lang) {
        err->message_lang = lydict_insert(server_opts.ctx, lang, 0);
    } else {
        lang = NULL;
    }

    return 0;
}

API int
nc_err_set_sid(struct nc_server_error *err, uint32_t session_id)
{
    if (!err || !session_id) {
        ERRARG;
        return -1;
    }

    err->sid = session_id;
    return 0;
}

API int
nc_err_add_bad_attr(struct nc_server_error *err, const char *attr_name)
{
    if (!err || !attr_name) {
        ERRARG;
        return -1;
    }

    ++err->attr_count;
    err->attr = nc_realloc(err->attr, err->attr_count * sizeof *err->attr);
    if (!err->attr) {
        ERRMEM;
        return -1;
    }
    err->attr[err->attr_count - 1] = lydict_insert(server_opts.ctx, attr_name, 0);

    return 0;
}

API int
nc_err_add_bad_elem(struct nc_server_error *err, const char *elem_name)
{
    if (!err || !elem_name) {
        ERRARG;
        return -1;
    }

    ++err->elem_count;
    err->elem = nc_realloc(err->elem, err->elem_count * sizeof *err->elem);
    if (!err->elem) {
        ERRMEM;
        return -1;
    }
    err->elem[err->elem_count - 1] = lydict_insert(server_opts.ctx, elem_name, 0);

    return 0;
}

API int
nc_err_add_bad_ns(struct nc_server_error *err, const char *ns_name)
{
    if (!err || !ns_name) {
        ERRARG;
        return -1;
    }

    ++err->ns_count;
    err->ns = nc_realloc(err->ns, err->ns_count * sizeof *err->ns);
    if (!err->ns) {
        ERRMEM;
        return -1;
    }
    err->ns[err->ns_count - 1] = lydict_insert(server_opts.ctx, ns_name, 0);

    return 0;
}

API int
nc_err_add_info_other(struct nc_server_error *err, struct lyxml_elem *other)
{
    if (!err || !other) {
        ERRARG;
        return -1;
    }

    ++err->other_count;
    err->other = nc_realloc(err->other, err->other_count * sizeof *err->other);
    if (!err->other) {
        ERRMEM;
        return -1;
    }
    err->other[err->other_count - 1] = other;
    return 0;
}

void
nc_server_rpc_free(struct nc_server_rpc *rpc, struct ly_ctx *ctx)
{
    if (!rpc) {
        return;
    }

    lyxml_free(ctx, rpc->root);
    lyd_free(rpc->tree);

    free(rpc);
}

API void
nc_server_reply_free(struct nc_server_reply *reply)
{
    uint32_t i;
    struct nc_server_reply_data *data_rpl;
    struct nc_server_reply_error *error_rpl;

    if (!reply) {
        return;
    }

    switch (reply->type) {
    case NC_RPL_DATA:
        data_rpl = (struct nc_server_reply_data *)reply;
        if (data_rpl->free) {
            lyd_free_withsiblings(data_rpl->data);
        }
        break;
    case NC_RPL_OK:
        /* nothing to free */
        break;
    case NC_RPL_ERROR:
        error_rpl = (struct nc_server_reply_error *)reply;
        for (i = 0; i < error_rpl->count; ++i) {
            nc_err_free(error_rpl->err[i]);
        }
        free(error_rpl->err);
        break;
    default:
        break;
    }
    free(reply);
}

API void
nc_err_free(struct nc_server_error *err)
{
    uint32_t i;

    if (!err) {
        return;
    }

    lydict_remove(server_opts.ctx, err->apptag);
    lydict_remove(server_opts.ctx, err->path);
    lydict_remove(server_opts.ctx, err->message);
    lydict_remove(server_opts.ctx, err->message_lang);
    for (i = 0; i < err->attr_count; ++i) {
        lydict_remove(server_opts.ctx, err->attr[i]);
    }
    free(err->attr);
    for (i = 0; i < err->elem_count; ++i) {
        lydict_remove(server_opts.ctx, err->elem[i]);
    }
    free(err->elem);
    for (i = 0; i < err->ns_count; ++i) {
        lydict_remove(server_opts.ctx, err->ns[i]);
    }
    free(err->ns);
    for (i = 0; i < err->other_count; ++i) {
        lyxml_free(server_opts.ctx, err->other[i]);
    }
    free(err->other);
    free(err);
}