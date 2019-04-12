/*
 * Copyright (c) 2016 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2022-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */


/**
 * @file mysql_utils.c  - Binary MySQL data processing utilities
 *
 * This file contains functions that are used when processing binary format
 * information. The MySQL protocol uses the binary format in result sets and
 * row based replication.
 */

#include <maxscale/mysql_utils.hh>

#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <errmsg.h>

#include <maxbase/atomic.hh>
#include <maxbase/format.hh>
#include <maxsql/mariadb.hh>
#include <maxscale/alloc.h>
#include <maxscale/config.hh>

/**
 * @brief Calculate the length of a length-encoded integer in bytes
 *
 * @param ptr Start of the length encoded value
 * @return Number of bytes before the actual value
 */
size_t mxs_leint_bytes(const uint8_t* ptr)
{
    uint8_t val = *ptr;
    if (val < 0xfb)
    {
        return 1;
    }
    else if (val == 0xfc)
    {
        return 3;
    }
    else if (val == 0xfd)
    {
        return 4;
    }
    else
    {
        return 9;
    }
}

/**
 * @brief Converts a length-encoded integer to @c uint64_t
 *
 * @see https://dev.mysql.com/doc/internals/en/integer.html
 * @param c Pointer to the first byte of a length-encoded integer
 * @return The value converted to a standard unsigned integer
 */
uint64_t mxs_leint_value(const uint8_t* c)
{
    uint64_t sz = 0;

    if (*c < 0xfb)
    {
        sz = *c;
    }
    else if (*c == 0xfc)
    {
        memcpy(&sz, c + 1, 2);
    }
    else if (*c == 0xfd)
    {
        memcpy(&sz, c + 1, 3);
    }
    else if (*c == 0xfe)
    {
        memcpy(&sz, c + 1, 8);
    }
    else
    {
        mxb_assert(*c == 0xff);
        MXS_ERROR("Unexpected length encoding '%x' encountered when reading "
                  "length-encoded integer.",
                  *c);
    }

    return sz;
}

/**
 * Converts a length-encoded integer into a standard unsigned integer
 * and advances the pointer to the next unrelated byte.
 *
 * @param c Pointer to the first byte of a length-encoded integer
 */
uint64_t mxs_leint_consume(uint8_t** c)
{
    uint64_t rval = mxs_leint_value(*c);
    *c += mxs_leint_bytes(*c);
    return rval;
}

/**
 * @brief Consume and duplicate a length-encoded string
 *
 * Converts a length-encoded string to a C string and advances the pointer to
 * the first byte after the string. The caller is responsible for freeing
 * the returned string.
 * @param c Pointer to the first byte of a valid packet.
 * @return The newly allocated string or NULL if memory allocation failed
 */
char* mxs_lestr_consume_dup(uint8_t** c)
{
    uint64_t slen = mxs_leint_consume(c);
    char* str = (char*)MXS_MALLOC((slen + 1) * sizeof(char));

    if (str)
    {
        memcpy(str, *c, slen);
        str[slen] = '\0';
        *c += slen;
    }

    return str;
}

/**
 * @brief Consume a length-encoded string
 *
 * Converts length-encoded strings to character strings and advanced
 * the pointer to the next unrelated byte.
 * @param c Pointer to the start of the length-encoded string
 * @param size Pointer to a variable where the size of the string is stored
 * @return Pointer to the start of the string
 */
char* mxs_lestr_consume(uint8_t** c, size_t* size)
{
    uint64_t slen = mxs_leint_consume(c);
    *size = slen;
    char* start = (char*) *c;
    *c += slen;
    return start;
}

MYSQL* mxs_mysql_real_connect(MYSQL* con, SERVER* server, const char* user, const char* passwd)
{
    SSL_LISTENER* listener = server->server_ssl;

    if (listener)
    {
        mysql_ssl_set(con, listener->ssl_key, listener->ssl_cert, listener->ssl_ca_cert, NULL, NULL);
    }

    char yes = 1;
    mysql_optionsv(con, MYSQL_OPT_RECONNECT, &yes);
    mysql_optionsv(con, MYSQL_INIT_COMMAND, "SET SQL_MODE=''");

    MXS_CONFIG* config = config_get_global_options();

    if (config->local_address)
    {
        if (mysql_optionsv(con, MYSQL_OPT_BIND, config->local_address) != 0)
        {
            MXS_ERROR("'local_address' specified in configuration file, but could not "
                      "configure MYSQL handle. MaxScale will try to connect using default "
                      "address.");
        }
    }

    MYSQL* mysql = nullptr;

    if (server->address[0] == '/')
    {
        mysql = mysql_real_connect(con, nullptr, user, passwd, nullptr, 0, server->address, 0);
    }
    else
    {
        mysql = mysql_real_connect(con, server->address, user, passwd, NULL, server->port, NULL, 0);
        auto extra_port = mxb::atomic::load(&server->extra_port, mxb::atomic::RELAXED);

        if (!mysql && extra_port > 0)
        {
            mysql = mysql_real_connect(con, server->address, user, passwd, NULL, extra_port, NULL, 0);
            MXS_WARNING("Could not connect with normal port to server '%s', using extra_port", server->name());
        }
    }

    if (mysql)
    {
        /** Copy the server charset */
        MY_CHARSET_INFO cs_info;
        mysql_get_character_set_info(mysql, &cs_info);
        server->charset = cs_info.number;

        if (listener && mysql_get_ssl_cipher(con) == NULL)
        {
            if (server->warn_ssl_not_enabled)
            {
                server->warn_ssl_not_enabled = false;
                MXS_ERROR("An encrypted connection to '%s' could not be created, "
                          "ensure that TLS is enabled on the target server.",
                          server->name());
            }
            // Don't close the connection as it is closed elsewhere, just set to NULL
            mysql = NULL;
        }
    }

    return mysql;
}

int mxs_mysql_query(MYSQL* conn, const char* query)
{
    MXS_CONFIG* cnf = config_get_global_options();
    return maxsql::mysql_query_ex(conn, query, cnf->query_retries, cnf->query_retry_timeout);
}

const char* mxs_mysql_get_value(MYSQL_RES* result, MYSQL_ROW row, const char* key)
{
    MYSQL_FIELD* f = mysql_fetch_fields(result);
    int nfields = mysql_num_fields(result);

    for (int i = 0; i < nfields; i++)
    {
        if (strcasecmp(f[i].name, key) == 0)
        {
            return row[i];
        }
    }

    return NULL;
}

bool mxs_mysql_trim_quotes(char* s)
{
    bool dequoted = true;

    char* i = s;
    char* end = s + strlen(s);

    // Remove space from the beginning
    while (*i && isspace(*i))
    {
        ++i;
    }

    if (*i)
    {
        // Remove space from the end
        while (isspace(*(end - 1)))
        {
            *(end - 1) = 0;
            --end;
        }

        mxb_assert(end > i);

        char quote;

        switch (*i)
        {
        case '\'':
        case '"':
        case '`':
            quote = *i;
            ++i;
            break;

        default:
            quote = 0;
        }

        if (quote)
        {
            --end;

            if (*end == quote)
            {
                *end = 0;

                memmove(s, i, end - i + 1);
            }
            else
            {
                dequoted = false;
            }
        }
        else if (i != s)
        {
            memmove(s, i, end - i + 1);
        }
    }
    else
    {
        *s = 0;
    }

    return dequoted;
}


mxs_mysql_name_kind_t mxs_mysql_name_to_pcre(char* pcre,
                                             const char* mysql,
                                             mxs_pcre_quote_approach_t approach)
{
    mxs_mysql_name_kind_t rv = MXS_MYSQL_NAME_WITHOUT_WILDCARD;

    while (*mysql)
    {
        switch (*mysql)
        {
        case '%':
            if (approach == MXS_PCRE_QUOTE_WILDCARD)
            {
                *pcre = '.';
                pcre++;
                *pcre = '*';
            }
            rv = MXS_MYSQL_NAME_WITH_WILDCARD;
            break;

        case '\'':
        case '^':
        case '.':
        case '$':
        case '|':
        case '(':
        case ')':
        case '[':
        case ']':
        case '*':
        case '+':
        case '?':
        case '{':
        case '}':
            *pcre++ = '\\';

        // Flowthrough
        default:
            *pcre = *mysql;
        }

        ++pcre;
        ++mysql;
    }

    *pcre = 0;

    return rv;
}

void mxs_mysql_update_server_version(SERVER* dest, MYSQL* source)
{
    // This function should only be called for a live connection.
    const char* version_string = mysql_get_server_info(source);
    unsigned long version_num = mysql_get_server_version(source);
    mxb_assert(version_string != NULL && version_num != 0);
    dest->set_version(version_num, version_string);
}

namespace maxscale
{

std::unique_ptr<mxq::QueryResult> execute_query(MYSQL* conn, const std::string& query,
                                                std::string* errmsg_out)
{
    using mxq::QueryResult;
    std::unique_ptr<QueryResult> rval;
    MYSQL_RES* result = NULL;
    if (mxs_mysql_query(conn, query.c_str()) == 0 && (result = mysql_store_result(conn)) != NULL)
    {
        rval = std::unique_ptr<QueryResult>(new QueryResult(result));
    }
    else if (errmsg_out)
    {
        *errmsg_out = mxb::string_printf("Query '%s' failed: '%s'.", query.c_str(), mysql_error(conn));
    }
    return rval;
}

}

#if defined(SS_DEBUG)
/**
 * Return decoded MySQL response packet.
 *
 * Intended to be used when debugging with a GDB-based debugger.
 * For instance, if GDB has been stopped by a breakpoint in
 * clientReply() you can use this function for investigating
 * what the response packet contains:
 *
 * (gdb) p dbg_decode_response(writebuf)
 * $30 = 0x7ffff0d40d54 "Packet no: 1, Payload len: 44, Command : ERR,
 * Code: 1146, Message : Table 'test.blahasdf' doesn't exist"
 *
 * @param pPacket  A MySQL response packet.
 *
 * @return The packet decoded into a descriptive string.
 */
char *dbg_decode_response(GWBUF* pPacket)
{
    uint8_t header[MYSQL_HEADER_LEN + 1];

    gwbuf_copy_data(pPacket, 0, sizeof(header), header);

    uint32_t payload_len = MYSQL_GET_PAYLOAD_LEN(header);
    uint32_t packet_no = MYSQL_GET_PACKET_NO(header);

    uint32_t command = std::numeric_limits<uint32_t>::max();

    if (gwbuf_length(pPacket) > MYSQL_HEADER_LEN)
    {
        command = MYSQL_GET_COMMAND(header);
    }

    const int buflen = 1024; // Should be enough.

    thread_local char buffer[buflen];

    int len = buflen;
    char* z = buffer;

    int l = snprintf(z, len, "Packet no: %u, Payload len: %u", packet_no, payload_len);

    z += l;
    len -= l;

    switch (command)
    {
    case 0x00:
        snprintf(z, len, ", Command : OK");
        break;

    case 0xff:
        {
            l = snprintf(z, len, ", Command : ERR");
            z += l;
            len -= l;

            uint8_t error[payload_len];

            gwbuf_copy_data(pPacket, MYSQL_HEADER_LEN, payload_len, error);

            uint32_t error_code = gw_mysql_get_byte2(&error[1]);

            l = snprintf(z, len, ", Code: %u", error_code);
            z += l;
            len -= l;

            const int message_index = 1 + 2 + 1 + 5;
            uint8_t* pMessage = &error[message_index];

            l = snprintf(z, len, ", Message : ");

            z += l;
            len -= l;

            int message_len = payload_len - message_index;

            if (message_len + 1 > len)
            {
                message_len = len - 1;
            }

            strncpy(z, (char*)pMessage, message_len);
            z[message_len] = 0;
        }
        break;

    case 0xfb:
        snprintf(z, len, ", Command : GET_MORE_CLIENT_DATA");
        break;

    case std::numeric_limits<uint32_t>::max():
        break;

    default:
        snprintf(z, len, ", Command : Result Set");
    }

    return buffer;
}
#endif
