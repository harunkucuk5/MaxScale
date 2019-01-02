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

#include "testconnections.h"
#include "fail_switch_rejoin_common.cpp"
#include <iostream>
#include <string>

using std::string;
using std::cout;

int main(int argc, char** argv)
{
    TestConnections test(argc, argv);
    test.repl->connect();
    delete_slave_binlogs(test);

    const char pam_user[] = "dtrump";
    const char pam_pw[] = "maga";

    const string add_user_cmd = (string)"useradd " + pam_user;
    const string add_pw_cmd = (string)"echo " + pam_user + ":" + pam_pw + " | chpasswd";
    const string read_shadow = "chmod o+r /etc/shadow";

    const string remove_user_cmd = (string)"userdel --remove " + pam_user;
    const string read_shadow_off = "chmod o-r /etc/shadow";

    test.repl->connect();
    // Prepare the backends for PAM authentication. Enable the plugin and create a user. Also, since
    // make /etc/shadow readable for all so that the server process can access it.
    for (int i = 0; i < test.repl->N; i++)
    {
        MYSQL* conn = test.repl->nodes[i];
        test.try_query(conn, "INSTALL SONAME 'auth_pam';");
        test.repl->ssh_node_f(i, true, "%s", add_user_cmd.c_str());
        test.repl->ssh_node_f(i, true, "%s", add_pw_cmd.c_str());
        test.repl->ssh_node_f(i, true, "%s", read_shadow.c_str());
    }

    // Also create the user on the node running MaxScale, as the MaxScale PAM plugin compares against
    // local users.
    test.maxscales->ssh_node_f(0, true, "%s", add_user_cmd.c_str());
    test.maxscales->ssh_node_f(0, true, "%s", add_pw_cmd.c_str());
    test.maxscales->ssh_node_f(0, true, "%s", read_shadow.c_str());

    if (test.ok())
    {
        cout << "PAM-plugin installed and users created on all servers. Starting MaxScale.\n";
    }
    else
    {
        cout << "Test preparations failed.\n";
    }

    auto set_to_string = [](const StringSet& str_set) -> string {
            string rval;
            for (const string& elem : str_set)
            {
                rval += elem + ",";
            }
            return rval;
        };

    auto expect_server_status = [&test, &set_to_string](const string& server_name, const string& status) {
            auto status_set = test.maxscales->get_server_status(server_name.c_str());
            string status_str = set_to_string(status_set);
            bool found = (status_set.count(status) == 1);
            test.expect(found, "%s was not %s as was expected. Status: %s.",
                        server_name.c_str(), status.c_str(), status_str.c_str());
        };

    string server_names[] = {"server1", "server2", "server3", "server4"};
    string master = "Master";
    string slave = "Slave";

    if (test.ok())
    {
        get_output(test);
        print_gtids(test);

        expect_server_status(server_names[0], master);
        expect_server_status(server_names[1], slave);
        expect_server_status(server_names[2], slave);
        expect_server_status(server_names[3], slave);
    }

    // Helper function for checking PAM-login.
    auto try_log_in = [&test](const string& user, const string& pass) {
        const char* host = test.maxscales->IP[0];
        int port = test.maxscales->ports[0][0];
        printf("Trying to log in to [%s]:%i as %s.\n", host, port, user.c_str());
        auto maxconn = open_conn(port, host, user, pass);
        auto err = mysql_error(maxconn);
        if (err && *err)
        {
            cout << "Could not log in: '" << err << "'\n";
        }
        else
        {
            test.try_query(maxconn, "SELECT @@server_id;");
            if (test.ok())
            {
                cout << "Logged in and queried successfully.\n";
            }
            else
            {
                cout << "Query rejected: '" << mysql_error(maxconn) << "'\n";
            }
        }
        mysql_close(maxconn);
    };

    auto update_users = [&test]() {
        test.maxscales->execute_maxadmin_command(0, "reload dbusers RWSplit-Router");
    };

    if (test.ok())
    {
        MYSQL* conn = test.repl->nodes[0];
        // Create the PAM user on the master, it will replicate. Use the standard password service for
        // authenticating.
        test.try_query(conn, "CREATE USER '%s'@'%%' IDENTIFIED VIA pam USING 'passwd';", pam_user);
        test.try_query(conn, "GRANT SELECT ON *.* TO '%s'@'%%';", pam_user);
        test.try_query(conn, "FLUSH PRIVILEGES;");
        sleep(1);
        test.repl->sync_slaves();
        update_users();

        // If ok so far, try logging in with PAM.
        if (test.ok())
        {
            try_log_in(pam_user, pam_pw);
        }

        // Remove the created user.
        test.try_query(conn, "DROP USER '%s'@'%%';", pam_user);
    }

    if (test.ok())
    {
        const char dummy_user[] = "proxy-target";
        const char dummy_pw[] = "unused_pw";
        // Basic PAM authentication seems to be working. Now try with an anonymous user proxying to
        // the real user.
        MYSQL* conn = test.repl->nodes[0];
        // Add a user which has the grants.
        test.try_query(conn, "CREATE USER '%s'@'%%' IDENTIFIED BY '%s';", dummy_user, dummy_pw);
        test.try_query(conn, "GRANT SELECT ON *.* TO '%s'@'%%';", dummy_user);
        // Create the anonymous catch-all user and allow it to proxy as the proxy-target, meaning it
        // gets the target's privileges.
        test.try_query(conn, "CREATE USER ''@'%%' IDENTIFIED VIA pam USING 'passwd';");
        test.try_query(conn, "GRANT PROXY ON '%s'@'%%' TO ''@'%%';", dummy_user);
        test.try_query(conn, "FLUSH PRIVILEGES;");
        sleep(1);
        test.repl->sync_slaves();
        update_users();

        if (test.ok())
        {
            // Again, try logging in with the same user.
            try_log_in(pam_user, pam_pw);
        }

        // Remove the created users.
        test.try_query(conn, "DROP USER '%s'@'%%';", dummy_user);
        test.try_query(conn, "DROP USER ''@'%%';");
    }

    // Cleanup: remove the linux users on the backends and MaxScale node, unload pam plugin.
    for (int i = 0; i < test.repl->N; i++)
    {
        MYSQL* conn = test.repl->nodes[i];
        test.try_query(conn, "UNINSTALL SONAME 'auth_pam';");
        test.repl->ssh_node_f(i, true, "%s", remove_user_cmd.c_str());
        test.repl->ssh_node_f(i, true, "%s", read_shadow_off.c_str());
    }
    test.maxscales->ssh_node_f(0, true, "%s", remove_user_cmd.c_str());
    test.maxscales->ssh_node_f(0, true, "%s", read_shadow_off.c_str());

    test.repl->disconnect();
    return test.global_result;
}
