// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2024 igo95862
#define _GNU_SOURCE
#include <error.h>
#include <fcntl.h>
#include <glib.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#define CLEANUP_SD_BUS_MESSAGE __attribute__((cleanup(sd_bus_message_unrefp)))

#define INT_CHECK(function)                                                \
        ({                                                                 \
                int r = function;                                          \
                if (r < 0) {                                               \
                        printf("Failed %s with code %i \n", #function, r); \
                        return r;                                          \
                }                                                          \
                r;                                                         \
        })

#define FATAL_INT_CHECK(function)             \
        ({                                    \
                int r = function;             \
                if (r < 0) {                  \
                        error(1, r, "FATAL"); \
                }                             \
        })

static char* from_dbus_address = "unix:path=/run/dbus/system_bus_socket";
static sd_bus* from_dbus = NULL;

static char* to_dbus_address = "unix:path=/run/user/1000/bus";
static sd_bus* to_dbus = NULL;
static const char* to_dbus_unique_addr = NULL;

static char* service_to_forward = "org.freedesktop.NetworkManager";

static sd_event* event_loop = NULL;

static pid_t pid = -1;

static int forwarded_callback(sd_bus_message* m, void* userdata, [[maybe_unused]] sd_bus_error* ret_error) {
        sd_bus_message* CLEANUP_SD_BUS_MESSAGE original_message = userdata;
        sd_bus_message* CLEANUP_SD_BUS_MESSAGE forwarded_reply = NULL;

        INT_CHECK(sd_bus_message_new_method_return(original_message, &forwarded_reply));
        INT_CHECK(sd_bus_message_copy(forwarded_reply, m, 1));

        INT_CHECK(sd_bus_message_send(forwarded_reply));

        return 0;
}

static int capture_all_to_messages(sd_bus_message* m, [[maybe_unused]] void* userdata, [[maybe_unused]] sd_bus_error* ret_error) {
        INT_CHECK(sd_bus_message_dump(m, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER));
        INT_CHECK(sd_bus_message_rewind(m, 1));

        const char* m_destination = sd_bus_message_get_destination(m);
        if (!(strcmp(service_to_forward, m_destination) == 0 || strcmp(to_dbus_unique_addr, m_destination) == 0)) {
                return 0;
        }
        uint8_t incomming_message_type = -1;
        INT_CHECK(sd_bus_message_get_type(m, &incomming_message_type));
        if (incomming_message_type != SD_BUS_MESSAGE_METHOD_CALL) {
                return 0;
        }

        sd_bus_message* CLEANUP_SD_BUS_MESSAGE forwarding_message = NULL;

        INT_CHECK(sd_bus_message_new_method_call(from_dbus, &forwarding_message, service_to_forward, sd_bus_message_get_path(m),
                                                 sd_bus_message_get_interface(m), sd_bus_message_get_member(m)));

        INT_CHECK(sd_bus_message_copy(forwarding_message, m, 1));

        INT_CHECK(sd_bus_call_async(from_dbus, NULL, forwarding_message, forwarded_callback, sd_bus_message_ref(m), 0));

        return 1;
}

static int open_from_dbus() {
        INT_CHECK(sd_bus_new(&from_dbus));
        INT_CHECK(sd_bus_set_address(from_dbus, from_dbus_address));
        INT_CHECK(sd_bus_set_bus_client(from_dbus, 1));
        INT_CHECK(sd_bus_start(from_dbus));
        INT_CHECK(sd_bus_attach_event(from_dbus, event_loop, 0));

        return 0;
}

static int open_to_dbus() {
        INT_CHECK(sd_bus_new(&to_dbus));
        INT_CHECK(sd_bus_set_address(to_dbus, to_dbus_address));
        INT_CHECK(sd_bus_set_bus_client(to_dbus, 1));
        INT_CHECK(sd_bus_start(to_dbus));
        INT_CHECK(sd_bus_attach_event(to_dbus, event_loop, 0));
        INT_CHECK(sd_bus_get_unique_name(to_dbus, &to_dbus_unique_addr));

        INT_CHECK(sd_bus_request_name(to_dbus, service_to_forward, 0));
        INT_CHECK(sd_bus_add_filter(to_dbus, NULL, capture_all_to_messages, NULL));
        printf("Acquired %s\n", service_to_forward);

        return 0;
}

static int create_event_loop() {
        INT_CHECK(sd_event_new(&event_loop));
        return 0;
}

static int switch_to_pid_mount_namespace() {
        if (pid < 0) {
                return 0;
        }
        GString* mount_ns_path = g_string_new(NULL);
        g_string_printf(mount_ns_path, "/proc/%i/ns/mnt", pid);
        int mount_ns = INT_CHECK(open(mount_ns_path->str, O_CLOEXEC | O_RDONLY));
        int user_ns = INT_CHECK(ioctl(mount_ns, NS_GET_USERNS));
        INT_CHECK(setns(user_ns, CLONE_NEWUSER));
        INT_CHECK(setns(mount_ns, CLONE_NEWNS));

        g_string_free(mount_ns_path, TRUE);
        close(user_ns);
        close(mount_ns);

        return 0;
}

static GOptionEntry entries[] = {
    {
        "service",
        '\0',
        0,
        G_OPTION_ARG_STRING,
        &service_to_forward,
        "D-Bus service to forward",
        NULL,
    },
    {
        "from-dbus-address",
        '\0',
        0,
        G_OPTION_ARG_STRING,
        &from_dbus_address,
        "from D-Bus address to forward",
        NULL,
    },
    {
        "to-dbus-address",
        '\0',
        0,
        G_OPTION_ARG_STRING,
        &to_dbus_address,
        "to D-Bus address to forward",
        NULL,
    },
    {
        "pid",
        '\0',
        0,
        G_OPTION_ARG_INT,
        &pid,
        "PID to use mount namespace of",
        NULL,
    },
    {0},
};

int main(int argc, char** argv) {
        GError* g_error = NULL;
        GOptionContext* context = g_option_context_new("");
        g_option_context_add_main_entries(context, entries, NULL);

        if (!g_option_context_parse(context, &argc, &argv, &g_error)) {
                g_print("option parsing failed: %s\n", g_error->message);
                abort();
        }

        printf("Forwarding service %s\n", service_to_forward);
        printf("From D-Bus address %s\n", from_dbus_address);
        printf("To D-Bus address %s\n", to_dbus_address);

        FATAL_INT_CHECK(create_event_loop());
        FATAL_INT_CHECK(open_from_dbus());
        FATAL_INT_CHECK(switch_to_pid_mount_namespace());
        FATAL_INT_CHECK(open_to_dbus());
        printf("Connected\n");

        FATAL_INT_CHECK(sd_event_loop(event_loop));

        return 0;
}
