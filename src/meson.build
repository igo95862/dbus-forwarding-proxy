# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2024 igo95862
glib = dependency('glib-2.0', required : true)
libsystemd = dependency('libsystemd', required : true)

executable(
    'dbus-forwarding-proxy',
    'main.c',
    dependencies : [glib, libsystemd],
)
