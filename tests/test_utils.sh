#! /bin/sh
# Shared utilities for test suites
#
# Copyright (c) 2004, 2010 Red Hat, Inc. All rights reserved.
#
# This is free software; you can redistribute it and/or modify it under
# the terms of the GNU Library General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Author: Miloslav Trmač <mitr@redhat.com>

# Wait for slapd to start and write its pid into $1
wait_for_slapd() {
    counter=0
    while [ "$counter" -lt 30 ]; do
	printf "\rWaiting for slapd: $counter..."
	counter=$(expr "$counter" + 1)
	if [ -s "$1" ]; then
	    echo
	    return
	fi
	sleep 1
    done
    echo
    echo "Timeout waiting for slapd" >&2
}
