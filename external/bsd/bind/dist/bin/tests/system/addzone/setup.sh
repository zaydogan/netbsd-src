#!/bin/sh
#
# Copyright (C) 2010, 2012-2014, 2017  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

cp -f ns2/named1.conf ns2/named.conf
cp -f ns2/default.nzf.in ns2/3bf305731dd26307.nzf

cp -f ns3/named1.conf ns3/named.conf
rm -f ns3/*.nzf ns3/*.nzf~
rm -f ns3/*.nzd ns3/*.nzd-lock
rm -f ns3/inlineslave.db
