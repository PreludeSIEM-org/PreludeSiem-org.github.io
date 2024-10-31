# Copyright (C) 2006 PreludeIDS Technologies. All Rights Reserved.
# Author: Francois Harvey <fharvey+prelude at securiweb dot net>
#
# This file is part of the Prewikka program.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

import os

from prewikka import Auth, User, Database

# Use the SSL_CLIENT_S_DN_CN from a SSL x509 Certificate to map the user
class SSLAuth(Auth.Auth):
    def getUser(self, request):
        if not request._req.subprocess_env['HTTPS']:
                raise Auth.AuthError(message=_("SSL Authentication failed: Not in a SSL session."))
        user = request._req.subprocess_env['SSL_CLIENT_S_DN_CN']
        if not user:
            raise Auth.AuthError(message=_("SSL Authentication failed: no user specified (hint: look at the certificate CN)."))

        return User.User(self.db, user, self.db.getLanguage(user), User.ALL_PERMISSIONS, self.db.getConfiguration(user))

def load(env, config):
    return SSLAuth(env)


