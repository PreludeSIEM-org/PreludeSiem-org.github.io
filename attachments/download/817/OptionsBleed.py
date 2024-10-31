# Copyright (C) 2017 CS-SI <support.prelude@c-s.fr>
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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.context import Context

class OptionsBleed(Plugin):
    def run(self, idmef):
        if "OPTIONS" not in idmef.get("alert.classification.text") or idmef.get("alert.analyzer(-1).name") != "httpd":
            return

        ctx = Context(("OPTIONSBLEED", idmef.get('alert.target(0).node.address(*).address')), { "expire": 120, "threshold": 15, "alert_on_expire": True }, update=True, idmef=idmef)
        if ctx.getUpdateCount() == 0:
            ctx.set("alert.classification.text", "OptionsBleed attack")
            ctx.set("alert.correlation_alert.name", "Multiple HTTP OPTIONS requests against a single host")
            ctx.set("alert.assessment.impact.severity", "high")
            ctx.set("alert.assessment.impact.description", "Multiple HTTP OPTIONS requests against a single host. It may be an OPTIONS Bleed atttack")
            ctx.set("alert.classification.reference(0).origin", "cve")
            ctx.set("alert.classification.reference(0).name", "2017-9798")