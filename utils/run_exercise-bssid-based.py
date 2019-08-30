#!/usr/bin/env python2
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Adapted by Robert MacDavid (macdavid@cs.princeton.edu) from scripts found in
# the p4app repository (https://github.com/p4lang/p4app)
#
# We encourage you to dissect this script to better understand the BMv2/Mininet
# environment used by the P4 tutorial.
#
import os, json, subprocess, argparse
from time import sleep

from p4_mininet import P4AP, P4Station, P4Host, P4Switch

from mininet.term import makeTerm
from mn_wifi.net import Mininet_wifi
from mn_wifi.topo import Topo_WiFi
from mn_wifi.cli import CLI_wifi

from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference

from p4runtime_ap import P4RuntimeAP
from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller


def configureP4Switch(**ap_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in ap_args and 'grpc' in ap_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(ap_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port: %d" % (self.name, int(self.grpc_port))

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(ap_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> Thrift port: %d" % (self.name, self.thrift_port)

        return ConfiguredP4Switch

def configureP4AP(**ap_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in ap_args and 'grpc' in ap_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeAP(P4RuntimeAP):
            def __init__(self, *opts, **kwargs):
                kwargs.update(ap_args)
                P4RuntimeAP.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port: %d" % (self.name, int(self.grpc_port))

        return ConfiguredP4RuntimeAP
    else:
        class ConfiguredP4AP(P4AP):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(ap_args)
                kwargs['thrift_port'] = ConfiguredP4AP.next_thrift_port
                ConfiguredP4AP.next_thrift_port += 1
                P4AP.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> Thrift port: %d" % (self.name, self.thrift_port)

        return ConfiguredP4AP


class ExerciseTopo(Topo_WiFi):
    """ The mininet topology class for the P4 tutorial exercises.
    """
    def __init__(self, stations, aps, hosts, switches, links,
                 log_dir, bmv2_exe, pcap_dir, **opts):
        Topo_WiFi.__init__(self, **opts)
        sta_links = []
        ap_links = []

        # assumes station always comes first for station<-->ap links
        for link in links:
            if (link['node2'][0] == 's' and link['node2'][1] == 't') \
                    or link['node1'][0] == 'h':
                sta_links.append(link)
            else:
                ap_links.append(link)

        if switches:
            for switch, params in switches.iteritems():
                if "program" in params:
                    switchClass = configureP4Switch(
                            sw_path=bmv2_exe,
                            json_path=params["program"],
                            log_console=True,
                            pcap_dump=pcap_dir)
                else:
                    # add default ap
                    switchClass = None

                if 'device_id' in params:
                    device_id = params['device_id']
                else:
                    device_id = None

                if 'grpc_port' in params:
                    grpc_port = params['grpc_port']
                else:
                    grpc_port = None

                if 'thrift-port' in params:
                    thrift_port = params['thrift-port']
                else:
                    thrift_port = None

                self.addSwitch(switch, log_file="%s/%s.log" % (log_dir, switch),
                               grpc_port=grpc_port, device_id=device_id,
                               thrift_port=thrift_port, cls=switchClass)

        if aps:
            for ap, params in aps.iteritems():
                if "program" in params:
                    apClass = configureP4AP(
                            sw_path=bmv2_exe,
                            json_path=params["program"],
                            log_console=True,
                            pcap_dump=pcap_dir)
                else:
                    # add default ap
                    apClass = None
                if int(ap[2:]) == 1:
                    x, y = 100, 100
                elif int(ap[2:]) == 2:
                    x, y = 500, 100

                if 'device_id' in params:
                    device_id = params['device_id']
                else:
                    device_id = None

                if 'grpc_port' in params:
                    grpc_port = params['grpc_port']
                else:
                    grpc_port = None

                if 'thrift-port' in params:
                    thrift_port = params['thrift-port']
                else:
                    thrift_port = None

                self.addAccessPoint(ap, log_file="%s/%s.log" % (log_dir, ap),
                                    position='%s,%s,0' % (x, y),
                                    grpc_port=grpc_port, device_id=device_id,
                                    thrift_port=thrift_port, cls=apClass,
                                    passwd='123456789a', encrypt='wpa2',
                                    ieee80211r='yes', mobility_domain='a1b2'
                                    )

        for link in sta_links:

            if link['node1'][0] == 'h':
                sta_name = link['node1']
                sw = link['node2']
                sta_num = int(sta_name[1:])
            else:
                sta_name = link['node2']
                sw = link['node1']
                sta_num = int(sta_name[3:])
            ap_name, sw_port = self.parse_ap_node(sw)
            sta_ip = "10.0.%d.%d" % (sta_num, sta_num)
            sta_mac = '08:00:00:00:%02x:%s%s' % (sta_num, sta_num, sta_num)
            if link['node1'][0] != 'h':
                if int(ap_name[2:]) == 1:
                    x, y = 100, 80
                elif int(ap_name[2:]) == 2:
                    x, y = 600, 500
            if link['node1'][0] == 'h':
                if sta_num == 4:
                    self.addHost(sta_name, ip=sta_ip + '/24', mac=sta_mac, inNamespace=False)
                else:
                    self.addHost(sta_name, ip=sta_ip + '/24', mac=sta_mac)
            else:
                self.addStation(sta_name, ip=sta_ip + '/24', mac=sta_mac,
                                encrypt='wpa2',
                                bgscan_threshold=-70,
                                s_inverval=1,
                                l_interval=2,
                                position='%s,%s,0' % (x, y))

            self.addLink(sta_name, ap_name)

        for link in ap_links:
            sw1_name, sw1_port = self.parse_ap_node(link['node1'])
            sw2_name, sw2_port = self.parse_ap_node(link['node2'])
            self.addLink(sw1_name, sw2_name,
                         port1=sw1_port, port2=sw2_port)

    def parse_ap_node(self, node):
        ap_name, sw_port = node.split('-')
        try:
            sw_port = int(sw_port[1])
        except:
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return ap_name, sw_port


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : dict<string, dict> // mininet host names and their associated properties
            switches : dict<string, dict> // mininet switch names and their associated properties
            links    : list<dict>         // list of mininet link properties

            ap_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance

    """
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def format_latency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"


    def __init__(self, topo_file, log_dir, pcap_dir,
                 ap_json, bmv2_exe='simple_switch', quiet=False):
        """ Initializes some attributes and reads the topology json. Does not
            actually run the exercise. Use run_exercise() for that.

            Arguments:
                topo_file : string    // A json file which describes the exercise's
                                         mininet topology.
                log_dir  : string     // Path to a directory for storing exercise logs
                pcap_dir : string     // Ditto, but for mininet switch pcap files
                ap_json : string  // Path to a compiled p4 json for bmv2
                bmv2_exe    : string  // Path to the p4 behavioral binary
                quiet : bool          // Enable/disable script debug messages
        """

        self.quiet = quiet
        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.stations = None
        self.hosts = None
        self.aps = None
        self.switches = None
        if 'stations' in topo:
            self.stations = topo['stations']
        if 'aps' in topo:
            self.aps = topo['aps']
        if 'switches' in topo:
            self.switches = topo['switches']
        if 'hosts' in topo:
            self.hosts = topo['hosts']
        self.links = self.parse_links(topo['links'])

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.ap_json = ap_json
        self.bmv2_exe = bmv2_exe

    def run_exercise(self):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.plotGraph(max_x=700, max_y=700)
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        if self.net.stations:
            self.program_stations()
        if self.net.hosts:
            self.program_hosts()
        if self.net.aps:
            self.program_aps()
        if self.net.switches:
            self.program_switches()

        # wait for that to finish. Not sure how to do this better
        sleep(1)

        makeTerm(self.net.aps[0], cmd="bash -c 'python send.py ap1;'")
        makeTerm(self.net.aps[1], cmd="bash -c 'python send.py ap2;'")
        makeTerm(self.net.hosts[1], cmd="bash -c 'python receive.py;'")

        self.do_net_cli()
        # stop right after the CLI is exited

        os.system('pkill -f \"xterm -title\"')
        self.net.stop()

    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s,t = t,s

            link_dict = {'node1':s,
                        'node2':t,
                        'latency':'0ms',
                        'bandwidth':None
                        }
            if len(link) > 2:
                link_dict['latency'] = self.format_latency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            links.append(link_dict)
        return links

    def create_network(self):
        """ Create the mininet network object, and store it as self.net.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")

        defaultapClass = configureP4AP(
            sw_path=self.bmv2_exe,
            json_path=self.ap_json,
            log_console=True,
            pcap_dump=self.pcap_dir)

        defaultSwitchClass = configureP4Switch(
            sw_path=self.bmv2_exe,
            json_path=self.ap_json,
            log_console=True,
            pcap_dump=self.pcap_dir)

        self.topo = ExerciseTopo(self.stations, self.aps, self.hosts, self.switches, self.links,
                                 self.log_dir, self.bmv2_exe, self.pcap_dir)

        self.net = Mininet_wifi(topo=self.topo,
                                station=P4Station,
                                host=P4Host,
                                switch=defaultSwitchClass,
                                accessPoint=defaultapClass,
                                controller=None,
                                link=wmediumd,
                                wmediumd_mode=interference
                                #plot=True
                                )

    def program_ap_p4runtime(self, ap_name, ap_dict):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_obj = self.net.get(ap_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        runtime_json = ap_dict['runtime_json']
        self.logger('Configuring ap %s using P4Runtime with file %s' % (ap_name, runtime_json))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-requests.txt' %(self.log_dir, ap_name)
            p4runtime_lib.simple_controller.program_switch(
                addr='127.0.0.1:%d' % int(grpc_port),
                device_id=device_id,
                sw_conf_file=sw_conf_file,
                workdir=os.getcwd(),
                proto_dump_fpath=outfile)

    def program_switch_cli(self, ap_name, ap_dict):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """
        cli = 'simple_switch_CLI'
        # get the port for this particular switch's thrift server
        sw_obj = self.net.get(ap_name)
        thrift_port = sw_obj.thrift_port

        cli_input_commands = ap_dict['cli_input']
        self.logger('Configuring ap %s with file %s' % (ap_name, cli_input_commands))
        with open(cli_input_commands, 'r') as fin:
            cli_outfile = '%s/%s_cli_output.log'%(self.log_dir, ap_name)
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                 stdin=fin, stdout=fout)

    def program_aps(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for ap_name, ap_dict in self.aps.iteritems():
            if 'cli_input' in ap_dict:
                self.program_switch_cli(ap_name, ap_dict)
            if 'runtime_json' in ap_dict:
                self.program_ap_p4runtime(ap_name, ap_dict)

    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for ap_name, ap_dict in self.switches.iteritems():
            if 'cli_input' in ap_dict:
                self.program_switch_cli(ap_name, ap_dict)
            if 'runtime_json' in ap_dict:
                self.program_ap_p4runtime(ap_name, ap_dict)

    def program_stations(self):
        """ Execute any commands provided in the topology.json file on each Mininet host
        """
        for host_name, host_info in self.stations.items():
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)

    def program_hosts(self):
        """ Execute any commands provided in the topology.json file on each Mininet host
        """
        for host_name, host_info in self.hosts.items():
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)

    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.aps:
            s.describe()
        for s in self.net.switches:
            s.describe()
        for h in self.net.stations:
            h.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet-wifi CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet-WiFi CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial runtime configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.ap_json:
            print('To inspect or change the switch configuration, connect to')
            print('its CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' %  self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r ap1-eth1.pcap')
        print('')
        if 'grpc' in self.bmv2_exe:
            print('To view the P4Runtime requests sent to the switch, check the')
            print('corresponding txt file in %s:' % self.log_dir)
            print(' for example run:  cat %s/s1-p4runtime-requests.txt' % self.log_dir)
            print('')

        CLI_wifi(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--ap_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                                type=str, required=False, default='simple_switch')
    return parser.parse_args()


if __name__ == '__main__':
    #from mininet.log import setLogLevel
    #setLogLevel("debug")

    args = get_args()
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir,
                              args.ap_json, args.behavioral_exe, args.quiet)

    exercise.run_exercise()

