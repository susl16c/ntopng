/*
 *
 * (C) 2013-22 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef _NTOP_H_
#define _NTOP_H_

#include "config.h"

#if defined(__FreeBSD) || defined(__FreeBSD__)
#define _XOPEN_SOURCE
#define _WITH_GETLINE
#endif

#include <stdarg.h>
#include <stdio.h>

#ifdef WIN32
#include "ntop_win32.h"
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#if defined(__OpenBSD__)
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <sys/socket.h>
#include <sys/types.h>
#else
#include <net/ethernet.h>
#endif

#include <dirent.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <syslog.h>
#include <unistd.h>
#endif

#ifdef __linux__
#define __FAVOR_BSD
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zmq.h>
#ifndef WIN32
#include <grp.h>
#endif
//#include <libgen.h>
#if defined(__linux__)
#include <ifaddrs.h>
#include <linux/ethtool.h> // ethtool
#include <linux/sockios.h> // sockios
#elif defined(__FreeBSD__) || defined(__APPLE__)
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif
#ifdef __APPLE__
#include <uuid/uuid.h>
#endif

extern "C" {
#include "pcap.h"

#ifndef __linux__
#include <pcap/bpf.h> /* Used for bpf_filter() */
#endif

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "ndpi_api.h"
#ifdef HAVE_PF_RING
#include "pfring.h"
#include "pfring_zc.h"
#endif
#ifdef HAVE_NEDGE
#include <ifaddrs.h> /* SilicomHwBypass */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <linux/types.h>
#endif
#include "hiredis.h"
#include "json.h"
#include <sqlite3.h>
#ifdef HAVE_LDAP
#include <ldap.h>
#endif
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef WIN32
/*
See
https://translate.google.co.uk/translate?sl=auto&tl=en&u=http%3A%2F%2Fbugsfixed.blogspot.com%2F2017%2F05%2Fvcpkg.html
*/
#define CURL_STATICLIB
#endif
#include <curl/curl.h>

#ifdef WIN32
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wldap32.lib")
#endif

#ifdef HAVE_MYSQL
#include <errmsg.h>
#include <mysql.h>
#endif

#ifdef HAVE_MAXMINDDB
#include <maxminddb.h>
#endif

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#include <sys/prctl.h>
#endif
};

#include <fstream>
#include <map>
#include <unordered_map>

#if !defined(__clang__) && (__GNUC__ <= 4) && (__GNUC_MINOR__ < 8) &&          \
    !defined(WIN32)
#include <cstdatomic>
#else
#include <atomic>
#endif

#include <algorithm>
#include <iostream>
#include <list>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

using namespace std;

#include "AddressTree.h"
#include "Bitmap.h"
#include "Bitmask.h"
#include "Bloom.h"
#include "BroadcastDomains.h"
#include "Cardinality.h"
#include "ContinuousPing.h"
#include "ContinuousPingStats.h"
#include "DSCPStats.h"
#include "IpAddress.h"
#include "MDNS.h"
#include "MonitoredCounter.h"
#include "MonitoredGauge.h"
#include "MonitoredMetric.h"
#include "Mutex.h"
#include "PeerStats.h"
#include "Ping.h"
#include "RwLock.h"
#include "TcpPacketStats.h"
#include "TrafficStats.h"
#include "VLANAddressTree.h"
#include "mongoose.h"
#include "ntop_defines.h"
#if defined(NTOPNG_PRO)
#include "BinAnalysis.h"
#endif
#include "Alert.h"
#include "AlertableEntity.h"
#include "BehaviouralCounter.h"
#include "Bitmap128.h"
#include "FlowRiskAlerts.h"
#include "FrequentStringItems.h"
#include "HostAlertableEntity.h"
#include "InterfaceMemberAlertableEntity.h"
#include "MostVisitedList.h"
#include "NetworkInterfaceAlertableEntity.h"
#include "NtopGlobals.h"
#include "OtherAlertableEntity.h"
#include "ProtoStats.h"
#include "Score.h"
#include "ScoreStats.h"
#include "Trace.h"
#include "Utils.h"
#include "ViewScoreStats.h"
#include "ntop_typedefs.h"

#ifdef NTOPNG_PRO
#include "BehaviorAnalysis.h"
#endif

#include "FlowStats.h"
#include "InterarrivalStats.h"
#include "nDPIStats.h"
#ifdef NTOPNG_PRO
#include "CustomAppMaps.h"
#include "CustomAppStats.h"
#endif
#include "AlertCounter.h"
#include "ContainerStats.h"
#include "GenericTrafficElement.h"
#include "NetworkStats.h"
#include "ParsedFlow.h"
#include "ParsedFlowCore.h"
#include "ParsedeBPF.h"
#include "ThroughputStats.h"
#ifdef HAVE_EBPF
#include "ebpf_flow.h"
#endif

#ifdef NTOPNG_PRO
#include "AlertExclusions.h"
#include "AlertExclusionsInfo.h"
#include "CountMinSketch.h"
#include "Profile.h"
#include "Profiles.h"
#ifndef HAVE_NEDGE
#include "FlowProfile.h"
#include "FlowProfiles.h"
#include "SubInterface.h"
#include "SubInterfaces.h"
#endif
#include "CounterTrend.h"
#include "FlowInterfacesStats.h"
#include "LRUMacIP.h"
#ifdef HAVE_LDAP
#include "LdapAuthenticator.h"
#endif
#endif
#include "DnsStats.h"
#include "EthStats.h"
#include "Fingerprint.h"
#include "FlowGrouper.h"
#include "HostPoolStats.h"
#include "HostPools.h"
#include "ICMPinfo.h"
#include "ICMPstats.h"
#include "NetworkDiscovery.h"
#include "PacketStats.h"
#include "Prefs.h"
#include "RoundTripStats.h"
#include "SNMP.h"
#include "SerializableElement.h"
#include "SyslogStats.h"

#include "AlertStore.h"
#include "DB.h"
#include "LocalTrafficStats.h"
#include "PacketDumper.h"
#include "PacketDumperGeneric.h"
#include "PacketDumperTuntap.h"
#include "SQLiteAlertStore.h"
#include "SQLiteStoreManager.h"
#include "StatsManager.h"
#include "TcpFlowStats.h"
#include "TimelineExtract.h"
#ifdef HAVE_MYSQL
#include "MySQLDB.h"
#endif
#include "GenericHash.h"
#include "GenericHashEntry.h"
#include "InterfaceStatsHash.h"
#include "MacHash.h"
#ifdef HAVE_RADIUS
#include <radcli/radcli.h>
#endif

#include "AlertFifoQueue.h"
#include "AlertsQueue.h"
#include "Condvar.h"
#include "FifoQueue.h"
#include "FifoSerializerQueue.h"
#include "InfluxDBTimeseriesExporter.h"
#include "L4Stats.h"
#include "LuaEngine.h"
#include "LuaEngineFunctions.h"
#include "RRDTimeseriesExporter.h"
#include "RecipientQueues.h"
#include "Recipients.h"
#include "SPSCQueue.h"
#include "StringFifoQueue.h"
#include "SyslogLuaEngine.h"
#include "TimeseriesExporter.h"
#if defined(NTOPNG_PRO)
#include "PeriodicityHash.h"
#include "PeriodicityMap.h"
#include "PeriodicityStats.h"
#include "ServiceMap.h"
#endif
#include "NetworkInterface.h"
#include "ObservationPointIdTrafficStats.h"
#ifndef HAVE_NEDGE
#include "PcapInterface.h"
#endif
#include "ViewInterface.h"
#ifdef HAVE_PF_RING
#include "PF_RINGInterface.h"
#endif
#include "HTTPstats.h"
#include "Redis.h"
#include "VirtualHost.h"
#include "VirtualHostHash.h"
#ifndef HAVE_NEDGE
#include "ElasticSearch.h"
#ifndef WIN32
#include "SyslogDump.h"
#endif
#endif
#if defined(NTOPNG_PRO) && defined(HAVE_CLICKHOUSE)
#include "ClickHouseAlertStore.h"
#include "ClickHouseFlowDB.h"
#include "ClickHouseImport.h"
#endif
#ifdef NTOPNG_PRO
#include "DnsHostMapping.h"
#include "L7Policer.h"
#include "LuaHandler.h"
#include "NtopPro.h"
#include "TrafficShaper.h"
#ifdef HAVE_NEDGE
#include "HwBypass.h"
#include "NetfilterInterface.h"
#include "SilicomHwBypass.h"
#endif
#endif
#ifndef HAVE_NEDGE
#include "DummyInterface.h"
#include "ExportInterface.h"
#include "ListeningPorts.h"
#include "ParserInterface.h"
#include "SyslogCollectorInterface.h"
#include "SyslogParserInterface.h"
#include "ZCCollectorInterface.h"
#include "ZMQCollectorInterface.h"
#include "ZMQParserInterface.h"
#include "ZMQPublisher.h"
#endif

#include "AddressResolution.h"
#include "AutonomousSystem.h"
#include "AutonomousSystemHash.h"
#include "Check.h"
#include "ChecksLoader.h"
#include "CountriesHash.h"
#include "Country.h"
#include "Flow.h"
#include "FlowAlert.h"
#include "FlowAlertsLoader.h"
#include "FlowCheck.h"
#include "FlowChecksExecutor.h"
#include "FlowChecksLoader.h"
#include "FlowHash.h"
#include "FlowTrafficStats.h"
#include "Geolocation.h"
#include "HTTPserver.h"
#include "Host.h"
#include "HostAlert.h"
#include "HostCheck.h"
#include "HostChecksExecutor.h"
#include "HostChecksLoader.h"
#include "HostChecksStatus.h"
#include "HostHash.h"
#include "HostStats.h"
#include "IEC104Stats.h"
#include "LocalHost.h"
#include "LocalHostStats.h"
#include "Mac.h"
#include "MacManufacturers.h"
#include "MacStats.h"
#include "Ntop.h"
#include "ObservationPoint.h"
#include "ObservationPointHash.h"
#include "OperatingSystem.h"
#include "OperatingSystemHash.h"
#include "Paginator.h"
#include "PartializableFlowTrafficStats.h"
#include "PeriodicActivities.h"
#include "PeriodicScript.h"
#include "RemoteHost.h"
#include "ThreadPool.h"
#include "ThreadedActivity.h"
#include "ThreadedActivityStats.h"
#include "VLAN.h"
#include "VLANHash.h"
#include "ViewInterfaceFlowStats.h"

#ifdef NTOPNG_PRO
#include "ntoppro_defines.h"
#endif

#endif /* _NTOP_H_ */
