//este es mi file myAttack para representar un ataque de sniffing con escucha pasivo
//en una red wifi sencilla mediante la captura de paquetes pcap como en wireshark

#include "ns3/netanim-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ssid.h"
#include "ns3/yans-wifi-helper.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("MyAttack");
// Network
//
//   Wifi 10.1.2.0
//              	   AP
//  * 	*    *    *
//  |   |    |    |    10.1.1.0
// n5  n6   n7   n0 ------------ n1   n2 n3
//      *             	P a P     |    | |
//      |                          =======
//      n8 sniffer               LAN 10.1.3.0



int
main(int argc, char* argv[]){

//variables nodos tutoriales 5-7 ns-3 documentacion
uint32_t nCsma=2;
uint32_t nWifi=3;

//log de los mensajes cliente servidor de level info para arriba
LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

//creamos los nodos punto a punto
NodeContainer p2pNodes;
p2pNodes.Create(2);

//helper para la conexion pap
PointToPointHelper pTp;
pTp.SetDeviceAttribute("DataRate", StringValue("5Mbps"));//vt
pTp.SetChannelAttribute("Delay", StringValue("2ms")); //vp

NetDeviceContainer p2pDevices;
p2pDevices = pTp.Install(p2pNodes); //nic

NodeContainer csmaNodes;
csmaNodes.Add(p2pNodes.Get(1));//del canal pap de la LAN
csmaNodes.Create(nCsma);

CsmaHelper csma;//medidas de la documentacion
csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));

NetDeviceContainer csmaDevices; //red bus
csmaDevices = csma.Install(csmaNodes);

//la parte de la wifi
//nodo 8 sniffer
NodeContainer snifferNode;
snifferNode.Create(1);

NodeContainer wifiStaNodes;
wifiStaNodes.Create(nWifi);

NodeContainer wifiApNode = p2pNodes.Get(0);

YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
YansWifiPhyHelper phy;
phy.SetChannel(channel.Create());

WifiMacHelper mac;
Ssid ssid = Ssid("ns-3-ssid");

WifiHelper wifi;

NetDeviceContainer staDevices;
mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
staDevices = wifi.Install(phy, mac, wifiStaNodes);

NetDeviceContainer apDevices;
mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
apDevices = wifi.Install(phy, mac, wifiApNode);

NetDeviceContainer snifferDevice;
mac.SetType("ns3::AdhocWifiMac");
snifferDevice = wifi.Install(phy, mac, snifferNode);

//Se pretende con este helper simular el desplazamientos de los dispositivos en el espacio
//randomwalk es para que se muevan. Esto forma parte del ejemplo third
// El AP se mantiene estatico
MobilityHelper mobility;

mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                          "MinX",
                          DoubleValue(0.0),
                          "MinY",
                          DoubleValue(0.0),
                          "DeltaX",
                          DoubleValue(5.0),
                          "DeltaY",
                          DoubleValue(10.0),
                          "GridWidth",
                          UintegerValue(3),
                          "LayoutType",
                          StringValue("RowFirst"));

mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel","Bounds",
                              RectangleValue(Rectangle(-50, 50, -50, 50)));
mobility.Install(wifiStaNodes);
mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
mobility.Install(wifiApNode);
mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
mobility.Install(snifferNode);
mobility.Install(csmaNodes);


InternetStackHelper stack;
stack.Install(csmaNodes);
stack.Install(wifiApNode);
stack.Install(wifiStaNodes);

Ipv4AddressHelper address;

address.SetBase("10.1.1.0", "255.255.255.0");
Ipv4InterfaceContainer p2pInterfaces;
p2pInterfaces = address.Assign(p2pDevices);

address.SetBase("10.1.2.0", "255.255.255.0");
Ipv4InterfaceContainer csmaInterfaces;
csmaInterfaces = address.Assign(csmaDevices);

address.SetBase("10.1.3.0", "255.255.255.0");
address.Assign(staDevices);
address.Assign(apDevices);

UdpEchoServerHelper echoServer(9);

ApplicationContainer serverApps = echoServer.Install(csmaNodes.Get(nCsma));
serverApps.Start(Seconds(1.0));
serverApps.Stop(Seconds(10.0));

UdpEchoClientHelper echoClient(csmaInterfaces.GetAddress(nCsma), 9);
echoClient.SetAttribute("MaxPackets", UintegerValue(1)); //no se si cambiarlo. Va a ser una simulacion de 30 seg
echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
echoClient.SetAttribute("PacketSize", UintegerValue(1024));

ApplicationContainer clientApps = echoClient.Install(wifiStaNodes.Get(nWifi - 1));
clientApps.Start(Seconds(2.0));
clientApps.Stop(Seconds(10.0));

Ipv4GlobalRoutingHelper::PopulateRoutingTables();

//captura de eventos??
Simulator::Stop(Seconds(11.0));

phy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);
pTp.EnablePcapAll("attack");
phy.EnablePcap("sniffer", snifferDevice.Get(0),true);
phy.EnablePcap("attack", apDevices.Get(0));
csma.EnablePcap("attack", csmaDevices.Get(0), true);

AnimationInterface anim("Sniffer.xml");
ns3::AnimationInterface::SetConstantPosition(wifiStaNodes.Get(nWifi-1),0,5);
ns3::AnimationInterface::SetConstantPosition(wifiStaNodes.Get(nWifi-2),5,5);
ns3::AnimationInterface::SetConstantPosition(wifiStaNodes.Get(0),10,5);
ns3::AnimationInterface::SetConstantPosition(wifiApNode.Get(0),15,5);
ns3::AnimationInterface::SetConstantPosition(csmaNodes.Get(0),30,5);
ns3::AnimationInterface::SetConstantPosition(csmaNodes.Get(1),35,5);
ns3::AnimationInterface::SetConstantPosition(csmaNodes.Get(2),40,5);
ns3::AnimationInterface::SetConstantPosition(snifferNode.Get(0),5,15);


Simulator::Run();
Simulator::Destroy();
return 0;
}
