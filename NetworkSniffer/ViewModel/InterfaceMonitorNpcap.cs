using PacketDotNet;
using SharpPcap;

namespace NetworkSniffer.Model
{
    class InterfaceMonitorNpcap
    {
        private ILiveDevice device;

        public InterfaceMonitorNpcap(ILiveDevice liveDevice)
        {
            device = liveDevice;
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
        }

        public void StartPcapture()
        {
            var readTimeoutMilliseconds = 1000;

            device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);
            device.StartCapture();
        }

        public void StopCap()
        {
            device.StopCapture();
            device.Close();
        }

        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawCapture = e.GetPacket();
            var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

            if (packet is EthernetPacket eth)
            {
                var ipPacket = packet.Extract<PacketDotNet.IPPacket>();

                if (ipPacket != null)
                {
                    IPPacket newPacket = new IPPacket(ipPacket.Bytes, ipPacket.Bytes.Length);
                    if (newPacketEventHandler != null)
                    {
                        newPacketEventHandler(newPacket);
                    }
                }
            }
        }

        #region Event handlers
        public event NewPacketEventHandler newPacketEventHandler;

        public delegate void NewPacketEventHandler(IPPacket newPacket);
        #endregion
    }
}
