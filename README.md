### Description ###

Profinet is an industrial Ethernet standard for automation, providing a platform for data exchange between industrial controllers and devices. It supports real-time data transfer, is highly scalable, and allows for seamless integration with other networks and systems in industrial environments.

This script simulates some the following profinet communication channels listed below at the network flow level without actual meaningful packet payload. 

1. Real-time (RT) communication:
Simulation: Flows between the IO-Controller VM and each IO-Device(s) VM(s). The IO-Controller sends a packet containing the mock "RT_L2_Ctrl_to_Devices" payload, which the IO-Devices detect and respond to the IO-Controller with "RT_L2_Ack_Device_to_Ctrl" packet. In a real production environment, RT communication happens between PROFINET Controllers like PLCs and IO-Devices. It is cyclic and ensures data exchange in real-time intervals. This communication bypasses the IP and UDP layers, operating directly on Ethernet for low latency.

2. PROFINET Communication Channel (PN-CC):
Simulation: Flows between the IO-Controller VM and an IO-Device(s) VM(s). The IO-Controller sends a packet with the mock "PNCC_UDP_Ctrl_to_Devices" payload to the IO-Device, which the IO-Devices detect and respond to the IO-Controller with "PNCC_UDP_Device_to_Ctrl" packet. In a real production environment, PN-CC is used for acyclic data exchanges, like parameterization or diagnostics. It typically flows between a PROFINET Controller and IO-Device, often over UDP.

3. PROFINET Discovery and Basic Configuration Protocol (PN-DCP):
Simulation: The IO-Controller VM broadcasts a packet with the mock "DCP_Bcast_Discovery_Ctrl_to_Devices" payload. IO-Devices respond to this broadcast with a unicast to controller "DCP_Bcast_Discovery_Ack_Device_to_Ctrl" packet. In a real production environment,PN-DCP is used for basic device configuration, IP setting, and network discovery. It flows between PROFINET devices and controllers or engineering stations. The communication is typically a multicast or broadcast on the Ethernet layer.

4. Alarm Handling:
Simulation: The IO-Device VM sends a packet with the mock "Alarm_Device_to_Ctrl" payload to an IO-Controller VM, simulating that an alarm condition is being signaled. In a real production environment, Alarm messages flow between PROFINET IO-Devices and Controllers. If a device encounters an error or a specific event, it sends an alarm to the controller. These alarms are typically handled over UDP.

### Installation instructions ###

1. Clone the Repository:
git clone https://github.com/kmikholap/profi-sim

2. Setup Virtual Enviroment (Optional):<br>
python -m venv profivenv<br>
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3. Install requirements:<br>
pip install -r requirements.txt

4. Data:<br>
Ensure "devices.yaml" file is in the same directory as main python script "profinet-sim.py". Modify devices.yaml as desired (see usage example)




### Usage example ###

1. Deploy VM. 

2. Follow installation instructions above.

3. Ensure "devices.yaml" file is in the same directory as main python script "profinet-sim.py". Modify devices.yaml as desired:

- Adjust protocol section values if needed.
- In the "devices" section specify Controller and IO devices. Included test YAML file implies simulation with (1) Controller and (2) IO-Devices. 
- In the "devices" section, for each device (Controller and IO) specify correct configuration parameters for the Mac and IP addresses, interface used for sending packets, device role and name.
- In the "devices" section, adjust value of "this:" to correspond to the device this script is being run on.<br>
For example, if you are running this script on the device that will be acting as Controller, then "this:" needs to be set to "true" under controller configuration while for all other devices need to have "this:" value set to false. Likewise, if you are running this script on the device that will be acting as an IO VM, then "this:" needs to be set to "true" under this IO device configuration while for all other devices (Controllers and IOs) need to have "this:" value set to false

4. Run:
- if you are root:<br>
python main.py

- if not root AND running in virtual enviroment, use sudo and specify path to the virtual enviroment python:<br>
sudo -E ~/Python/env/profinet/bin/python3 profi-sim.py