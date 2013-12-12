
from pox.core import core
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.recoco import Timer
from netaddr import IPNetwork
import pox.openflow.libopenflow_01 as of
import errno
import os

log = core.getLogger()



class Bongo(object):
  """
  A Bongo object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    # Store ARP entries here
    self.arp_table = {}

    self.unknown_neigh_announce = {}
    self.IXPSUB = "10.255.255.0/24"

    #these are necessary because exabgp doesn't log about it's own networks...
    self.protected_router_ip = "10.255.255.1"
    self.protected_router_networks = ['1.1.1.0/24']

    #set up rule so broadcast traffic doesn't come to the controller all of the time
    self.mac_to_port[of.EthAddr('FF:FF:FF:FF:FF:FF')] = of.OFPP_FLOOD

    fifo_path = '/tmp/exabgproutes'
    if not os.path.exists(fifo_path):
      os.mkfifo(fifo_path, 0777)
    self.bgpio = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)

    Timer(5, self.check_bgp, recurring = True)

 
  def check_bgp(self):
    try:
      BUFFER_SIZE = 65000
      buffer = os.read(self.bgpio, BUFFER_SIZE)
    except OSError as err:
      if err.errno == errno.EAGAIN or err.errno == errno.EWOULDBLOCK:
        buffer = None
      else:
        raise  # something else has happened -- better reraise

    if not buffer: 
      # nothing was received -- do something else
      #print "BGP QUIET"
      pass
    else:
      lines = buffer.split("\n")
      for line in lines:
        parts = line.split(' ')
        if len(parts)>6:
          neighbor = parts[1]
          try:
            network = IPNetwork(parts[4])
          except:
            pass
          if neighbor in self.arp_table.keys() and self.protected_router_ip in self.arp_table:
            print "generating rule to allow %s from %s" % (network, neighbor)
            self.allow_network_from_mac(network,
                                        self.arp_table[neighbor])
          else:
            print "Announcement for %s from unknown neighbor %s" % (network, neighbor)
            # collect unknowns to check later
            if neighbor not in self.unknown_neigh_announce:
              self.unknown_neigh_announce[neighbor] = []
            elif network not in self.unknown_neigh_announce[neighbor]:
              self.unknown_neigh_announce[neighbor].append(network)
    log.debug("checking for unknown neighbors")
    for nei in self.unknown_neigh_announce.keys():
       if nei in self.arp_table.keys():
         for upd in self.unknown_neigh_announce[nei]:
           try:
             self.allow_network_from_mac(upd, self.arp_table[nei])
           except KeyError as e:
             print "something broke"
             print e
             break
         del self.unknown_neigh_announce[nei]
       else:
         log.debug("%s is not in %s" %(nei, self.arp_table))      

  def allow_network_from_mac(self, network, src_mac):
      log.debug("Installing flow... source %s %s" % (network, src_mac))
      out_action = of.ofp_action_output(port = self.mac_to_port[self.arp_table[self.protected_router_ip]])
      match = of.ofp_match(dl_type = 0x800,
                           dl_src = src_mac,
                           nw_src = str(network))
      fm = of.ofp_flow_mod(match = match)
      fm.actions.append(out_action)
      fm.priority = 101
      self.connection.send(fm)
      for net in self.protected_router_networks:
          out_action = of.ofp_action_output(port = self.mac_to_port[src_mac])
          match = of.ofp_match(dl_type = 0x800,
                               dl_src = self.arp_table[self.protected_router_ip],
                               nw_src = net)
          fm = of.ofp_flow_mod(match = match)
          fm.actions.append(out_action)
          fm.priority = 101
          self.connection.send(fm)


  def send_packet (self, buffer_id, raw_data, out_port, in_port):
    """
    Sends a packet out of the specified switch port.
    If buffer_id is a valid buffer on the switch, use that.  Otherwise,
    send the raw data in raw_data.
    The "in_port" is the port number that packet arrived on.  Use
    OFPP_NONE if you're generating this packet.
    """
    msg = of.ofp_packet_out()
    msg.in_port = in_port
    if buffer_id != -1 and buffer_id is not None:
      # We got a buffer ID from the switch; use that
      msg.buffer_id = buffer_id
    else:
      # No buffer ID from switch -- we got the raw data
      if raw_data is None:
        # No raw_data specified -- nothing to send!
        return
      msg.data = raw_data

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """
    log.debug("packet: "+str(packet)+str(packet.src)+"=>"+str(packet.dst)+" Port:"+str(packet_in.in_port));

    # Learn the port for the source MAC
    self.mac_to_port[packet.src] = packet_in.in_port;

    if isinstance(packet.next, ipv4):
      srcnet = str(packet.next.srcip) + '/' +str(self.IXPSUB).split('/')[1]
      if IPNetwork(srcnet) == IPNetwork(self.IXPSUB):
          self.arp_table[str(packet.next.srcip)] = packet.src
      dstnet = str(packet.next.dstip) + '/' +str(self.IXPSUB).split('/')[1]
      if IPNetwork(dstnet) == IPNetwork(self.IXPSUB):
          self.arp_table[str(packet.next.dstip)] = packet.dst

    # we want all ARP packets
    if isinstance(packet.next, arp):
      a = packet.next
      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:
            self.arp_table[str(a.protosrc)] = packet.src
      self.send_packet(packet_in.buffer_id, packet_in.data,
                       of.OFPP_FLOOD, packet_in.in_port)
    elif packet.dst in self.mac_to_port:
      log.debug("Installing flow...")
      out_action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
      match = of.ofp_match(dl_type = 0x800,
                           dl_src = packet.src,
                           dl_dst = packet.dst,
                           nw_src = self.IXPSUB)
                           #nw_dst = self.IXPSUB)
      fm = of.ofp_flow_mod(match = match)
      fm.actions.append(out_action)
      fm.hard_timeout = 3000
      fm.priority = 100
      fm.buffer_id = packet_in.buffer_id
      self.connection.send(fm)

      log.debug("Installing mirror flow...")
      out_action = of.ofp_action_output(port = self.mac_to_port[packet.src])
      match = of.ofp_match(dl_type = 0x800,
                           dl_dst = packet.src,
                           dl_src = packet.dst,
                           nw_src = self.IXPSUB)
                           #nw_dst = self.IXPSUB)
      fm = of.ofp_flow_mod(match = match)
      fm.actions.append(out_action)
      fm.hard_timeout = 3000
      fm.priority = 100
      self.connection.send(fm)


      log.debug("Blocking other IP")
      out_action = of.ofp_action_output(port = of.OFPP_NONE)
      match = of.ofp_match(dl_type = 0x800,
                           dl_src = packet.src,
                           dl_dst = packet.dst)
      fm = of.ofp_flow_mod(match = match)
      fm.actions.append(out_action)
      fm.hard_timeout = 3000
      fm.priority = 80
      self.connection.send(fm)

      log.debug("Mirror blocking other IP")
      out_action = of.ofp_action_output(port = of.OFPP_NONE)
      match = of.ofp_match(dl_type = 0x800,
                           dl_dst = packet.src,
                           dl_src = packet.dst)
      fm = of.ofp_flow_mod(match = match)
      fm.actions.append(out_action)
      fm.hard_timeout = 3000
      fm.priority = 80
      self.connection.send(fm)

      log.debug("Allowing non-IP")
      out_action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
      match = of.ofp_match(dl_src = packet.src,
                           dl_dst = packet.dst)
      fm = of.ofp_flow_mod(match = match)
      fm.actions.append(out_action)
      fm.hard_timeout = 3000
      fm.priority = 60
      self.connection.send(fm)

      log.debug("Mirror allowing non-IP")
      out_action = of.ofp_action_output(port = self.mac_to_port[packet.src])
      match = of.ofp_match(dl_dst = packet.src,
                           dl_src = packet.dst)
      fm = of.ofp_flow_mod(match = match)
      fm.actions.append(out_action)
      fm.hard_timeout = 3000
      fm.priority = 60
      self.connection.send(fm)

    else:
      log.debug("Don't know where to send")
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.send_packet(packet_in.buffer_id, packet_in.data,
                       of.OFPP_FLOOD, packet_in.in_port)



  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Bongo(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
