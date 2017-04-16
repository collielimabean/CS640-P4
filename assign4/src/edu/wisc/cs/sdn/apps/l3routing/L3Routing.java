package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;

public class L3Routing implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener
{
    public static final String MODULE_NAME = L3Routing.class.getSimpleName();
	
    // Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;
    

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Initialize variables or perform startup tasks, if necessary */
		/*********************************************************************/
	}
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() == null)
			return;
		
		log.info(String.format("Host %s added", host.getName()));
		this.knownHosts.put(device, host);
		
		/*****************************************************************/
		/* TODO: Update routing: add rules to route to new host          */
		this.installRulesToHost(host);
		/*****************************************************************/
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
			return;
		this.knownHosts.remove(device);
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		this.removeRulesFromHost(host);
		/*********************************************************************/
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		this.removeRulesFromHost(host);
		this.installRulesToHost(host);
		/*********************************************************************/
	}
	
    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		for (Host host : this.getHosts())
		{
			this.removeRulesFromHost(host);
			this.installRulesToHost(host);
		}
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		for (Host host : this.getHosts())
		{
			this.removeRulesFromHost(host);
			this.installRulesToHost(host);
		}
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> s%s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Executes Bellman-Ford algorithm on current switch network.
	 *  
	 * @param start Switch from which to execute 
	 * @return Switch DPID -> Distance from given switch
	 */
	private Map<Long, Integer> runBellmanFordAlgorithm(IOFSwitch start)
	{
		Map<Long, Integer> bestRouteDistMap = new ConcurrentHashMap<>();
		Map<Long, Integer> bestRoutePorts = new ConcurrentHashMap<>();
		Queue<Long> swToProcess = new LinkedBlockingQueue<>();
		
		// init graph to infinity (-1) in this case
		for (Map.Entry<Long, IOFSwitch> pair : this.getSwitches().entrySet())
			bestRouteDistMap.put(pair.getKey(), -1);
		
		// current switch has weight of zero
		bestRouteDistMap.put(start.getId(), 0);
		
		// main iteration //
		swToProcess.add(start.getId());
		while (!swToProcess.isEmpty())
		{
			long sw_id = swToProcess.remove();
			
			// get all links connected to the switch //
			List<Link> sw_links = new ArrayList<Link>();
			for (Link l : this.getUniqueLinks())
				if (l.getSrc() == sw_id || l.getDst() == sw_id)
					sw_links.add(l);
			
			// loop over connected links //
			for (Link link : sw_links)
			{
				// is the switch at the link src or dest?
				// have to check since links are bidirectional
				boolean is_src = (sw_id == link.getSrc());
				
				// the other switch ID
				long other_sw = (is_src) ? link.getDst() : link.getSrc();
				
				// current distance to the switch with id "sw_id"
				int distToSwitch = bestRouteDistMap.get(sw_id);
				
				// current distance to the swithc with id "other_sw"
				int currDistToOtherSwitch = (is_src) ? bestRouteDistMap.get(link.getSrc()) 
						: bestRouteDistMap.get(link.getDst());
				
				// what's the distance to the sw right next to us?
				// if the current distance is bigger than ours + 1, then
				// we have a better path. 
				if (currDistToOtherSwitch > distToSwitch + 1)
				{
					bestRouteDistMap.put(other_sw, distToSwitch + 1);
					bestRoutePorts.put(other_sw, (is_src) ? link.getDstPort() : link.getSrcPort()); 
				}
				
				// in any case, we need to process this new switch
				swToProcess.add(other_sw);
			}
		}
		
		// in order to install the routes, we need to know the map between
		// DPID and ports. So we return this map.
		return bestRoutePorts;
	}
	
	private List<Link> getUniqueLinks()
	{
		List<Link> unique_links = new ArrayList<Link>();
		for (Link l : this.getLinks())
		{
			for (Link ul : unique_links)
			{
				boolean same_dir_match = (l.getDst() == ul.getDst()) && (l.getSrc() == ul.getSrc());
				boolean opp_dir_match = (l.getDst() == ul.getSrc()) && (l.getSrc() == ul.getDst());
				
				if (same_dir_match || opp_dir_match)
					break;
			}
			
			unique_links.add(l);
		}
		
		return unique_links;
	}
	
	private void installRulesToHost(Host host)
	{
		if (!host.isAttachedToSwitch())
			return;
		
		Map<Long, Integer> bestRoute = this.runBellmanFordAlgorithm(host.getSwitch());
		for (long sw_id : bestRoute.keySet())
		{
			OFAction action = new OFActionOutput(bestRoute.get(sw_id));
			OFInstruction instr = new OFInstructionApplyActions(Arrays.asList(action));

			
			boolean success = SwitchCommands.installRule(
				this.getSwitches().get(sw_id), 
				table,
				SwitchCommands.DEFAULT_PRIORITY,
				this.getMatchCriterion(host),
				Arrays.asList(instr)
			);
			
			System.out.println(success + " installing rule on switch: " 
					+ this.getSwitches().get(sw_id) + " | ID: " + sw_id);
		}
	}
	
	private void removeRulesFromHost(Host host)
	{
		for (IOFSwitch sw : this.getSwitches().values())
			SwitchCommands.removeRules(sw, table, getMatchCriterion(host));
	}
	
	private OFMatch getMatchCriterion(Host host)
	{
		OFMatch match = new OFMatch();
		match.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		match.setNetworkDestination(host.getIPv4Address());
		return match;
	}
	
	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(ILinkDiscoveryService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}
}
