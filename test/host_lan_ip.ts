// Host's LAN-facing IP address (e.g. en0), for URLs a container must call
// back into the host. The container network's own gateway IP (bridge100 on
// macOS `container`) IS the host, but macOS does not hairpin-NAT a host
// process dialing its own bridge interface address — only the LAN-facing
// interface reliably round-trips host-to-self while still being routable
// from inside a container via the bridge gateway's forwarding.
export async function getHostLanIp(): Promise<string> {
  const routeCmd = new Deno.Command("route", { args: ["get", "1.1.1.1"], stdout: "piped", stderr: "null" });
  const routeOut = new TextDecoder().decode((await routeCmd.output()).stdout);
  const ifaceMatch = routeOut.match(/interface: (\S+)/);
  if (!ifaceMatch) throw new Error("could not determine default route interface");
  const iface = ifaceMatch[1];

  const ifconfigCmd = new Deno.Command("ifconfig", { args: [iface], stdout: "piped", stderr: "null" });
  const ifconfigOut = new TextDecoder().decode((await ifconfigCmd.output()).stdout);
  const ipMatch = ifconfigOut.match(/inet (\d+\.\d+\.\d+\.\d+)/);
  if (!ipMatch) throw new Error(`no inet address found on interface ${iface}`);
  return ipMatch[1];
}
