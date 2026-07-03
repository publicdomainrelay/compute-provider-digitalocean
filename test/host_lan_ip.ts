// Host's LAN-facing IP address, for URLs a container must call back into the
// host. On macOS the container network's gateway IP (bridge100) IS the host,
// but the host cannot hairpin-NAT its own bridge interface address — only the
// LAN-facing interface reliably round-trips host-to-self while still being
// routable from inside a container via the bridge gateway's forwarding.
// Docker on Linux/Windows does not have this limitation, but the same IP
// works for all platforms.

async function darwinLanIp(): Promise<string> {
  const routeCmd = new Deno.Command("route", { args: ["get", "1.1.1.1"], stdout: "piped", stderr: "null" });
  const routeOut = new TextDecoder().decode((await routeCmd.output()).stdout);
  const ifaceMatch = routeOut.match(/interface: (\S+)/);
  if (!ifaceMatch) throw new Error("could not determine default route interface");
  let iface = ifaceMatch[1];

  // VPN tunnel interfaces (utun*) aren't reachable from inside a container VM.
  // Fall back to a physical Ethernet interface.
  if (iface.startsWith("utun")) {
    const listCmd = new Deno.Command("ifconfig", { args: ["-l"], stdout: "piped", stderr: "null" });
    const listOut = new TextDecoder().decode((await listCmd.output()).stdout);
    const physical = listOut.split(/\s+/).find((i: string) => /^en\d+$/.test(i));
    if (physical) iface = physical;
  }

  const ifconfigCmd = new Deno.Command("ifconfig", { args: [iface], stdout: "piped", stderr: "null" });
  const ifconfigOut = new TextDecoder().decode((await ifconfigCmd.output()).stdout);
  const ipMatch = ifconfigOut.match(/inet (\d+\.\d+\.\d+\.\d+)/);
  if (!ipMatch) throw new Error(`no inet address found on interface ${iface}`);
  return ipMatch[1];
}

async function linuxLanIp(): Promise<string> {
  // Try iproute2 first
  try {
    const ipCmd = new Deno.Command("ip", { args: ["-o", "route", "get", "1.1.1.1"], stdout: "piped", stderr: "null" });
    const ipOut = new TextDecoder().decode((await ipCmd.output()).stdout);
    const srcMatch = ipOut.match(/src (\d+\.\d+\.\d+\.\d+)/);
    if (srcMatch) return srcMatch[1];
  } catch { /* fall through */ }
  // Fallback: hostname -I (works on Alpine, any POSIX)
  const hnCmd = new Deno.Command("hostname", { args: ["-I"], stdout: "piped", stderr: "null" });
  const hnOut = new TextDecoder().decode((await hnCmd.output()).stdout).trim();
  const first = hnOut.split(/\s+/)[0];
  if (first && /^\d+\.\d+\.\d+\.\d+$/.test(first)) return first;
  throw new Error("could not determine LAN IP on Linux");
}

async function windowsLanIp(): Promise<string> {
  const psCmd = new Deno.Command("powershell", {
    args: [
      "-NoProfile", "-Command",
      "$ifIndex = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1).InterfaceIndex; " +
      "if ($ifIndex) { (Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4).IPAddress } " +
      "else { (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { " +
        "$_.AddressState -eq 'Preferred' -and $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notlike '169.254.*' " +
      "}).IPAddress | Select-Object -First 1 }",
    ],
    stdout: "piped", stderr: "null",
  });
  const psOut = new TextDecoder().decode((await psCmd.output()).stdout).trim();
  if (!psOut) throw new Error("could not determine LAN IP on Windows");
  return psOut;
}

export async function getHostLanIp(): Promise<string> {
  const os = Deno.build.os;
  if (os === "darwin") return darwinLanIp();
  if (os === "linux") return linuxLanIp();
  if (os === "windows") return windowsLanIp();
  throw new Error(`unsupported OS: ${os}`);
}
