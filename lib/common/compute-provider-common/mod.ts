export const ON_BEHALF_OF_HEADER = "x-on-behalf-of";

export const COMPUTE_VM_NSID = "com.publicdomainrelay.temp.compute.vm";

export function serviceDidFromUrl(url: string): string {
  return `did:web:${new URL(url).host}`;
}
