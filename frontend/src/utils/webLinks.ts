import type { Host, Port } from '../services/api';

export interface HostWebLink {
  protocol: 'http' | 'https';
  url: string;
  port: number;
  label: string;
}

const HTTPS_PORTS = new Set([443, 8443, 9443, 9444, 4443]);
const HTTP_PORTS = new Set([80, 8080, 8081, 8000, 8008, 8888, 9090, 8181]);

const isOpenPort = (port: Port) => port.state?.toLowerCase() === 'open';

const isLikelyHttps = (port: Port) => {
  if (HTTPS_PORTS.has(port.port_number)) {
    return true;
  }
  const name = port.service_name?.toLowerCase() || '';
  return name.includes('https') || name.includes('ssl');
};

const isLikelyHttp = (port: Port) => {
  if (HTTP_PORTS.has(port.port_number)) {
    return true;
  }
  const name = port.service_name?.toLowerCase() || '';
  if (name.includes('https')) {
    return false;
  }
  return name.includes('http') || name.includes('web');
};

const buildUrl = (hostLabel: string, protocol: 'http' | 'https', port: number) => {
  const defaultPort = protocol === 'https' ? 443 : 80;
  const portSuffix = port === defaultPort ? '' : `:${port}`;
  return `${protocol}://${hostLabel}${portSuffix}`;
};

export const getHostWebLinks = (host: Host): HostWebLink[] => {
  const ports = host.ports?.filter(isOpenPort) ?? [];
  if (!ports.length) {
    return [];
  }

  const hostLabel = (host.hostname && host.hostname.trim()) || host.ip_address;
  if (!hostLabel) {
    return [];
  }

  const links: HostWebLink[] = [];
  const seen = new Set<string>();

  ports.forEach((port) => {
    if (isLikelyHttps(port)) {
      const key = `https-${port.port_number}`;
      if (!seen.has(key)) {
        seen.add(key);
        links.push({
          protocol: 'https',
          port: port.port_number,
          url: buildUrl(hostLabel, 'https', port.port_number),
          label: `${hostLabel}${port.port_number === 443 ? '' : `:${port.port_number}`}`,
        });
      }
    }
  });

  ports.forEach((port) => {
    if (isLikelyHttp(port)) {
      const key = `http-${port.port_number}`;
      if (!seen.has(key)) {
        seen.add(key);
        links.push({
          protocol: 'http',
          port: port.port_number,
          url: buildUrl(hostLabel, 'http', port.port_number),
          label: `${hostLabel}${port.port_number === 80 ? '' : `:${port.port_number}`}`,
        });
      }
    }
  });

  return links.sort((a, b) => {
    if (a.protocol !== b.protocol) {
      return a.protocol === 'https' ? -1 : 1;
    }
    return a.port - b.port;
  });
};
