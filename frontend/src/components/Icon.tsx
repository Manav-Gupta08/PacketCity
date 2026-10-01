const PATHS = {
  live: "M3 12h4l2-6 4 12 2-6h6",
  car: "M5 16l1.5-5.5A2 2 0 0 1 8.4 9h7.2a2 2 0 0 1 1.9 1.5L19 16M4 16h16v3H4zM7 19v1.5M17 19v1.5",
  connections: "M6 6a2 2 0 1 0 0 .01M18 6a2 2 0 1 0 0 .01M12 18a2 2 0 1 0 0 .01M7.5 7.5l3.5 8.5M16.5 7.5L13 16M8 6h8",
  devices: "M3 5h18v11H3zM8 20h8M12 16v4",
  protocols: "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5",
  alerts: "M6 17V11a6 6 0 1 1 12 0v6l1.5 2h-15zM10 21h4",
  pcap: "M4 5h16v14H4zM7 9l3 3-3 3M12 15h5",
  stats: "M5 19V11M10 19V6M15 19v-5M20 19V9",
  settings: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1",
  packets: "M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12L4 7.5",
  down: "M12 4v14M6 12l6 6 6-6",
  up: "M12 20V6M6 12l6-6 6 6",
  search: "M11 5a6 6 0 1 0 0 12 6 6 0 0 0 0-12zM20 20l-4.5-4.5",
  close: "M6 6l12 12M18 6L6 18",
  fit: "M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5",
  plus: "M12 5v14M5 12h14",
  minus: "M5 12h14",
  pause: "M8 5v14M16 5v14",
  play: "M7 5l12 7-12 7z",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6",
  shield: "M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6zM12 8v5M12 16v.01",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d={PATHS[name]} />
    </svg>
  );
}
