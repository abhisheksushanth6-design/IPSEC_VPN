import type { LucideIcon } from 'lucide-react';

/** A single destination in the sidebar. */
export interface NavigationItem {
  label: string;
  path: string;
  icon: LucideIcon;
  /** Short sentence used for tooltips and the module placeholder. */
  description: string;
}

/** A titled cluster of navigation items. */
export interface NavigationGroup {
  /** Omitted for the ungrouped top-level entry. */
  title?: string;
  items: NavigationItem[];
}
