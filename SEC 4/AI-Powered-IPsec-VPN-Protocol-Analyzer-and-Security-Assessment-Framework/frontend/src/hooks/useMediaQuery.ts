import { useEffect, useState } from 'react';

/** Subscribe to a CSS media query from React. */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    typeof window === 'undefined' ? false : window.matchMedia(query).matches,
  );

  useEffect(() => {
    const list = window.matchMedia(query);
    const onChange = (event: MediaQueryListEvent) => setMatches(event.matches);

    setMatches(list.matches);
    list.addEventListener('change', onChange);
    return () => list.removeEventListener('change', onChange);
  }, [query]);

  return matches;
}

/** True on viewports narrower than the `lg` breakpoint. */
export function useIsCompactViewport(): boolean {
  return useMediaQuery('(max-width: 1023px)');
}
