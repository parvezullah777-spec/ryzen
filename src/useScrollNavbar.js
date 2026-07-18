import { useEffect, useState } from "react";

/**
 * Returns a boolean you attach as a class toggle on your EXISTING navbar:
 *   const scrolled = useScrollNavbar();
 *   <nav className={`your-existing-classes ryzen-navbar ${scrolled ? "is-scrolled" : ""}`}>
 *
 * Doesn't touch your nav's markup or links — just tells you when to
 * flip the glass/solid state.
 */
export function useScrollNavbar(threshold = 40) {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    let ticking = false;
    const onScroll = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          setScrolled(window.scrollY > threshold);
          ticking = false;
        });
        ticking = true;
      }
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, [threshold]);

  return scrolled;
}
