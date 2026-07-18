import React, { useRef } from "react";

/**
 * Wraps an EXISTING button/link so it subtly follows the cursor on hover
 * (a "magnetic" pull), then springs back. Doesn't replace your button's
 * onClick, href, or styling — just adds the motion layer around it.
 *
 * Usage:
 *   <MagneticButton><YourExistingAddToCartButton /></MagneticButton>
 */
export default function MagneticButton({ children, strength = 0.3, className = "" }) {
  const ref = useRef(null);

  const onMouseMove = (e) => {
    const node = ref.current;
    if (!node) return;
    const rect = node.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;
    node.style.transform = `translate3d(${x * strength}px, ${y * strength}px, 0)`;
  };

  const onMouseLeave = () => {
    const node = ref.current;
    if (!node) return;
    node.style.transform = "translate3d(0, 0, 0)";
  };

  return (
    <div
      ref={ref}
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
      className={`ryzen-anim-layer inline-block transition-transform duration-200 ease-out ${className}`}
    >
      {children}
    </div>
  );
}
