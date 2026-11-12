import type { ElementType, ReactNode } from "react";

/** Server component: emits data attributes the Motion engine animates. */
export function Reveal({
  children,
  as: Tag = "div",
  type = "up",
  delay = 0,
  className = "",
}: {
  children: ReactNode;
  as?: ElementType;
  type?: "up" | "mask" | "fade";
  delay?: number; // milliseconds
  className?: string;
}) {
  return (
    <Tag data-reveal={type} data-delay={delay.toString()} className={className}>
      {children}
    </Tag>
  );
}
