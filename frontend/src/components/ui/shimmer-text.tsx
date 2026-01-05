import React from "react";
import { cn } from "@/lib/utils";

interface ShimmerTextProps {
  text: string;
  className?: string;
  shimmer?: boolean;
  speed?: number;
  as?: React.ElementType;
}

export const ShimmerText: React.FC<ShimmerTextProps> = ({
  text,
  className,
  shimmer = true,
  speed = 3,
  as: Component = "span",
}) => {
  if (!shimmer) {
    return <Component className={className}>{text}</Component>;
  }

  return (
    <Component
      className={cn(
        "inline-block bg-gradient-to-r from-slate-600 via-slate-200 to-slate-600 dark:from-slate-400 dark:via-white dark:to-slate-400 bg-clip-text text-transparent bg-[length:200%_100%] animate-shimmer",
        className
      )}
      style={{
        backgroundSize: "200% 100%",
        animation: `shimmer ${speed}s linear infinite`,
      }}
    >
      {text}
    </Component>
  );
};
