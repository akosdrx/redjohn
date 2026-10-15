import { cn } from "../utils.js";
import { strings } from "../strings.js";

/** Approved RedJohn logo asset path (within this package). */
export const LOGO_ASSET = "redjohn-logo.png";

export interface LogoProps {
  /** Resolved URL of the logo asset (host app bundles it). */
  src: string;
  size?: number;
  withName?: boolean;
  className?: string;
}

export function Logo({ src, size = 28, withName = true, className }: LogoProps) {
  return (
    <span className={cn("flex items-center gap-2", className)}>
      <img src={src} width={size} height={size} alt="" aria-hidden="true" className="rounded-md" />
      {withName && <span className="text-[16px] font-semibold tracking-tight text-rj-text">{strings.appName}</span>}
    </span>
  );
}
