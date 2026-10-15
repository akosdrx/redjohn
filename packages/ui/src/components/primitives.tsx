import { Children, forwardRef, isValidElement, useEffect, useId, useImperativeHandle, useRef, useState, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { createPortal } from "react-dom";
import { cn } from "../utils.js";

/* ------------------------------------------------------------------ */
/* Panel                                                               */
/* ------------------------------------------------------------------ */

export interface PanelProps extends Omit<HTMLAttributes<HTMLDivElement>, "title"> {
  title?: ReactNode;
  headerRight?: ReactNode;
  padded?: boolean;
}

export function Panel({ title, headerRight, padded = false, className, children, ...rest }: PanelProps) {
  return (
    <section
      className={cn(
        "rounded-lg border border-rj-border bg-rj-panel min-w-0 flex flex-col",
        className,
      )}
      {...rest}
    >
      {(title != null || headerRight != null) && (
        <header className="flex items-center justify-between gap-2 border-b border-rj-border px-3 py-2">
          <h2 className="text-[13px] font-medium text-rj-text">{title}</h2>
          {headerRight != null && <div className="flex items-center gap-2 text-rj-text-3">{headerRight}</div>}
        </header>
      )}
      <div className={cn("flex-1 min-h-0", padded && "p-3")}>{children}</div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost" | "outline" | "danger";
  size?: "sm" | "md";
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "ghost", size = "md", className, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors",
        "disabled:opacity-50 disabled:pointer-events-none cursor-pointer",
        size === "sm" ? "h-7 px-2.5 text-[12px]" : "h-8 px-3 text-[13px]",
        variant === "primary" &&
          "bg-rj-accent-strong text-white hover:bg-rj-accent active:bg-rj-accent",
        variant === "ghost" && "text-rj-text-2 hover:bg-rj-panel-hover hover:text-rj-text",
        variant === "outline" &&
          "border border-rj-border-strong text-rj-text hover:bg-rj-panel-hover",
        variant === "danger" && "text-rj-down hover:bg-rj-accent-subtle",
        className,
      )}
      {...rest}
    />
  );
});

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

const fieldClass =
  "w-full rounded-md border border-rj-border-strong bg-rj-panel-sunken px-2.5 text-[13px] text-rj-text placeholder:text-rj-text-3 hover:border-rj-border-strong focus:border-rj-accent outline-none";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return <input ref={ref} className={cn(fieldClass, "h-8", className)} {...rest} />;
  },
);

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  function Textarea({ className, ...rest }, ref) {
    return <textarea ref={ref} className={cn(fieldClass, "py-2 min-h-20", className)} {...rest} />;
  },
);

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, children, value, defaultValue, disabled, id, style, ...rest }, ref) {
    const native = useRef<HTMLSelectElement>(null);
    const trigger = useRef<HTMLButtonElement>(null);
    const popup = useRef<HTMLDivElement>(null);
    const listId = useId();
    const [open, setOpen] = useState(false);
    const [active, setActive] = useState(0);
    const [position, setPosition] = useState({ left: 0, top: 0, width: 0, maxHeight: 240 });
    const [internal, setInternal] = useState(String(defaultValue ?? ""));
    const search = useRef({ text: "", time: 0 });
    const options: Array<{ value: string; label: ReactNode; text: string; disabled: boolean }> = [];
    function collect(nodes: ReactNode): void {
      Children.forEach(nodes, (node) => {
        if (!isValidElement<{ value?: string | number; disabled?: boolean; children?: ReactNode }>(node)) return;
        if (node.type === "option") {
          const text = Children.toArray(node.props.children).join("");
          options.push({ value: String(node.props.value ?? text), label: node.props.children, text, disabled: !!node.props.disabled });
        } else collect(node.props.children);
      });
    }
    collect(children);
    const currentValue = String(value ?? internal);
    const selected = options.findIndex((option) => option.value === currentValue);
    useImperativeHandle(ref, () => native.current!, []);
    useEffect(() => {
      if (!open) return;
      function dismiss(event: PointerEvent): void {
        if (!trigger.current?.contains(event.target as Node) && !popup.current?.contains(event.target as Node)) setOpen(false);
      }
      const close = (): void => setOpen(false);
      const scrolled = (event: Event): void => { if (!popup.current?.contains(event.target as Node)) close(); };
      document.addEventListener("pointerdown", dismiss);
      document.addEventListener("scroll", scrolled, true);
      window.addEventListener("resize", close);
      return () => { document.removeEventListener("pointerdown", dismiss); document.removeEventListener("scroll", scrolled, true); window.removeEventListener("resize", close); };
    }, [open]);
    useEffect(() => {
      if (open) document.getElementById(`${listId}-${active}`)?.scrollIntoView?.({ block: "nearest" });
    }, [active, listId, open]);
    function show(): void {
      if (disabled) return;
      const bounds = trigger.current!.getBoundingClientRect();
      const below = window.innerHeight - bounds.bottom - 12;
      const above = bounds.top - 12;
      const upwards = below < 160 && above > below;
      const height = Math.max(40, Math.min(240, upwards ? above : below));
      const width = Math.min(Math.max(bounds.width, 160), window.innerWidth - 16);
      setPosition({ left: Math.min(Math.max(8, bounds.left), window.innerWidth - width - 8), top: upwards ? bounds.top - height - 4 : bounds.bottom + 4, width, maxHeight: height });
      setActive(selected >= 0 && !options[selected]?.disabled ? selected : Math.max(0, options.findIndex((option) => !option.disabled)));
      setOpen(true);
    }
    function choose(index: number): void {
      const option = options[index];
      if (!option || option.disabled || !native.current) return;
      setInternal(option.value);
      // Dispatch through the real form control to retain React's normal
      // change event, FormData and ref semantics without an OS popup.
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(native.current, option.value);
      native.current.dispatchEvent(new Event("change", { bubbles: true }));
      setOpen(false);
      trigger.current?.focus();
    }
    function move(direction: number): void {
      for (let step = 1; step <= options.length; step++) {
        const next = (active + direction * step + options.length) % options.length;
        if (!options[next]?.disabled) { setActive(next); break; }
      }
    }
    return (
      <>
        <select ref={native} hidden tabIndex={-1} value={value ?? internal} disabled={disabled} {...rest} aria-hidden="true" aria-label={undefined} aria-labelledby={undefined} onFocus={() => trigger.current?.focus()}>{children}</select>
        <button ref={trigger} id={id} type="button" role="combobox" aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? listId : undefined}
          aria-activedescendant={open ? `${listId}-${active}` : undefined} aria-label={rest["aria-label"]} aria-labelledby={rest["aria-labelledby"]} aria-describedby={rest["aria-describedby"]} aria-invalid={rest["aria-invalid"]}
          disabled={disabled} style={style} className={cn(fieldClass, "flex h-8 cursor-pointer items-center justify-between gap-2 text-left disabled:opacity-50", className)}
          onBlur={(event) => { rest.onBlur?.(event as unknown as React.FocusEvent<HTMLSelectElement>); setOpen(false); }}
          onClick={() => open ? setOpen(false) : show()}
          onKeyDown={(event) => {
            if (event.key === "Escape" && open) { event.preventDefault(); event.stopPropagation(); setOpen(false); }
            else if (event.key === "Tab") setOpen(false);
            else if (["ArrowDown", "ArrowUp"].includes(event.key)) { event.preventDefault(); if (!open) show(); else move(event.key === "ArrowDown" ? 1 : -1); }
            else if (["Enter", " "].includes(event.key)) { event.preventDefault(); if (open) choose(active); else show(); }
            else if (event.key === "Home" || event.key === "End") { event.preventDefault(); if (!open) show(); const indices = options.map((_, i) => i).filter((i) => !options[i]?.disabled); setActive((event.key === "Home" ? indices[0] : indices.at(-1)) ?? 0); }
            else if (event.key.length === 1 && !event.metaKey && !event.ctrlKey && !event.altKey) {
              const now = Date.now(); search.current = { text: (now - search.current.time < 600 ? search.current.text : "") + event.key.toLowerCase(), time: now };
              const index = options.findIndex((option) => !option.disabled && option.text.toLowerCase().startsWith(search.current.text));
              if (!open) show(); if (index >= 0) setActive(index);
            }
          }}>
          <span className="truncate">{options[selected]?.label ?? options[0]?.label ?? "Select…"}</span>
          <svg width="10" height="6" viewBox="0 0 10 6" aria-hidden="true" className="shrink-0 text-rj-text-2"><path d="M1 1l4 4 4-4" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" /></svg>
        </button>
        {open && createPortal(<div ref={popup} id={listId} role="listbox" aria-label={rest["aria-label"]} className="rj-root fixed z-[100] overflow-y-auto rounded-md border border-rj-border-strong bg-rj-panel p-1 shadow-2xl" style={position}
          onMouseDown={(event) => event.preventDefault()}>
          {options.map((option, index) => <div key={option.value} id={`${listId}-${index}`} role="option" data-value={option.value} aria-selected={option.value === currentValue} aria-disabled={option.disabled || undefined}
            className={cn("flex min-h-8 cursor-pointer items-center justify-between gap-2 rounded px-2 text-[13px]", option.disabled ? "cursor-default text-rj-text-3" : index === active ? "bg-rj-panel-hover text-rj-text" : "text-rj-text-2", option.value === currentValue && !option.disabled && "text-rj-text")}
            onPointerMove={() => !option.disabled && setActive(index)} onClick={() => choose(index)}>
            <span>{option.label}</span>{option.value === currentValue && !option.disabled && <span aria-hidden="true" className="text-rj-accent">✓</span>}
          </div>)}
        </div>, document.body)}
      </>
    );
  },
);

export function Field({ label, hint, error, children }: { label: string; hint?: string | undefined; error?: string | undefined; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[12px] font-medium text-rj-text-2">{label}</span>
      {children}
      {error ? (
        <span role="alert" className="mt-1 block text-[11px] text-rj-down">{error}</span>
      ) : hint ? (
        <span className="mt-1 block text-[11px] text-rj-text-3">{hint}</span>
      ) : null}
    </label>
  );
}

/* ------------------------------------------------------------------ */
/* Chip (small tag, e.g. targets)                                      */
/* ------------------------------------------------------------------ */

export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border border-rj-border-strong bg-rj-panel-sunken px-1.5 py-0.5",
        "font-mono text-[11px] text-rj-text-2",
        className,
      )}
    >
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Dialog (accessible modal)                                           */
/* ------------------------------------------------------------------ */

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  width?: number;
}

export function Dialog({ open, onClose, title, children, width = 520 }: DialogProps) {
  const dialog = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  useEffect(() => { closeRef.current = onClose; }, [onClose]);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusable = (): HTMLElement[] => Array.from(dialog.current?.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), textarea:not(:disabled), a[href], [tabindex='0']") ?? []).filter((el) => !el.hidden && el.tabIndex >= 0);
    const first = dialog.current?.querySelector<HTMLElement>("[autofocus], input, textarea") ?? focusable()[0];
    first?.focus();
    function keyboard(event: KeyboardEvent): void {
      if (event.key === "Escape" && !event.defaultPrevented) { event.preventDefault(); closeRef.current(); }
      if (event.key === "Tab") {
        const elements = focusable(); const first = elements[0]; const last = elements.at(-1);
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    }
    document.addEventListener("keydown", keyboard);
    return () => { document.removeEventListener("keydown", keyboard); previous?.focus(); };
  }, [open]);
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="max-h-[85vh] overflow-y-auto rounded-lg border border-rj-border-strong bg-rj-panel shadow-2xl"
        style={{ width, maxWidth: "calc(100vw - 32px)" }}
      >
        <header className="flex items-center justify-between border-b border-rj-border px-4 py-3">
          <h2 className="text-[14px] font-semibold text-rj-text">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="cursor-pointer rounded p-1 text-rj-text-3 hover:bg-rj-panel-hover hover:text-rj-text"
          >
            <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
              <path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </header>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Spinner                                                             */
/* ------------------------------------------------------------------ */

export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={cn("animate-spin text-rj-text-3", className)} width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
      <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="2" fill="none" opacity="0.25" />
      <path d="M14.5 8a6.5 6.5 0 0 0-6.5-6.5" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" />
    </svg>
  );
}
