export function Marquee({ items, className = "" }: { items: string[]; className?: string }) {
  return (
    <div className={`overflow-hidden ${className}`} aria-hidden="true">
      <div className="marquee-track">
        {items.concat(items).map((t, i) => (
          <span key={i} className="flex items-center">
            <span className="display px-6 text-2xl tracking-tightest sm:text-3xl">{t}</span>
            <span className={`inline-block h-2 w-2 rotate-45 ${i % 2 ? "bg-green" : "bg-brand"}`} />
          </span>
        ))}
      </div>
    </div>
  );
}
