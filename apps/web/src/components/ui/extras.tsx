import React from 'react';

export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(({ className = '', ...props }, ref) => (
  <select ref={ref} className={`flex h-9 w-full rounded-[6px] border border-border bg-white px-3 py-1 text-sm text-text-primary transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary disabled:cursor-not-allowed disabled:opacity-50 ${className}`} {...props} />
));
Select.displayName = 'Select';

export const Divider = ({ className = '', ...props }: React.HTMLAttributes<HTMLHRElement>) => (
  <hr className={`border-border w-full my-4 ${className}`} {...props} />
);

export const Tooltip = ({ title, children, className = '' }: { title: string, children: React.ReactNode, className?: string }) => (
  <div title={title} className={`inline-block ${className}`}>
    {children}
  </div>
);
