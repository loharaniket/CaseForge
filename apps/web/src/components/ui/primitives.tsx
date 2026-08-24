import React from 'react';

export const Button = React.forwardRef<HTMLButtonElement, React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' | 'tertiary' }>(({ className = '', variant = 'primary', ...props }, ref) => {
  const baseClasses = 'inline-flex items-center justify-center font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed';
  
  const variants = {
    primary: 'bg-primary text-white hover:bg-primary-hover h-9 px-4 rounded-[6px]',
    secondary: 'bg-white border border-border text-text-primary hover:bg-bg-panel-subtle h-9 px-4 rounded-[6px]',
    danger: 'bg-danger text-white hover:bg-critical h-9 px-4 rounded-[6px]',
    tertiary: 'text-primary hover:text-primary-hover underline-offset-2 hover:underline'
  };

  return (
    <button ref={ref} className={`${baseClasses} ${variants[variant]} ${className}`} {...props} />
  );
});
Button.displayName = 'Button';

export const Card = ({ className = '', children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={`bg-bg-panel border border-border rounded-[8px] overflow-hidden ${className}`} {...props}>
    {children}
  </div>
);

export const CardHeader = ({ className = '', children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={`p-4 border-b border-border ${className}`} {...props}>
    {children}
  </div>
);

export const CardContent = ({ className = '', children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={`p-4 ${className}`} {...props}>
    {children}
  </div>
);

export const Badge = ({ className = '', variant = 'neutral', children, ...props }: React.HTMLAttributes<HTMLSpanElement> & { variant?: 'success' | 'warning' | 'danger' | 'critical' | 'info' | 'neutral' }) => {
  const variants = {
    success: 'bg-success-bg text-success border-success',
    warning: 'bg-warning-bg text-warning border-warning',
    danger: 'bg-danger-bg text-danger border-danger',
    critical: 'bg-critical-bg text-critical border-critical',
    info: 'bg-info-bg text-info border-info',
    neutral: 'bg-neutral-bg text-neutral border-neutral'
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${variants[variant]} ${className}`} {...props}>
      {children}
    </span>
  );
};

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className = '', ...props }, ref) => (
  <input ref={ref} className={`flex h-9 w-full rounded-[6px] border border-border bg-white px-3 py-1 text-sm text-text-primary transition-colors placeholder:text-text-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary disabled:cursor-not-allowed disabled:opacity-50 ${className}`} {...props} />
));
Input.displayName = 'Input';

export const Table = ({ className = '', children, ...props }: React.TableHTMLAttributes<HTMLTableElement>) => (
  <div className="w-full overflow-auto rounded-[8px] border border-border bg-white">
    <table className={`w-full text-sm text-left ${className}`} {...props}>{children}</table>
  </div>
);

export const Thead = ({ className = '', children, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className={`text-[12px] font-[650] text-text-secondary bg-bg-panel-subtle border-b border-border ${className}`} {...props}>{children}</thead>
);

export const Tbody = ({ className = '', children, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <tbody className={`divide-y divide-border ${className}`} {...props}>{children}</tbody>
);

export const Tr = ({ className = '', children, ...props }: React.HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={`h-12 hover:bg-bg-panel-subtle transition-colors ${className}`} {...props}>{children}</tr>
);

export const Th = ({ className = '', children, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) => (
  <th className={`h-10 px-4 align-middle ${className}`} {...props}>{children}</th>
);

export const Td = ({ className = '', children, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={`p-4 align-middle ${className}`} {...props}>{children}</td>
);
