import { FlashMessage as FlashMessageType } from '../lib/session'

export const Badge = ({ children, type = 'user' }: { children: any, type?: string }) => {
  const styles: any = {
    owner: 'badge-owner',
    admin: 'badge-admin',
    manager: 'badge-manager',
    user: 'badge-user',
    success: 'badge-success',
    error: 'badge-error',
    warning: 'badge-warning'
  }
  return (
    <span class={`badge ${styles[type] || styles.user} uppercase font-mono`}>
      {children}
    </span>
  )
}

export const Button = ({ children, type = 'button', variant = 'primary', ...props }: any) => {
  const variants: any = {
    primary: 'btn-primary',
    secondary: 'px-5 py-2.5 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 font-bold text-xs tracking-wider transition bg-white'
  }
  return (
    <button type={type} class={variants[variant]} {...props}>
      {children}
    </button>
  )
}

export const Flash = ({ message }: { message: FlashMessageType }) => {
  const styles: any = {
    success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    error: 'bg-rose-50 text-rose-700 border-rose-200',
    info: 'bg-indigo-50 text-indigo-700 border-indigo-200'
  }
  return (
    <div class={`mb-6 p-4 rounded-xl border ${styles[message.type] || styles.info} flex items-center gap-3 flash-enter`}>
      {message.type === 'success' && <svg class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
      {message.type === 'error' && <svg class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
      {message.type === 'info' && <svg class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
      <span class="text-sm font-medium whitespace-pre-line">{message.text}</span>
    </div>
  )
}
