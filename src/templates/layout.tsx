import { Fragment } from 'hono/jsx'
import { FlashMessage } from '../lib/session'
import { Flash } from './components'

export const layout = (title: string, content: any, user?: any, flash?: FlashMessage | null) => {
  const sidebarItems = [
    { name: 'Dashboard', href: '/dashboard', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" /> },
    { name: 'Domains', href: '/domains', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /> },
    ...(user?.role === 'owner' || user?.role === 'admin' ? [{ name: 'Audit Logs', href: '/logs', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /> }] : []),
    ...(user?.role === 'owner' ? [
      { name: 'User Management', href: '/users', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" /> },
      { name: 'Blacklist', href: '/blacklist', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /> },
      { name: 'Settings', href: '/setup', icon: <Fragment><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></Fragment> }
    ] : [])
  ]

  const isLoginPage = title === 'Welcome';
  const isUnauthPage = !user;

  const head = (
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>{title} - Record Manager</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script dangerouslySetInnerHTML={{ __html: `
            tailwind.config = {
                theme: {
                    extend: {
                        colors: {
                            brand: {
                                bg: '#f8fafc',
                                panel: '#ffffff',
                                deep: '#f1f5f9',
                                dark: '#e2e8f0',
                                border: '#e2e8f0',
                                text: '#0f172a',
                                primary: '#4f46e5',
                                secondary: '#6366f1',
                            }
                        },
                        fontFamily: {
                            sans: ['Inter', 'sans-serif'],
                            mono: ['JetBrains Mono', 'monospace'],
                            display: ['Inter', 'sans-serif'],
                        }
                    }
                }
            }
        `}} />
        <style dangerouslySetInnerHTML={{ __html: `
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
            body { font-family: 'Inter', sans-serif; }
            .font-mono { font-family: 'JetBrains Mono', monospace; }

            .main-card {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05);
            }

            .table-header { background: #f8fafc; }

            input[type="text"], input[type="password"], input[type="email"], input[type="number"], select {
                background: #ffffff;
                border: 1px solid #cbd5e1;
                color: #0f172a;
                border-radius: 6px;
                padding: 0.5rem 0.75rem;
                font-size: 0.875rem;
                transition: all 0.1s ease-in-out;
            }
            input:focus, select:focus {
                outline: none;
                border-color: #4f46e5;
                box-shadow: 0 0 0 1px #4f46e5;
            }

            input[type="checkbox"] {
                accent-color: #4f46e5;
            }

            .btn-primary {
                background: #0f172a;
                color: #ffffff;
                border-radius: 6px;
                padding: 0.5rem 1rem;
                font-size: 0.875rem;
                font-weight: 500;
                transition: all 0.15s ease-in-out;
                display: inline-flex;
                align-items: center;
                justify-content: center;
            }
            .btn-primary:hover {
                background: #1e293b;
            }

            .badge {
                font-size: 0.75rem;
                font-weight: 500;
                padding: 0.125rem 0.625rem;
                border-radius: 9999px;
                display: inline-flex;
                align-items: center;
            }
            .badge-owner { background-color: #fef2f2; color: #ef4444; border: 1px solid #fee2e2; }
            .badge-admin { background-color: #f5f3ff; color: #7c3aed; border: 1px solid #ddd6fe; }
            .badge-manager { background-color: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
            .badge-user { background-color: #f0f9ff; color: #0284c7; border: 1px solid #e0f2fe; }
            .badge-success { background-color: #ecfdf5; color: #059669; border: 1px solid #d1fae5; }
            .badge-warning { background-color: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
            .badge-error { background-color: #fef2f2; color: #ef4444; border: 1px solid #fee2e2; }

            .flash-enter { animation: flash-in 0.25s ease-out; }
            @keyframes flash-in {
                from { opacity: 0; transform: translateY(-8px); }
                to { opacity: 1; transform: translateY(0); }
            }

            .sidebar-active {
                background: #f1f5f9;
                color: #0f172a !important;
                font-weight: 600;
            }
        `}} />
    </head>
  )

  if (isUnauthPage) {
    return (
      <html lang="en" class="h-full bg-slate-50">
        {head}
        <body class="h-full bg-slate-50 text-slate-900 flex flex-col justify-between min-h-screen">
          <div class="flex-1 flex flex-col items-center justify-center px-4 py-16 sm:px-6 lg:px-8">
            {flash && <Flash message={flash} />}
            {isLoginPage ? content : (
              <div class="main-card w-full max-w-xl rounded-xl p-8 shadow-sm">
                <div class="flex items-center gap-3 mb-6 border-b border-slate-100 pb-4">
                  <div class="h-8 w-8 rounded bg-slate-900 flex items-center justify-center text-white font-bold font-sans text-sm">
                    R
                  </div>
                  <h2 class="text-base font-semibold text-slate-900">{title}</h2>
                </div>
                {content}
              </div>
            )}
          </div>
          <Footer />
        </body>
      </html>
    )
  }

  return (
    <html lang="en" class="h-full bg-slate-50">
      {head}
      <body class="h-full overflow-hidden bg-slate-50 text-slate-900">
        <div class="flex h-full">
          {/* Sidebar */}
          <div class="hidden md:flex md:flex-shrink-0 border-r border-slate-200">
            <div class="flex flex-col w-64 bg-white">
              <div class="flex items-center gap-3 h-16 px-5 border-b border-slate-200">
                <div class="h-8 w-8 rounded bg-slate-900 flex items-center justify-center text-white font-bold text-sm">R</div>
                <span class="text-slate-900 text-base font-semibold tracking-tight">Record Manager</span>
              </div>
              <div class="flex-1 flex flex-col overflow-y-auto pt-5 pb-4">
                <nav class="flex-1 px-3 space-y-1">
                  {sidebarItems.map(item => (
                    <a href={item.href} class="group flex items-center px-3 py-2 text-sm font-medium rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-50 transition-all duration-150">
                      <svg class="mr-3 h-5 w-5 text-slate-400 group-hover:text-slate-500 transition-colors" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        {item.icon}
                      </svg>
                      {item.name}
                    </a>
                  ))}
                </nav>
              </div>
              <div class="flex-shrink-0 flex bg-slate-50 p-4 border-t border-slate-200">
                <div class="w-full">
                  <p class="text-xs font-medium text-slate-700 truncate font-mono">{user.email}</p>
                  <div class="flex justify-between items-center mt-2">
                    <span class={`badge badge-${user.role}`}>{user.role}</span>
                    <form method="post" action="/auth/logout" style="display:inline;">
                      <button type="submit" class="text-xs text-slate-500 hover:text-slate-800 font-medium hover:underline flex items-center gap-1 cursor-pointer">
                        Logout
                        <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
                      </button>
                    </form>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Main content */}
          <div class="flex flex-col w-0 flex-1 overflow-hidden">
            <main class="flex-1 relative z-0 overflow-y-auto focus:outline-none py-6 bg-slate-50">
              <div class="max-w-7xl mx-auto px-4 sm:px-6 md:px-8 flex justify-between items-center mb-6">
                <h1 class="text-xl font-bold text-slate-900 tracking-tight">{title}</h1>
                <div class="text-xs text-slate-400 font-mono hidden md:block">Connected</div>
              </div>
              <div class="max-w-7xl mx-auto px-4 sm:px-6 md:px-8 pb-10">
                {flash && <Flash message={flash} />}
                <div class="main-card p-6 md:p-8 rounded-xl min-h-[450px]">
                  {content}
                </div>
              </div>
            </main>
          </div>
        </div>
        <script dangerouslySetInnerHTML={{ __html: `
          document.addEventListener('DOMContentLoaded', () => {
            const currentPath = window.location.pathname;
            const navLinks = document.querySelectorAll('nav a');
            navLinks.forEach(link => {
              const href = link.getAttribute('href');
              if (href === currentPath || (currentPath.startsWith(href) && href !== '/' && href !== '/dashboard')) {
                link.classList.add('sidebar-active');
              }
            });
          });
        `}} />
      </body>
    </html>
  )
}

const Footer = () => (
  <div class="py-6 border-t border-slate-200 text-center text-xs text-slate-400 font-mono flex flex-col sm:flex-row items-center justify-center gap-2 sm:gap-4">
    <span>Record Manager • Powered by Cloudflare Workers</span>
    <span class="hidden sm:inline text-slate-300">|</span>
    <a href="https://github.com/simon-msdos/record-manager" target="_blank" rel="noopener noreferrer" class="hover:text-slate-600 underline flex items-center gap-1">
      GitHub
    </a>
  </div>
)
