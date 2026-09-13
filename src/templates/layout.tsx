import { Fragment } from 'hono/jsx'
import { FlashMessage } from '../lib/session'
import { Flash } from './components'

export const layout = (title: string, content: any, user?: any, flash?: FlashMessage | null) => {
  const sidebarItems = [
    { name: 'Dashboard', href: '/dashboard', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" /> },
    { name: 'Domains', href: '/domains', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /> },
    { name: 'API Tokens', href: '/tokens', icon: <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /> },
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
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <script src="/theme.js"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" />
        <link rel="stylesheet" href="/app.css" />
    </head>
  )

  if (isUnauthPage) {
    return (
      <html lang="en" class="h-full bg-slate-50">
        {head}
        <body class="h-full bg-slate-50 text-slate-900 flex flex-col justify-between min-h-screen">
          <button type="button" data-theme-toggle title="Toggle dark mode" class="fixed top-4 right-4 z-10 p-2 rounded-lg bg-white border border-slate-200 text-slate-500 hover:text-slate-800 cursor-pointer shadow-sm">
            <svg class="h-4 w-4 dark:hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
            <svg class="h-4 w-4 hidden dark:block" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
          </button>
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
      <body class="h-full overflow-hidden bg-slate-50 text-slate-900 flex flex-col">
        {/* Mobile top bar — without it the sidebar (and all navigation) is
            unreachable below the md breakpoint. */}
        <div class="md:hidden flex-shrink-0 flex items-center justify-between h-14 px-4 bg-white border-b border-slate-200">
          <button type="button" data-nav-toggle aria-label="Open navigation" class="p-2 -ml-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors">
            <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" /></svg>
          </button>
          <a href="/dashboard" class="flex items-center gap-2">
            <div class="h-7 w-7 rounded bg-slate-900 flex items-center justify-center text-white font-bold text-xs">R</div>
            <span class="text-sm font-semibold text-slate-900 tracking-tight">Record Manager</span>
          </a>
          <button type="button" data-theme-toggle aria-label="Toggle dark mode" class="p-2 -mr-2 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors">
            <svg class="h-5 w-5 dark:hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
            <svg class="h-5 w-5 hidden dark:block" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
          </button>
        </div>

        {/* Drawer scrim on mobile; inert on desktop. */}
        <div class="mobile-backdrop" data-nav-close></div>

        <div class="flex flex-1 min-h-0">
          {/* Sidebar — off-canvas drawer below md, static rail from md up */}
          <div class="sidebar-drawer md:flex md:flex-shrink-0 border-r border-slate-200">
            <div class="flex flex-col w-64 h-full bg-white">
              <div class="flex items-center gap-3 h-16 px-5 border-b border-slate-200">
                <div class="h-8 w-8 rounded bg-slate-900 flex items-center justify-center text-white font-bold text-sm">R</div>
                <span class="text-slate-900 text-base font-semibold tracking-tight flex-1">Record Manager</span>
                <button type="button" data-nav-close aria-label="Close navigation" class="md:hidden p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors">
                  <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
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
                    <div class="flex items-center gap-2">
                      <button type="button" data-theme-toggle title="Toggle dark mode" class="text-slate-500 hover:text-slate-800 cursor-pointer">
                        <svg class="h-4 w-4 dark:hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
                        <svg class="h-4 w-4 hidden dark:block" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
                      </button>
                      <form method="post" action="/auth/logout" class="inline">
                        <button type="submit" class="text-xs text-slate-500 hover:text-slate-800 font-medium hover:underline flex items-center gap-1 cursor-pointer">
                          Logout
                          <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
                        </button>
                      </form>
                    </div>
                  </div>
                  <form method="post" action="/auth/logout-all" class="inline">
                    <button type="submit" class="mt-2 text-[10px] text-slate-400 hover:text-slate-700 font-medium hover:underline cursor-pointer" data-confirm="Sign out on every device?">
                      Sign out everywhere
                    </button>
                  </form>
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
        <script src="/app.js" defer></script>
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
