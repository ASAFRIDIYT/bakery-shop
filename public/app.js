// Shared Supabase client, auth handling, and the bits every page needs.
//
// The key below is the PUBLISHABLE key. It is meant to be here -- it identifies the
// project, it does not grant access. What each visitor may read or write is decided
// by Row Level Security in the database, not by keeping this string secret.

import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm'

export const supabase = createClient(
  'https://dqrltgsrfozsfyvipwae.supabase.co',
  'sb_publishable_JNQLrBOV3H9LSNaUeqAbOQ_16cNuLdQ'
)

export const money = n =>
  'Rs ' + Number(n).toLocaleString('en-PK', { maximumFractionDigits: 0 })

// A product's real price after its discount.
export const finalPrice = p =>
  Math.round(Number(p.price) * (100 - p.discount_percent) / 100)

export const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

/* ------------------------------------------------------------------- theme */

// Three states: an explicit "light"/"dark" stamped on <html>, or no attribute at
// all, which lets the visitor's OS setting decide. Stored per browser only.
const THEMES = ['system', 'light', 'dark']
const THEME_ICON = { system: '🌗', light: '☀️', dark: '🌙' }

export function readTheme () {
  try { return THEMES.includes(localStorage.theme) ? localStorage.theme : 'system' }
  catch { return 'system' }
}

export function applyTheme (t) {
  if (t === 'system') document.documentElement.removeAttribute('data-theme')
  else document.documentElement.setAttribute('data-theme', t)
  try { localStorage.theme = t } catch {}
}

// Runs before first paint (app.js is imported in <head>'s module graph) so the
// page never flashes the wrong theme.
applyTheme(readTheme())

function themeButton () {
  const b = document.createElement('button')
  b.className = 'theme-btn'
  b.type = 'button'
  const sync = () => {
    const t = readTheme()
    b.textContent = THEME_ICON[t]
    b.title = `Theme: ${t} — click to change`
    b.setAttribute('aria-label', b.title)
  }
  sync()
  b.addEventListener('click', () => {
    applyTheme(THEMES[(THEMES.indexOf(readTheme()) + 1) % THEMES.length])
    sync()
  })
  return b
}

/* ------------------------------------------------------------------ upload */

export const PRODUCT_BUCKET = 'bakery-products'

// Uploads one image and returns its public URL. The bucket rejects anything that
// is not an image or is over 3 MB, and storage policies reject the write outright
// unless the caller is an admin -- these checks are the convenience copy.
export async function uploadProductImage (file) {
  if (!file) throw new Error('No file chosen')
  if (!file.type.startsWith('image/')) throw new Error('That file is not an image')
  if (file.size > 3 * 1024 * 1024) throw new Error('Image must be under 3 MB')

  const ext = (file.name.split('.').pop() || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '')
  const path = `${crypto.randomUUID()}.${ext || 'jpg'}`

  const { error } = await supabase.storage
    .from(PRODUCT_BUCKET)
    .upload(path, file, { cacheControl: '31536000', upsert: false })

  if (error) throw error

  return supabase.storage.from(PRODUCT_BUCKET).getPublicUrl(path).data.publicUrl
}

/* ----------------------------------------------------------------- session */

export async function currentUser () {
  const { data } = await supabase.auth.getUser()
  return data.user ?? null
}

// Admin status is decided in the database, never in the browser. This asks the same
// SECURITY DEFINER function the RLS policies use, so the answer here and the answer
// the database enforces can never disagree.
export async function isAdmin () {
  const { data, error } = await supabase.rpc('bakery_is_admin')
  if (error) return false
  return data === true
}

/* ------------------------------------------------------------------ header */

export async function paintHeader (active) {
  const user = await currentUser()
  const admin = user ? await isAdmin() : false

  const nav = document.querySelector('nav.site')
  if (!nav) return

  const link = (href, label) =>
    `<a href="${href}"${active === href ? ' class="active"' : ''}>${label}</a>`

  let html = link('index.html', 'Shop')
  if (user) html += link('orders.html', 'My Orders')
  if (admin) html += link('admin.html', 'Admin')

  html += user
    ? `<button class="btn ghost sm" id="signout">Sign out</button>`
    : `<button class="btn sm" id="signin">Sign in</button>`

  nav.innerHTML = html
  nav.appendChild(themeButton())

  nav.querySelector('#signout')?.addEventListener('click', async () => {
    await supabase.auth.signOut()
    location.href = 'index.html'
  })
  nav.querySelector('#signin')?.addEventListener('click', openAuth)

  return { user, admin }
}

/* -------------------------------------------------------------- auth modal */

export function openAuth () {
  let dlg = document.getElementById('authDialog')
  if (!dlg) {
    dlg = document.createElement('dialog')
    dlg.id = 'authDialog'
    dlg.innerHTML = `
      <div class="inner">
        <div class="tabs">
          <button type="button" data-mode="in" class="on">Sign in</button>
          <button type="button" data-mode="up">Create account</button>
        </div>
        <div id="authMsg"></div>
        <form id="authForm">
          <label class="field"><span>Email</span>
            <input type="email" name="email" required autocomplete="email"></label>
          <label class="field"><span>Password</span>
            <input type="password" name="password" required minlength="6"
                   autocomplete="current-password"></label>
          <div class="row" style="margin-top:6px">
            <button class="btn" type="submit" style="flex:1">Sign in</button>
            <button class="btn ghost" type="button" id="authClose">Cancel</button>
          </div>
          <p style="margin:14px 0 0"><a href="#" id="forgot" class="muted"
             style="font-size:13px">Forgot password?</a></p>
        </form>
      </div>`
    document.body.appendChild(dlg)

    let mode = 'in'
    const msg = dlg.querySelector('#authMsg')
    const form = dlg.querySelector('#authForm')
    const submit = form.querySelector('button[type=submit]')

    const say = (text, kind = 'err') => {
      msg.innerHTML = `<div class="notice ${kind}">${esc(text)}</div>`
    }

    dlg.querySelectorAll('.tabs button').forEach(b => {
      b.addEventListener('click', () => {
        mode = b.dataset.mode
        dlg.querySelectorAll('.tabs button').forEach(x => x.classList.toggle('on', x === b))
        submit.textContent = mode === 'in' ? 'Sign in' : 'Create account'
        form.password.autocomplete = mode === 'in' ? 'current-password' : 'new-password'
        msg.innerHTML = ''
      })
    })

    dlg.querySelector('#authClose').addEventListener('click', () => dlg.close())

    dlg.querySelector('#forgot').addEventListener('click', async e => {
      e.preventDefault()
      const email = form.email.value.trim()
      if (!email) return say('Enter your email first, then tap Forgot password.')
      const { error } = await supabase.auth.resetPasswordForEmail(email)
      error ? say(error.message) : say('Reset link sent. Check your inbox.', 'ok')
    })

    form.addEventListener('submit', async e => {
      e.preventDefault()
      submit.disabled = true
      const email = form.email.value.trim()
      const password = form.password.value

      const { data, error } = mode === 'in'
        ? await supabase.auth.signInWithPassword({ email, password })
        : await supabase.auth.signUp({ email, password })

      submit.disabled = false

      if (error) return say(error.message)

      // Sign-up with confirmations on returns a user but no session yet.
      if (mode === 'up' && !data.session) {
        return say('Account created. Check your email to confirm, then sign in.', 'ok')
      }
      dlg.close()
      location.reload()
    })
  }
  dlg.showModal()
}

/* Require a signed-in user, prompting if needed. Returns the user or null. */
export async function requireUser () {
  const user = await currentUser()
  if (!user) { openAuth(); return null }
  return user
}
