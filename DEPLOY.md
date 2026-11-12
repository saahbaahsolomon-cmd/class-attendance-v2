# Put the attendance system online (Render)

After this, there is **no laptop and no tunnel**. Everyone uses one permanent web address.

## What you need
- A free GitHub account (github.com)
- A Render account (render.com) — sign up with GitHub
- A bank card for Render's **Starter** plan (about $7/month). The disk is what keeps class lists, accounts, records and selfies safe.

## Steps
1. **GitHub:** click **New repository**. Name it `class-attendance`. Choose **Private**. Click **Create repository**.
2. Click **uploading an existing file**. Drag in everything from this folder **except** `node_modules` and `data` (they are not needed). Click **Commit changes**.
3. **Render:** click **New +** → **Blueprint** → choose your `class-attendance` repository.
4. Render reads `render.yaml` and asks for **ADMIN_KEY**. Type a strong password of your own. This is the admin password. Click **Apply**.
5. Wait 3–5 minutes. Render shows your address, like `https://class-attendance.onrender.com`.

## First use
1. Open `https://YOUR-ADDRESS/lecturer.html`.
2. Sign in with username `admin` and your ADMIN_KEY.
3. Under **Lecturers**, add each lecturer: full name, username, password. Send them their login.
4. Each lecturer signs in, pastes their own class list, and starts sessions.
5. Leave **Public link** empty. The QR automatically uses your Render address.

## Every class
Lecturer signs in → stands in the room → sets the distance (0.15) → **Start session & show QR** → students scan → **Download CSV** at the end.

## Good to know
- Phones need the secure `https` address for camera and location. Render provides it.
- Do **not** use Render's free plan for real classes. Its files are erased when it sleeps, so accounts and class lists would vanish.
- Selfies are personal data. Get the school's approval and delete old photos when you no longer need them.
- To change a password: sign in as admin → **New password** next to the lecturer.
