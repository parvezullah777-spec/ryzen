import React, { useState, useEffect } from "react";
import {
  User, LogOut, ChevronRight, ChevronLeft, ShieldCheck, Plus,
  Mail, Lock, Eye, EyeOff, Check, ArrowRight, Phone, Camera,
  MapPin, KeyRound, Trash2, Pencil, X, Crown, PackageCheck, Ruler,
} from "lucide-react";
import { supabase } from "./supabaseClient";

// Remembered accounts (one entry per account that has ever signed in on this
// device) are kept in localStorage as { id, name, email, refresh_token }.
// This is what powers the Amazon-style "Continue as X" picker: Supabase
// itself only holds one live session, so switching accounts means calling
// supabase.auth.setSession() with a different stored refresh token.
const REMEMBERED_KEY = "vantra_remembered_accounts";

function loadRemembered() {
  try {
    return JSON.parse(localStorage.getItem(REMEMBERED_KEY)) || [];
  } catch {
    return [];
  }
}

function saveRemembered(list) {
  localStorage.setItem(REMEMBERED_KEY, JSON.stringify(list));
}

function upsertRemembered(account) {
  const list = loadRemembered().filter((a) => a.id !== account.id);
  list.unshift(account);
  saveRemembered(list);
  return list;
}

function removeRemembered(id) {
  const list = loadRemembered().filter((a) => a.id !== id);
  saveRemembered(list);
  return list;
}

const AVATAR_COLORS = ["#E8823C", "#0E6E63", "#5B5FEF", "#C4432B", "#B08900"];
const colorFor = (id) => {
  let hash = 0;
  for (const ch of String(id)) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return AVATAR_COLORS[hash % AVATAR_COLORS.length];
};
const initials = (name = "") =>
  name.split(" ").map((p) => p[0]).join("").slice(0, 2).toUpperCase();

export default function AuthFlow() {
  const [accounts, setAccounts] = useState([]);
  const [active, setActive] = useState(null); // {id, name, email}
  const [membership, setMembership] = useState(null); // {status, currentPeriodEnd} | null
  const [step, setStep] = useState("loading"); // loading | select | identify | password | signup | home
  const [pendingEmail, setPendingEmail] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [toast, setToast] = useState("");

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 2200);
    return () => clearTimeout(t);
  }, [toast]);

  // On load: check for a live Supabase session, otherwise show the picker.
  useEffect(() => {
    (async () => {
      const remembered = loadRemembered();
      setAccounts(remembered);
      const { data } = await supabase.auth.getSession();
      if (data.session) {
        const profile = await fetchProfile(data.session.user.id);
        setActive(profile);
        fetchMembership(profile.id);
        setStep("home");
      } else {
        setStep("select");
      }
    })();
  }, []);

  async function fetchProfile(userId) {
    const { data } = await supabase
      .from("profiles")
      .select("id, full_name, email, phone, avatar_url, created_at")
      .eq("id", userId)
      .single();
    return {
      id: data.id,
      name: data.full_name,
      email: data.email,
      phone: data.phone || "",
      avatarUrl: data.avatar_url || null,
      createdAt: data.created_at,
    };
  }

  async function fetchMembership(userId) {
    const { data } = await supabase
      .from("memberships")
      .select("status, current_period_end")
      .eq("user_id", userId)
      .maybeSingle();
    setMembership(data ? { status: data.status, currentPeriodEnd: data.current_period_end } : { status: "none" });
  }

  async function handleContinueAs(account) {
    setError("");
    setBusy(true);
    const { error: sessErr } = await supabase.auth.setSession({
      refresh_token: account.refresh_token,
      access_token: account.access_token,
    });
    setBusy(false);
    if (sessErr) {
      setError("This session has expired. Please sign in again.");
      setAccounts(removeRemembered(account.id));
      return;
    }
    setActive(account);
    fetchMembership(account.id);
    setStep("home");
    setToast(`Signed in as ${account.name}`);
  }

  function handleIdentifySubmit(email) {
    setError("");
    const clean = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
      setError("Enter a valid email address to continue.");
      return;
    }
    setPendingEmail(clean);
    setStep("password"); // Supabase doesn't expose "does this email exist" pre-auth;
    // we always try sign-in first, and offer sign-up if it fails.
  }

  async function handlePasswordSubmit(pw) {
    setError("");
    setBusy(true);
    const { data, error: signErr } = await supabase.auth.signInWithPassword({
      email: pendingEmail,
      password: pw,
    });
    setBusy(false);
    if (signErr) {
      setError("No account found or incorrect password.");
      return;
    }
    const profile = await fetchProfile(data.user.id);
    const { data: sessionData } = await supabase.auth.getSession();
    const remembered = {
      ...profile,
      refresh_token: sessionData.session.refresh_token,
      access_token: sessionData.session.access_token,
    };
    setAccounts(upsertRemembered(remembered));
    setActive(profile);
    fetchMembership(profile.id);
    setStep("home");
    setToast(`Signed in as ${profile.name}`);
  }

  async function handleSignup(name, pw) {
    setError("");
    if (name.trim().length < 2) return setError("Enter your full name.");
    if (pw.length < 6) return setError("Password must be at least 6 characters.");

    setBusy(true);
    const { data, error: signErr } = await supabase.auth.signUp({
      email: pendingEmail,
      password: pw,
      options: { data: { full_name: name.trim() } },
    });
    setBusy(false);
    if (signErr) return setError(signErr.message);

    if (!data.session) {
      // Email confirmation is enabled on this project
      setToast("Check your email to confirm your account");
      setStep("select");
      return;
    }
    const profile = { id: data.user.id, name: name.trim(), email: pendingEmail };
    const remembered = {
      ...profile,
      refresh_token: data.session.refresh_token,
      access_token: data.session.access_token,
    };
    setAccounts(upsertRemembered(remembered));
    setActive(profile);
    fetchMembership(profile.id);
    setStep("home");
    setToast(`Welcome, ${profile.name}`);
  }

  async function handleSignOut({ forgetDevice } = {}) {
    await supabase.auth.signOut();
    if (forgetDevice) setAccounts(removeRemembered(active.id));
    setActive(null);
    setMembership(null);
    setStep("select");
    setToast("Signed out");
  }

  async function handleDeleteAccount() {
    setBusy(true);
    const { error: fnErr } = await supabase.functions.invoke("delete-account");
    setBusy(false);
    if (fnErr) {
      setToast("Couldn't delete account. Try again.");
      return;
    }
    setAccounts(removeRemembered(active.id));
    setActive(null);
    setStep("select");
    setToast("Account deleted");
  }

  if (step === "loading") return null;

  return (
    <div style={{ fontFamily: "Inter, ui-sans-serif, system-ui" }} className="min-h-screen w-full flex items-center justify-center p-4 bg-[#F7F5F0]">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-xl p-8 max-h-[92vh] overflow-y-auto flex flex-col">
        <div className="flex flex-col flex-1 min-h-[520px]">
        {step === "select" && (
          <SelectScreen accounts={accounts} onContinueAs={handleContinueAs} onAddAccount={() => setStep("identify")} error={error} />
        )}
        {step === "identify" && (
          <IdentifyScreen onBack={accounts.length ? () => setStep("select") : null} onSubmit={handleIdentifySubmit} error={error} />
        )}
        {step === "password" && (
          <PasswordScreen
            email={pendingEmail} busy={busy} showPw={showPw} setShowPw={setShowPw}
            onBack={() => setStep("identify")} onSubmit={handlePasswordSubmit}
            onNoAccount={() => { setError(""); setStep("signup"); }}
            error={error}
          />
        )}
        {step === "signup" && (
          <SignupScreen email={pendingEmail} busy={busy} showPw={showPw} setShowPw={setShowPw}
            onBack={() => setStep("password")} onSubmit={handleSignup} error={error} />
        )}
        {step === "home" && active && (
          <HomeScreen account={active} accounts={accounts} membership={membership} onSwitch={() => setStep("select")} onSignOut={handleSignOut} onOpenProfile={() => setStep("profile")} onOpenMembership={() => setStep("membership")} />
        )}
        {step === "profile" && active && (
          <ProfileScreen
            account={active}
            busy={busy}
            onBack={() => setStep("home")}
            onSaved={(updated) => {
              setActive(updated);
              setAccounts(upsertRemembered({ ...accounts.find((a) => a.id === updated.id), ...updated }));
              setToast("Profile updated");
            }}
            onOpenAddresses={() => setStep("addresses")}
            onOpenChangePassword={() => setStep("change-password")}
            onOpenMembership={() => setStep("membership")}
            membership={membership}
            onDeleteAccount={handleDeleteAccount}
          />
        )}
        {step === "membership" && active && (
          <MembershipScreen
            account={active}
            membership={membership}
            onBack={() => setStep("profile")}
            onRefresh={() => fetchMembership(active.id)}
            onCancelled={() => setToast("Membership will end after this billing period")}
          />
        )}
        {step === "addresses" && active && (
          <AddressesScreen userId={active.id} onBack={() => setStep("profile")} />
        )}
        {step === "change-password" && active && (
          <ChangePasswordScreen
            onBack={() => setStep("profile")}
            onDone={() => { setToast("Password updated"); setStep("profile"); }}
          />
        )}
        </div>
      </div>
      {toast && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-[#14212E] text-white text-sm px-4 py-2.5 rounded-lg shadow-lg flex items-center gap-2">
          <Check size={15} className="text-[#E8823C]" /> {toast}
        </div>
      )}
    </div>
  );
}

// ---------- screens ----------

function SelectScreen({ accounts, onContinueAs, onAddAccount, error }) {
  return (
    <div className="flex flex-col h-full">
      <h2 className="text-xl font-semibold text-[#14212E]">{accounts.length ? "Choose an account" : "Welcome"}</h2>
      <p className="text-sm text-[#6B6B6B] mt-1 mb-6">
        {accounts.length ? "Select who's continuing, or add a new account." : "Sign in or create an account."}
      </p>
      {error && <p className="text-xs text-[#C4432B] mb-4">{error}</p>}
      <div className="flex flex-col gap-2">
        {accounts.map((a) => (
          <button key={a.id} onClick={() => onContinueAs(a)}
            className="group flex items-center gap-3 border border-[#E4E0D6] hover:border-[#0E6E63] hover:bg-[#F7F5F0] rounded-xl px-4 py-3 transition-colors">
            <div className="w-10 h-10 rounded-full flex items-center justify-center text-white text-sm font-semibold shrink-0" style={{ background: colorFor(a.id) }}>
              {initials(a.name)}
            </div>
            <div className="min-w-0 flex-1 text-left">
              <div className="text-sm font-medium text-[#14212E] truncate">{a.name}</div>
              <div className="text-xs text-[#8A8A8A] truncate">{a.email}</div>
            </div>
            <ChevronRight size={18} className="text-[#C4C0B4] group-hover:text-[#0E6E63]" />
          </button>
        ))}
        <button onClick={onAddAccount}
          className="flex items-center gap-3 border border-dashed border-[#C4C0B4] hover:border-[#E8823C] rounded-xl px-4 py-3 transition-colors">
          <div className="w-10 h-10 rounded-full flex items-center justify-center bg-[#F1EEE6] text-[#14212E]"><Plus size={18} /></div>
          <div className="text-sm font-medium text-[#14212E]">{accounts.length ? "Add another account" : "Sign in / Sign up"}</div>
        </button>
      </div>
    </div>
  );
}

function IdentifyScreen({ onBack, onSubmit, error }) {
  const [email, setEmail] = useState("");
  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onBack} />
      <h2 className="text-xl font-semibold text-[#14212E]">Sign in or create an account</h2>
      <p className="text-sm text-[#6B6B6B] mt-1 mb-6">Enter your email to continue.</p>
      <form onSubmit={(e) => { e.preventDefault(); onSubmit(email); }} className="flex flex-col gap-4">
        <Field icon={<Mail size={16} />} label="Email address" type="email" value={email} onChange={setEmail} placeholder="you@example.com" autoFocus />
        {error && <p className="text-xs text-[#C4432B]">{error}</p>}
        <PrimaryButton type="submit">Continue</PrimaryButton>
      </form>
    </div>
  );
}

function PasswordScreen({ email, onBack, onSubmit, onNoAccount, error, busy, showPw, setShowPw }) {
  const [pw, setPw] = useState("");
  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onBack} />
      <h2 className="text-xl font-semibold text-[#14212E] mb-1">Enter your password</h2>
      <p className="text-sm text-[#8A8A8A] mb-6 truncate">{email}</p>
      <form onSubmit={(e) => { e.preventDefault(); onSubmit(pw); }} className="flex flex-col gap-4">
        <Field icon={<Lock size={16} />} label="Password" type={showPw ? "text" : "password"} value={pw} onChange={setPw}
          placeholder="Enter your password" autoFocus
          endAdornment={<button type="button" tabIndex={-1} onClick={() => setShowPw((v) => !v)} className="text-[#8A8A8A]">{showPw ? <EyeOff size={16} /> : <Eye size={16} />}</button>} />
        {error && <p className="text-xs text-[#C4432B]">{error}</p>}
        <PrimaryButton type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</PrimaryButton>
        <button type="button" onClick={onNoAccount} className="text-sm text-[#0E6E63] font-medium hover:underline self-start">
          Don't have an account? Create one
        </button>
      </form>
    </div>
  );
}

function SignupScreen({ email, onBack, onSubmit, error, busy, showPw, setShowPw }) {
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onBack} />
      <h2 className="text-xl font-semibold text-[#14212E]">Create your account</h2>
      <p className="text-sm text-[#6B6B6B] mt-1 mb-6 truncate">{email}</p>
      <form onSubmit={(e) => { e.preventDefault(); onSubmit(name, pw); }} className="flex flex-col gap-4">
        <Field icon={<User size={16} />} label="Full name" value={name} onChange={setName} placeholder="Your name" autoFocus />
        <Field icon={<Lock size={16} />} label="Create password" type={showPw ? "text" : "password"} value={pw} onChange={setPw}
          placeholder="At least 6 characters"
          endAdornment={<button type="button" tabIndex={-1} onClick={() => setShowPw((v) => !v)} className="text-[#8A8A8A]">{showPw ? <EyeOff size={16} /> : <Eye size={16} />}</button>} />
        {error && <p className="text-xs text-[#C4432B]">{error}</p>}
        <PrimaryButton type="submit" disabled={busy}>{busy ? "Creating…" : "Create account"}</PrimaryButton>
      </form>
    </div>
  );
}

function HomeScreen({ account, accounts, membership, onSwitch, onSignOut, onOpenProfile, onOpenMembership }) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const others = accounts.filter((a) => a.id !== account.id);
  const isMember = membership?.status === "active";
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1 text-xs text-[#0E6E63] bg-[#0E6E63]/10 px-2.5 py-1 rounded-full font-medium">
          <Check size={13} /> Active
        </span>
        <button
          onClick={onOpenProfile}
          aria-label="Profile"
          title="Profile"
          className="w-9 h-9 rounded-full flex items-center justify-center border border-[#E4E0D6] text-[#14212E] hover:border-[#0E6E63] hover:text-[#0E6E63] transition-colors"
        >
          <User size={17} />
        </button>
      </div>

      <div className="flex items-center gap-3 mb-4">
        <div className="w-12 h-12 rounded-full flex items-center justify-center text-white font-semibold" style={{ background: colorFor(account.id) }}>
          {initials(account.name)}
        </div>
        <div>
          <div className="text-xs text-[#8A8A8A]">Signed in as</div>
          <div className="font-semibold text-[#14212E]">{account.name}</div>
        </div>
      </div>

      <button
        onClick={onOpenMembership}
        className={`flex items-center justify-between rounded-xl px-4 py-3 mb-4 transition-colors ${
          isMember
            ? "bg-[#14212E] text-white"
            : "border border-dashed border-[#E8823C] text-[#14212E] hover:bg-[#E8823C]/5"
        }`}
      >
        <span className="flex items-center gap-2 text-sm font-medium">
          <Crown size={16} className={isMember ? "text-[#E8823C]" : "text-[#E8823C]"} />
          {isMember ? "Vantra Membership — Active" : "Become a member — ₹150/mo"}
        </span>
        <ChevronRight size={16} className={isMember ? "text-white/60" : "text-[#8A8A8A]"} />
      </button>

      {others.length > 0 && (
        <button onClick={onSwitch} className="flex items-center justify-between text-sm text-[#14212E] border border-[#E4E0D6] rounded-xl px-4 py-3 mb-3 hover:border-[#0E6E63]">
          <span>Switch account ({others.length} other{others.length > 1 ? "s" : ""})</span>
          <ArrowRight size={15} className="text-[#8A8A8A]" />
        </button>
      )}

      <div className="mt-auto pt-4 border-t border-[#E4E0D6]">
        {!confirmOpen ? (
          <button onClick={() => setConfirmOpen(true)} className="flex items-center gap-2 text-sm font-medium text-[#C4432B] hover:underline">
            <LogOut size={15} /> Sign out
          </button>
        ) : (
          <div className="border border-[#E4E0D6] rounded-xl p-4">
            <p className="text-sm text-[#14212E] mb-3">Sign out of Vantra on this device?</p>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => onSignOut({ forgetDevice: false })} className="text-sm font-medium px-3.5 py-2 rounded-lg bg-[#14212E] text-white hover:bg-[#0E6E63]">Sign out</button>
              <button onClick={() => onSignOut({ forgetDevice: true })} className="text-sm font-medium px-3.5 py-2 rounded-lg border border-[#E4E0D6] text-[#14212E] hover:border-[#C4432B] hover:text-[#C4432B]">Sign out &amp; forget this account</button>
              <button onClick={() => setConfirmOpen(false)} className="text-sm px-3.5 py-2 text-[#8A8A8A]">Cancel</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ProfileScreen({ account, membership, busy, onBack, onSaved, onOpenAddresses, onOpenChangePassword, onOpenMembership, onDeleteAccount }) {
  const [name, setName] = useState(account.name);
  const [phone, setPhone] = useState(account.phone || "");
  const [avatarUrl, setAvatarUrl] = useState(account.avatarUrl);
  const [uploading, setUploading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);

  const dirty = name.trim() !== account.name || phone.trim() !== (account.phone || "");

  const memberSince = account.createdAt
    ? new Date(account.createdAt).toLocaleDateString(undefined, { month: "long", year: "numeric" })
    : null;

  async function handleAvatarChange(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError("");
    setUploading(true);
    const ext = file.name.split(".").pop();
    const path = `${account.id}/avatar.${ext}`;
    const { error: uploadErr } = await supabase.storage
      .from("avatars")
      .upload(path, file, { upsert: true });
    if (uploadErr) {
      setUploading(false);
      return setError("Couldn't upload image. Try a smaller file.");
    }
    const { data } = supabase.storage.from("avatars").getPublicUrl(path);
    const publicUrl = `${data.publicUrl}?t=${Date.now()}`; // bust cache
    await supabase.from("profiles").update({ avatar_url: publicUrl }).eq("id", account.id);
    setAvatarUrl(publicUrl);
    setUploading(false);
    onSaved({ ...account, avatarUrl: publicUrl });
  }

  async function handleSave() {
    setError("");
    if (name.trim().length < 2) return setError("Enter your full name.");
    setSaving(true);
    const { error: updateErr } = await supabase
      .from("profiles")
      .update({ full_name: name.trim(), phone: phone.trim() || null })
      .eq("id", account.id);
    setSaving(false);
    if (updateErr) return setError(updateErr.message);
    onSaved({ ...account, name: name.trim(), phone: phone.trim() });
  }

  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onBack} />
      <div className="flex flex-col items-center mb-8">
        <div className="relative mb-3">
          <div
            className="w-20 h-20 rounded-full flex items-center justify-center text-white text-2xl font-semibold overflow-hidden"
            style={{ background: colorFor(account.id) }}
          >
            {avatarUrl ? (
              <img src={avatarUrl} alt="" className="w-full h-full object-cover" />
            ) : (
              initials(name || account.name)
            )}
          </div>
          <label className="absolute -bottom-1 -right-1 w-7 h-7 rounded-full bg-white border border-[#E4E0D6] flex items-center justify-center cursor-pointer hover:border-[#0E6E63]">
            <Camera size={13} className="text-[#14212E]" />
            <input type="file" accept="image/*" className="hidden" onChange={handleAvatarChange} disabled={uploading} />
          </label>
        </div>
        <h2 className="text-xl font-semibold text-[#14212E]">Your profile</h2>
        {memberSince && <p className="text-xs text-[#8A8A8A] mt-1">Member since {memberSince}</p>}
        {uploading && <p className="text-xs text-[#0E6E63] mt-1">Uploading photo…</p>}
      </div>

      <div className="flex flex-col gap-4">
        <Field icon={<User size={16} />} label="Full name" value={name} onChange={setName} placeholder="Your name" />
        <Field icon={<Phone size={16} />} label="Phone number" type="tel" value={phone} onChange={setPhone} placeholder="Add a phone number" />
        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium text-[#14212E]">Email address</span>
          <div className="flex items-center gap-2 border border-[#E4E0D6] rounded-lg px-3 py-2.5 bg-[#F7F5F0]">
            <Mail size={16} className="text-[#8A8A8A]" />
            <span className="text-sm text-[#8A8A8A]">{account.email}</span>
          </div>
        </label>
        {error && <p className="text-xs text-[#C4432B]">{error}</p>}
        <PrimaryButton onClick={handleSave} disabled={!dirty || saving}>
          {saving ? "Saving…" : "Save changes"}
        </PrimaryButton>
      </div>

      <div className="flex flex-col gap-2 mt-6 pt-6 border-t border-[#E4E0D6]">
        <button onClick={onOpenMembership} className="flex items-center justify-between text-sm text-[#14212E] border border-[#E4E0D6] rounded-xl px-4 py-3 hover:border-[#0E6E63]">
          <span className="flex items-center gap-2"><Crown size={16} className="text-[#8A8A8A]" /> Membership</span>
          <span className="flex items-center gap-2 text-xs text-[#8A8A8A]">
            {membership?.status === "active" ? "Active" : "Not a member"}
            <ChevronRight size={16} />
          </span>
        </button>
        <button onClick={onOpenAddresses} className="flex items-center justify-between text-sm text-[#14212E] border border-[#E4E0D6] rounded-xl px-4 py-3 hover:border-[#0E6E63]">
          <span className="flex items-center gap-2"><MapPin size={16} className="text-[#8A8A8A]" /> Manage addresses</span>
          <ChevronRight size={16} className="text-[#8A8A8A]" />
        </button>
        <button onClick={onOpenChangePassword} className="flex items-center justify-between text-sm text-[#14212E] border border-[#E4E0D6] rounded-xl px-4 py-3 hover:border-[#0E6E63]">
          <span className="flex items-center gap-2"><KeyRound size={16} className="text-[#8A8A8A]" /> Change password</span>
          <ChevronRight size={16} className="text-[#8A8A8A]" />
        </button>
      </div>

      <div className="mt-6 pt-6 border-t border-[#E4E0D6]">
        {!confirmDelete ? (
          <button onClick={() => setConfirmDelete(true)} className="flex items-center gap-2 text-sm font-medium text-[#C4432B] hover:underline">
            <Trash2 size={15} /> Delete account
          </button>
        ) : (
          <div className="border border-[#C4432B]/30 bg-[#C4432B]/5 rounded-xl p-4">
            <p className="text-sm text-[#14212E] mb-1 font-medium">Delete your account permanently?</p>
            <p className="text-xs text-[#6B6B6B] mb-3">This removes your profile, addresses, and login. This can't be undone.</p>
            <div className="flex flex-wrap gap-2">
              <button onClick={onDeleteAccount} disabled={busy} className="text-sm font-medium px-3.5 py-2 rounded-lg bg-[#C4432B] text-white hover:bg-[#A8371F] disabled:opacity-60">
                {busy ? "Deleting…" : "Yes, delete my account"}
              </button>
              <button onClick={() => setConfirmDelete(false)} className="text-sm px-3.5 py-2 text-[#8A8A8A]">Cancel</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function loadRazorpayScript() {
  return new Promise((resolve) => {
    if (window.Razorpay) return resolve(true);
    const script = document.createElement("script");
    script.src = "https://checkout.razorpay.com/v1/checkout.js";
    script.onload = () => resolve(true);
    script.onerror = () => resolve(false);
    document.body.appendChild(script);
  });
}

const BENEFITS = [
  { icon: PackageCheck, title: "7-day early pre-orders", desc: "Reserve new drops a full week before everyone else." },
  { icon: Ruler, title: "14-day tailor fit", desc: "Custom-fit alterations turned around in two weeks, not the usual wait." },
];

function MembershipScreen({ account, membership, onBack, onRefresh, onCancelled }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [confirmCancel, setConfirmCancel] = useState(false);

  const status = membership?.status || "none";
  const isActive = status === "active";
  const isPending = status === "created";
  const isEndingSoon = status === "cancelled" && membership?.currentPeriodEnd;

  const renewalDate = membership?.currentPeriodEnd
    ? new Date(membership.currentPeriodEnd).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" })
    : null;

  async function handleJoin() {
    setError("");
    setLoading(true);
    const { data, error: fnErr } = await supabase.functions.invoke("create-membership-subscription");
    if (fnErr || data?.error) {
      setLoading(false);
      return setError(data?.error || "Couldn't start checkout. Try again.");
    }
    const ready = await loadRazorpayScript();
    setLoading(false);
    if (!ready) return setError("Couldn't load payment window. Check your connection.");

    const rzp = new window.Razorpay({
      key: data.key_id,
      subscription_id: data.subscription_id,
      name: "Vantra Membership",
      description: "₹150 / month",
      theme: { color: "#E8823C" },
      prefill: { name: account.name, email: account.email },
      handler: () => {
        onRefresh();
      },
      modal: {
        ondismiss: () => onRefresh(),
      },
    });
    rzp.open();
  }

  async function handleCancel() {
    setLoading(true);
    const { error: fnErr } = await supabase.functions.invoke("cancel-membership");
    setLoading(false);
    setConfirmCancel(false);
    if (fnErr) return setError("Couldn't cancel right now. Try again.");
    onCancelled();
    onRefresh();
  }

  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onBack} />
      <div className="flex items-center gap-2 mb-1">
        <Crown size={20} className="text-[#E8823C]" />
        <h2 className="text-xl font-semibold text-[#14212E]">Vantra Membership</h2>
      </div>
      <p className="text-sm text-[#6B6B6B] mb-6">₹150/month, billed automatically. Cancel anytime.</p>

      <div className="flex flex-col gap-3 mb-6">
        {BENEFITS.map(({ icon: Icon, title, desc }) => (
          <div key={title} className="flex items-start gap-3 border border-[#E4E0D6] rounded-xl px-4 py-3">
            <div className="w-9 h-9 rounded-full bg-[#0E6E63]/10 flex items-center justify-center shrink-0">
              <Icon size={16} className="text-[#0E6E63]" />
            </div>
            <div>
              <div className="text-sm font-medium text-[#14212E]">{title}</div>
              <div className="text-xs text-[#8A8A8A] mt-0.5">{desc}</div>
            </div>
          </div>
        ))}
      </div>

      {error && <p className="text-xs text-[#C4432B] mb-4">{error}</p>}

      {isActive && (
        <div className="border border-[#0E6E63]/30 bg-[#0E6E63]/5 rounded-xl p-4 mb-4">
          <div className="flex items-center gap-2 text-sm font-medium text-[#0E6E63]">
            <Check size={15} /> You're a member
          </div>
          {renewalDate && <p className="text-xs text-[#6B6B6B] mt-1">Renews on {renewalDate}</p>}
        </div>
      )}

      {isEndingSoon && (
        <div className="border border-[#B08900]/30 bg-[#B08900]/5 rounded-xl p-4 mb-4">
          <p className="text-sm text-[#14212E]">Membership ending{renewalDate ? ` on ${renewalDate}` : ""}.</p>
          <p className="text-xs text-[#6B6B6B] mt-1">Benefits stay active until then.</p>
        </div>
      )}

      {isPending && (
        <div className="border border-[#E4E0D6] rounded-xl p-4 mb-4">
          <p className="text-sm text-[#14212E]">Payment in progress…</p>
          <button onClick={onRefresh} className="text-xs text-[#0E6E63] font-medium hover:underline mt-1">Refresh status</button>
        </div>
      )}

      {!isActive && !isPending && (
        <PrimaryButton onClick={handleJoin} disabled={loading}>
          {loading ? "Starting checkout…" : "Join for ₹150/month"}
        </PrimaryButton>
      )}

      {isActive && !confirmCancel && (
        <button onClick={() => setConfirmCancel(true)} className="text-sm text-[#C4432B] hover:underline self-start mt-2">
          Cancel membership
        </button>
      )}
      {confirmCancel && (
        <div className="border border-[#C4432B]/30 bg-[#C4432B]/5 rounded-xl p-4 mt-2">
          <p className="text-sm text-[#14212E] mb-3">Cancel your membership? You'll keep benefits until the current period ends.</p>
          <div className="flex gap-2">
            <button onClick={handleCancel} disabled={loading} className="text-sm font-medium px-3.5 py-2 rounded-lg bg-[#C4432B] text-white hover:bg-[#A8371F]">
              {loading ? "Cancelling…" : "Yes, cancel"}
            </button>
            <button onClick={() => setConfirmCancel(false)} className="text-sm px-3.5 py-2 text-[#8A8A8A]">Keep membership</button>
          </div>
        </div>
      )}
    </div>
  );
}

function AddressesScreen({ userId, onBack }) {
  const [addresses, setAddresses] = useState(null); // null = loading
  const [editing, setEditing] = useState(null); // null | {} for new | address object

  useEffect(() => {
    load();
  }, []);

  async function load() {
    const { data } = await supabase
      .from("addresses")
      .select("*")
      .eq("user_id", userId)
      .order("is_default", { ascending: false })
      .order("created_at", { ascending: false });
    setAddresses(data || []);
  }

  async function handleDelete(id) {
    await supabase.from("addresses").delete().eq("id", id);
    load();
  }

  async function handleMakeDefault(id) {
    await supabase.from("addresses").update({ is_default: false }).eq("user_id", userId);
    await supabase.from("addresses").update({ is_default: true }).eq("id", id);
    load();
  }

  if (editing !== null) {
    return (
      <AddressForm
        userId={userId}
        address={editing.id ? editing : null}
        onCancel={() => setEditing(null)}
        onSaved={() => { setEditing(null); load(); }}
      />
    );
  }

  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onBack} />
      <h2 className="text-xl font-semibold text-[#14212E] mb-1">Your addresses</h2>
      <p className="text-sm text-[#6B6B6B] mb-6">Manage the addresses saved to your account.</p>

      {addresses === null && <p className="text-sm text-[#8A8A8A]">Loading…</p>}

      <div className="flex flex-col gap-3">
        {addresses?.map((a) => (
          <div key={a.id} className="border border-[#E4E0D6] rounded-xl p-4">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-[#14212E]">{a.label}</span>
                  {a.is_default && <span className="text-[10px] uppercase tracking-wide text-[#0E6E63] bg-[#0E6E63]/10 px-1.5 py-0.5 rounded">Default</span>}
                </div>
                <p className="text-sm text-[#6B6B6B] mt-1 leading-relaxed">
                  {a.line1}{a.line2 ? `, ${a.line2}` : ""}<br />
                  {a.city}{a.state ? `, ${a.state}` : ""} {a.postal_code}<br />
                  {a.country}
                </p>
              </div>
              <div className="flex gap-1 shrink-0">
                <button onClick={() => setEditing(a)} className="p-1.5 text-[#8A8A8A] hover:text-[#0E6E63]"><Pencil size={15} /></button>
                <button onClick={() => handleDelete(a.id)} className="p-1.5 text-[#8A8A8A] hover:text-[#C4432B]"><Trash2 size={15} /></button>
              </div>
            </div>
            {!a.is_default && (
              <button onClick={() => handleMakeDefault(a.id)} className="text-xs text-[#0E6E63] font-medium hover:underline mt-2">
                Set as default
              </button>
            )}
          </div>
        ))}
      </div>

      <button onClick={() => setEditing({})} className="flex items-center gap-3 border border-dashed border-[#C4C0B4] hover:border-[#E8823C] rounded-xl px-4 py-3 mt-3">
        <div className="w-8 h-8 rounded-full flex items-center justify-center bg-[#F1EEE6] text-[#14212E]"><Plus size={16} /></div>
        <span className="text-sm font-medium text-[#14212E]">Add a new address</span>
      </button>
    </div>
  );
}

function AddressForm({ userId, address, onCancel, onSaved }) {
  const [form, setForm] = useState({
    label: address?.label || "Home",
    line1: address?.line1 || "",
    line2: address?.line2 || "",
    city: address?.city || "",
    state: address?.state || "",
    postal_code: address?.postal_code || "",
    country: address?.country || "India",
  });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    if (!form.line1 || !form.city || !form.postal_code) {
      return setError("Fill in address line, city, and postal code.");
    }
    setSaving(true);
    const payload = { ...form, user_id: userId };
    const { error: saveErr } = address
      ? await supabase.from("addresses").update(payload).eq("id", address.id)
      : await supabase.from("addresses").insert(payload);
    setSaving(false);
    if (saveErr) return setError(saveErr.message);
    onSaved();
  }

  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onCancel} />
      <h2 className="text-xl font-semibold text-[#14212E] mb-6">{address ? "Edit address" : "Add address"}</h2>
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field label="Label" value={form.label} onChange={(v) => set("label", v)} placeholder="Home, Work…" />
        <Field label="Address line 1" value={form.line1} onChange={(v) => set("line1", v)} placeholder="Street address" autoFocus />
        <Field label="Address line 2 (optional)" value={form.line2} onChange={(v) => set("line2", v)} placeholder="Apartment, suite, etc." />
        <div className="grid grid-cols-2 gap-3">
          <Field label="City" value={form.city} onChange={(v) => set("city", v)} placeholder="City" />
          <Field label="State" value={form.state} onChange={(v) => set("state", v)} placeholder="State" />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Postal code" value={form.postal_code} onChange={(v) => set("postal_code", v)} placeholder="000000" />
          <Field label="Country" value={form.country} onChange={(v) => set("country", v)} placeholder="Country" />
        </div>
        {error && <p className="text-xs text-[#C4432B]">{error}</p>}
        <PrimaryButton type="submit" disabled={saving}>{saving ? "Saving…" : "Save address"}</PrimaryButton>
      </form>
    </div>
  );
}

function ChangePasswordScreen({ onBack, onDone }) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    if (pw.length < 6) return setError("Password must be at least 6 characters.");
    if (pw !== confirm) return setError("Passwords don't match.");
    setSaving(true);
    const { error: updateErr } = await supabase.auth.updateUser({ password: pw });
    setSaving(false);
    if (updateErr) return setError(updateErr.message);
    onDone();
  }

  return (
    <div className="flex flex-col h-full">
      <TopNav onBack={onBack} />
      <h2 className="text-xl font-semibold text-[#14212E]">Change password</h2>
      <p className="text-sm text-[#6B6B6B] mt-1 mb-6">Choose a new password for your account.</p>
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field icon={<Lock size={16} />} label="New password" type={showPw ? "text" : "password"} value={pw} onChange={setPw}
          placeholder="At least 6 characters" autoFocus
          endAdornment={<button type="button" tabIndex={-1} onClick={() => setShowPw((v) => !v)} className="text-[#8A8A8A]">{showPw ? <EyeOff size={16} /> : <Eye size={16} />}</button>} />
        <Field icon={<Lock size={16} />} label="Confirm new password" type={showPw ? "text" : "password"} value={confirm} onChange={setConfirm} placeholder="Re-enter password" />
        {error && <p className="text-xs text-[#C4432B]">{error}</p>}
        <PrimaryButton type="submit" disabled={saving}>{saving ? "Updating…" : "Update password"}</PrimaryButton>
      </form>
    </div>
  );
}

// ---------- shared bits ----------

function TopNav({ onBack }) {
  if (!onBack) return <div className="h-6 mb-2" />;
  return (
    <button onClick={onBack} className="flex items-center gap-1 text-sm text-[#8A8A8A] hover:text-[#14212E] mb-4 -ml-1">
      <ChevronLeft size={16} /> Back
    </button>
  );
}

function Field({ icon, label, value, onChange, type = "text", placeholder, autoFocus, endAdornment }) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-medium text-[#14212E]">{label}</span>
      <div className="flex items-center gap-2 border border-[#D8D4C8] focus-within:border-[#0E6E63] rounded-lg px-3 py-2.5 bg-white">
        <span className="text-[#8A8A8A]">{icon}</span>
        <input autoFocus={autoFocus} type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
          className="flex-1 outline-none text-sm text-[#14212E] placeholder:text-[#B7B3A6] bg-transparent" />
        {endAdornment}
      </div>
    </label>
  );
}

function PrimaryButton({ children, ...props }) {
  return (
    <button {...props} className="w-full bg-[#E8823C] hover:bg-[#D4732F] disabled:opacity-60 text-white text-sm font-semibold rounded-lg py-2.5 transition-colors">
      {children}
    </button>
  );
}
