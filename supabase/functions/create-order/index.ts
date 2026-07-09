// supabase/functions/create-order/index.ts
//
// Creates a Razorpay order for the signed-in user's cart and records it in
// the `orders` table with status "created". Called from the storefront via:
//   window.supabaseClient.functions.invoke('create-order', { body: {...} })
// which automatically attaches the caller's auth token, so we can trust
// `auth.uid()` here instead of whatever user info the client sends.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const RAZORPAY_KEY_ID = Deno.env.get("RAZORPAY_KEY_ID")!;
const RAZORPAY_KEY_SECRET = Deno.env.get("RAZORPAY_KEY_SECRET")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: CORS_HEADERS });
  }

  try {
    // Client tied to the caller's own JWT — used only to identify who they are.
    const authClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      global: { headers: { Authorization: req.headers.get("Authorization")! } },
    });
    const { data: userData, error: userErr } = await authClient.auth.getUser();
    if (userErr || !userData?.user) {
      return json({ error: "Not signed in" }, 401);
    }
    const userId = userData.user.id;

    const body = await req.json();
    const { amount, items, address, coupon } = body || {};

    if (!amount || !(amount > 0)) return json({ error: "Invalid amount" }, 400);
    if (!items || !Array.isArray(items) || !items.length) return json({ error: "Cart is empty" }, 400);
    if (!address) return json({ error: "Address is required" }, 400);

    // Razorpay amounts are in paise, and must be an integer.
    const amountPaise = Math.round(Number(amount) * 100);

    const rzpResp = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Basic " + btoa(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`),
      },
      body: JSON.stringify({
        amount: amountPaise,
        currency: "INR",
        receipt: `ryzen_${Date.now()}`,
        notes: { user_id: userId },
      }),
    });

    if (!rzpResp.ok) {
      const errText = await rzpResp.text();
      console.error("Razorpay order creation failed:", errText);
      return json({ error: "Could not create payment order" }, 502);
    }
    const rzpOrder = await rzpResp.json();

    // Service-role client to write the order row (bypasses RLS by design —
    // see the migration file for why insert/update aren't user-facing policies).
    const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const { error: insertErr } = await db.from("orders").insert({
      user_id: userId,
      razorpay_order_id: rzpOrder.id,
      amount: Number(amount),
      currency: "INR",
      status: "created",
      items,
      address,
      coupon_code: coupon || null,
    });
    if (insertErr) {
      console.error("Order insert failed:", insertErr);
      return json({ error: "Could not record order" }, 500);
    }

    return json({
      id: rzpOrder.id,
      amount: rzpOrder.amount,
      currency: rzpOrder.currency,
      key: RAZORPAY_KEY_ID, // public key id — safe to expose to the client
    });
  } catch (e) {
    console.error("create-order error:", e);
    return json({ error: "Unexpected server error" }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}
