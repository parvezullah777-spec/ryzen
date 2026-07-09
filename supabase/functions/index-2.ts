// supabase/functions/verify-payment/index.ts
//
// Verifies the Razorpay payment signature returned by Razorpay Checkout's
// client-side handler, then marks the matching `orders` row as "paid".
// Signature verification uses HMAC-SHA256 (Web Crypto API — no npm package
// needed), exactly matching Razorpay's documented verification scheme:
//   expected = HMAC_SHA256(order_id + "|" + payment_id, key_secret)

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

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
    const authClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      global: { headers: { Authorization: req.headers.get("Authorization")! } },
    });
    const { data: userData, error: userErr } = await authClient.auth.getUser();
    if (userErr || !userData?.user) {
      return json({ success: false, error: "Not signed in" }, 401);
    }
    const userId = userData.user.id;

    const body = await req.json();
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = body || {};
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return json({ success: false, error: "Missing payment fields" }, 400);
    }

    const expectedSignature = await hmacSha256Hex(
      `${razorpay_order_id}|${razorpay_payment_id}`,
      RAZORPAY_KEY_SECRET
    );

    if (expectedSignature !== razorpay_signature) {
      // Signature mismatch — do not mark as paid.
      const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
      await db
        .from("orders")
        .update({ status: "failed", updated_at: new Date().toISOString() })
        .eq("razorpay_order_id", razorpay_order_id)
        .eq("user_id", userId);
      return json({ success: false, error: "Signature verification failed" }, 400);
    }

    const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const { error: updateErr } = await db
      .from("orders")
      .update({
        status: "paid",
        razorpay_payment_id,
        updated_at: new Date().toISOString(),
      })
      .eq("razorpay_order_id", razorpay_order_id)
      .eq("user_id", userId);

    if (updateErr) {
      console.error("Order update failed:", updateErr);
      return json({ success: false, error: "Could not finalize order" }, 500);
    }

    return json({ success: true });
  } catch (e) {
    console.error("verify-payment error:", e);
    return json({ success: false, error: "Unexpected server error" }, 500);
  }
});

async function hmacSha256Hex(message: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}
