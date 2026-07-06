// supabase/functions/create-membership-subscription/index.ts
// Deploy with: supabase functions deploy create-membership-subscription
//
// This function creates a Razorpay subscription when a user joins membership.
// The frontend calls this via supabase.functions.invoke("create-membership-subscription")

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const RAZORPAY_KEY_ID = Deno.env.get("RAZORPAY_KEY_ID")!;
const RAZORPAY_KEY_SECRET = Deno.env.get("RAZORPAY_KEY_SECRET")!;
const RAZORPAY_PLAN_ID = Deno.env.get("RAZORPAY_PLAN_ID")!;
const basicAuth = "Basic " + btoa(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`);

Deno.serve(async (req) => {
  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    const token = authHeader.replace("Bearer ", "");

    // Verify the user is authenticated
    const userClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: authHeader } } }
    );
    const { data: userData, error: userErr } = await userClient.auth.getUser(token);
    if (userErr || !userData.user) {
      return new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 });
    }
    const user = userData.user;

    const adminClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Check if user already has an active subscription
    const { data: existing } = await adminClient
      .from("memberships")
      .select("*")
      .eq("user_id", user.id)
      .maybeSingle();

    if (existing?.status === "active") {
      return new Response(JSON.stringify({ error: "Already a member" }), { status: 400 });
    }

    // Create Razorpay subscription
    // 120 cycles = 10 years (Razorpay requires total_count)
    const subRes = await fetch("https://api.razorpay.com/v1/subscriptions", {
      method: "POST",
      headers: { Authorization: basicAuth, "Content-Type": "application/json" },
      body: JSON.stringify({
        plan_id: RAZORPAY_PLAN_ID,
        total_count: 120,
        quantity: 1,
        customer_notify: 1,
        notes: { user_id: user.id, email: user.email },
      }),
    });
    const sub = await subRes.json();
    if (!subRes.ok) {
      return new Response(JSON.stringify({ error: sub.error?.description || "Razorpay error" }), { status: 400 });
    }

    // Save subscription ID to database (status will be updated by webhook)
    await adminClient.from("memberships").upsert({
      user_id: user.id,
      razorpay_subscription_id: sub.id,
      status: "created",
      updated_at: new Date().toISOString(),
    });

    // Return the subscription ID and key to the client
    // Client uses these to open Razorpay Checkout
    return new Response(
      JSON.stringify({ subscription_id: sub.id, key_id: RAZORPAY_KEY_ID }),
      { status: 200 }
    );
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 });
  }
});
